"""The served application: the API wired to the real services (SPEC §13, §11.6, §12.5).

`athar.services.wiring:create_app` is what `athar serve` and the container run. It builds the
FastAPI app from `athar.api.app.create_app`, installs the request-scoped `DbRepo` factory, and
adds two start-up hooks:

1. **ledger** — resolve the process-wide `LedgerWriter` and make sure the contract is deployed
   (SPEC §12.5). A node that is down leaves the writer unset: scans still run and record
   `ledger_status = unanchored` (SPEC §12.4 — the ledger never blocks the pipeline).
2. **scheduler** — when `SCAN_INTERVAL_MINUTES > 0`, a background job takes a Postgres advisory
   lock and runs retry parked ledger jobs → diff → scan → attest → investigate new findings →
   summary (SPEC §11.6, §12.4). The lock means two API replicas never scan the same month twice.

Every hook and every scheduler step is individually guarded: a missing dependency degrades the
feature, it never stops the API from answering `/health`.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic
from typing import Any

from fastapi import FastAPI
from sqlalchemy import select, text

from athar.config import Settings, get_settings
from athar.db import models as m
from athar.hashing import sha256_hex
from athar.log import get_logger
from athar.services.repo import DbRepo

log = get_logger("athar.services.wiring")

#: Postgres advisory-lock key for the governance loop — one holder across replicas (SPEC §11.6).
SCHEDULER_LOCK_KEY = int(sha256_hex(b"athar:continuous-governance")[:8], 16)

#: How many open findings one tick investigates (cache-aware, so a warm demo costs nothing).
INVESTIGATE_PER_TICK = 5

SCHEDULER_JOB_ID = "athar-continuous-governance"

#: How long a retried ledger job may hold the tick while it is mined. Anvil mines every second;
#: a node that is still down fails the future immediately and parks the job again.
LEDGER_RETRY_TIMEOUT_SECONDS = 30.0


def create_app() -> FastAPI:
    """Zero-argument factory: `uvicorn athar.services.wiring:create_app --factory`."""
    from athar.api.app import create_app as create_api_app

    settings = get_settings()
    app = create_api_app(settings, startup_hooks=[bootstrap_ledger, start_scheduler])
    app.state.ledger_writer = None
    app.state.scheduler = None
    app.state.repo_factory = lambda: _new_repo(app, settings)
    return app


def _new_repo(app: FastAPI, settings: Settings) -> DbRepo:
    from athar.db.session import get_sessionmaker

    writer = getattr(app.state, "ledger_writer", None)
    return DbRepo(get_sessionmaker()(), settings, writer)


# ---------------------------------------------------------------------------
# start-up hook: ledger (SPEC §12.4, §12.5)
# ---------------------------------------------------------------------------


def bootstrap_ledger(app: FastAPI) -> None:
    """Resolve the one writer of this process and deploy the contract if it is not there yet."""
    settings: Settings = app.state.settings
    if not settings.ledger_enabled:
        log.info("ledger disabled by configuration")
        return
    from athar.db.session import get_sessionmaker
    from athar.ledger.client import ensure_deployed
    from athar.ledger.writer import get_writer

    writer = get_writer(settings)
    client: Any = writer.client  # the writer exposes the transaction protocol; this is the LedgerClient
    session = get_sessionmaker()()
    try:
        meta = ensure_deployed(client, session, settings)
    except Exception as exc:  # SPEC §12.4: an unreachable node never blocks start-up
        log.warning(
            "ledger unavailable at start-up; scans will be unanchored",
            extra={"exc_type": type(exc).__name__},
        )
        return
    finally:
        session.close()
    writer.start()
    app.state.ledger_writer = writer
    log.info(
        "ledger ready",
        extra={"contract": meta.contract_address, "chain_id": meta.chain_id, "writer": meta.writer_address},
    )


# ---------------------------------------------------------------------------
# start-up hook: continuous governance (SPEC §11.6)
# ---------------------------------------------------------------------------


def start_scheduler(app: FastAPI) -> None:
    """Start the background governance loop when `SCAN_INTERVAL_MINUTES > 0`."""
    settings: Settings = app.state.settings
    minutes = settings.scan_interval_minutes
    if minutes <= 0:
        log.info("scheduler off (SCAN_INTERVAL_MINUTES=0)")
        return
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        lambda: governance_tick(app),
        trigger="interval",
        minutes=minutes,
        id=SCHEDULER_JOB_ID,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )
    scheduler.start()
    app.state.scheduler = scheduler
    log.info("scheduler started", extra={"interval_minutes": minutes})


def governance_tick(app: FastAPI) -> None:
    """One tick: advisory lock → scan (diff, rules, score, attest) → investigate → summary.

    Never raises: an APScheduler job that throws would only be logged and retried, and a failing
    LLM or ledger must not stop the loop.
    """
    from athar.db.session import get_sessionmaker

    settings: Settings = app.state.settings
    session = get_sessionmaker()()
    try:
        with governance_lock(session) as held:
            if not held:
                log.info("governance tick skipped: another worker holds the lock")
                return
            _run_cycle(session, settings, getattr(app.state, "ledger_writer", None))
    except Exception as exc:
        log.warning("governance tick failed", extra={"exc_type": type(exc).__name__})
    finally:
        session.close()


@contextmanager
def governance_lock(session: Any) -> Iterator[bool]:
    """Hold `pg_try_advisory_lock` on one dedicated connection for the whole tick.

    A PostgreSQL session-level advisory lock belongs to the *connection* that took it, and
    returning a connection to SQLAlchemy's pool does not release one. The tick commits many times,
    and every commit hands the session's connection back, so a lock taken and released through the
    session could easily be unlocked on a different connection than the one holding it: the unlock
    is a silent no-op (Postgres only warns), the lock outlives the tick on an idle pooled
    connection, and every later tick then finds it held and skips. Continuous governance would stop
    after exactly one run, logging "another worker holds the lock" forever with no other worker.

    So the lock gets a connection of its own, which nothing else uses and which is closed here.
    Yields False when another replica genuinely holds it, or when the backend cannot lock at all —
    the caller then does nothing, which is the safe direction.
    """
    bind = session.get_bind()
    try:
        conn = bind.connect()
    except Exception as exc:
        log.warning("advisory lock unavailable", extra={"exc_type": type(exc).__name__})
        yield False
        return
    try:
        held = bool(conn.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": SCHEDULER_LOCK_KEY}))
    except Exception as exc:
        log.warning("advisory lock unavailable", extra={"exc_type": type(exc).__name__})
        conn.close()
        yield False
        return
    try:
        yield held
    finally:
        if held:
            try:
                conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": SCHEDULER_LOCK_KEY})
            except Exception as exc:
                log.warning("advisory unlock failed", extra={"exc_type": type(exc).__name__})
        conn.close()


def _run_cycle(
    session: Any,
    settings: Settings,
    writer: Any,
    month: int | None = None,
    agent_budget_seconds: float | None = None,
) -> None:
    """One turn of the SPEC §11.6 loop.

    `month` defaults to the simulated clock, which is what the scheduler wants. `DbRepo.advance`
    passes the month it just created instead: the clock is advanced by ingest, so the two agree
    today, but a caller that has just made a month should not have to trust a shared row to find
    out which one the loop will act on.

    `agent_budget_seconds` bounds the agent half — the investigations and the executive summary.
    The scheduler passes nothing and does all of it. A request does: `POST /simulate/advance` runs
    this loop inline, and with a cold cache and a real provider that is up to
    `INVESTIGATE_PER_TICK` model calls plus a summary, each allowed `LLM_TIMEOUT_SECONDS`, in one
    HTTP request behind nginx's 120-second `proxy_read_timeout`. Past the budget the remaining
    findings are left open for the next tick or for whoever opens them, because a month that
    advanced and scanned is a complete result and a gateway timeout is not.
    """
    from athar.services import queries
    from athar.services.agents import estate_summary_paragraph, investigate_finding
    from athar.services.remediation import auto_remediate
    from athar.services.scan import run_scan

    # First, before anything anchors: the ordering is load-bearing. A parked job is past its
    # `existing_index_lookup`, so re-sending it after this tick had already anchored the same
    # root would put a second commit of that root on the chain (SPEC §12.4 idempotency).
    drain_ledger_retries(session, writer)

    if month is None:
        month = queries.current_month(session)
    if month is None:
        log.info("governance tick: nothing ingested yet")
        return
    outcome = run_scan(session, settings, month, writer=writer)
    log.info(
        "governance tick scanned",
        extra={"scan_id": outcome.scan_id, "month": month, "findings": outcome.finding_count},
    )
    try:
        auto_remediate(session, settings, outcome.scan_id, writer=writer)
    except Exception as exc:
        session.rollback()
        log.warning("governance tick: auto-remediation failed", extra={"exc_type": type(exc).__name__})

    # Auto-remediation changes the simulated estate and re-scans, which supersedes `outcome.scan_id`
    # (SPEC §11.5). Investigating and summarising the pre-remediation scan would describe access the
    # estate no longer grants, and would cache the paragraph under a scan id the UI never asks for —
    # it reads the newest scan of the month. Re-resolve; with auto-remediation off this is the row
    # `run_scan` just returned.
    scan = queries.scan_for_month(session, month) or queries.scan_by_id(session, outcome.scan_id)
    if scan is None:  # pragma: no cover — just written
        return
    rows = list(
        session.scalars(
            select(m.Finding)
            .where(m.Finding.scan_id == scan.scan_id, m.Finding.status == "open")
            .order_by(m.Finding.score.desc(), m.Finding.finding_key)
            .limit(INVESTIGATE_PER_TICK)
        )
    )
    deadline = None if agent_budget_seconds is None else monotonic() + agent_budget_seconds
    for row in rows:
        if deadline is not None and monotonic() >= deadline:
            log.info(
                "governance tick: agent budget spent, leaving findings for the next tick",
                extra={"scan_id": scan.scan_id, "remaining": len(rows) - rows.index(row)},
            )
            return
        try:
            investigate_finding(session, settings, row, regenerate=False)
            if row.status == "open":
                row.status = "investigated"
                session.commit()
        except Exception as exc:  # one finding must not stop the loop
            session.rollback()
            log.warning(
                "governance tick: investigate failed",
                extra={"finding_key": row.finding_key, "exc_type": type(exc).__name__},
            )
    try:
        result = estate_summary_paragraph(session, settings, scan, regenerate=False)
        _remember_summary(session, settings, scan.scan_id, result)
    except Exception as exc:
        session.rollback()
        log.warning("governance tick: summary failed", extra={"exc_type": type(exc).__name__})


# ---------------------------------------------------------------------------
# parked ledger jobs (SPEC §12.4 — "a background retry drains the queue")
# ---------------------------------------------------------------------------


def drain_ledger_retries(session: Any, writer: Any) -> int:
    """Re-send the jobs a node outage parked and write down what they anchored. Returns the count.

    SPEC §12.4: an unreachable node never blocks the pipeline — the scan finishes with
    `ledger_status = unanchored`, the writer parks the transaction, and this is the background
    retry that drains it. The writer re-enqueues each parked job with a fresh future
    (:meth:`LedgerWriter.retry_pending`); the DB row it belongs to is identified by the `tag` the
    caller passed when it queued the job: a `scan_id` for a commit, a `decision_id` for a
    decision.

    Never raises. A node that is still down fails each future with `LedgerUnavailable` and the
    writer parks the job again, so the next tick tries once more; nothing is lost and nothing is
    retried twice in one tick.
    """
    if writer is None or not getattr(writer, "pending_count", 0):
        return 0

    def settled(kind: Any, tag: Any) -> int | None:
        """The index this parked commit's root already occupies on the chain, if any.

        Runs before anything is re-enqueued, which is the only moment the send can still be
        stopped. The session the job closed over is long gone by now — it belonged to whichever
        scan parked it — so the check is made against this tick's own session.
        """
        if kind != "commit" or tag is None:
            return None
        scan = session.get(m.Scan, tag)
        if scan is None or not scan.merkle_root:
            return None
        from athar.services.scan import commit_index_for

        return commit_index_for(
            session, writer, scan.snapshot_hash, scan.merkle_root, scan.ruleset_hash, scan_id=scan.scan_id
        )

    try:
        retried = writer.retry_pending(settled)
    except Exception as exc:  # a writer whose thread cannot start must not stop the cycle
        log.warning("ledger retry could not start", extra={"exc_type": type(exc).__name__})
        return 0

    drained = 0
    for job in retried:
        try:
            receipt = job.future.result(timeout=LEDGER_RETRY_TIMEOUT_SECONDS)
        except Exception as exc:
            log.warning(
                "parked ledger job still unanchored",
                extra={"kind": job.kind, "tag": str(job.tag), "exc_type": type(exc).__name__},
            )
            continue
        if _record_retried(session, job, receipt):
            drained += 1
    if drained:
        session.commit()
        log.info("drained parked ledger jobs", extra={"count": drained})
    return drained


def _record_retried(session: Any, job: Any, receipt: Any) -> bool:
    """Move the row this job belongs to from `unanchored` to `anchored`. False if there is no row."""
    if job.tag is None:
        return False
    if job.kind == "commit":
        scan = session.get(m.Scan, job.tag)
        if scan is None:
            return False
        scan.ledger_scan_index = receipt.scan_index
        scan.ledger_tx = receipt.tx_hash
        scan.ledger_status = "already_anchored" if receipt.already_anchored else "anchored"
        return True
    decision = session.get(m.Decision, job.tag)
    if decision is None:
        return False
    decision.ledger_tx = receipt.tx_hash
    decision.ledger_status = "anchored"
    return True


def _remember_summary(session: Any, settings: Settings, scan_id: int, result: dict[str, Any]) -> None:
    """Same cache slot `DbRepo.summary` writes, so the Overview shows the paragraph with no call."""
    from datetime import UTC, datetime

    from athar.services import queries

    session.merge(
        m.LlmCache(
            key=queries.summary_cache_key(scan_id),
            provider=settings.llm_provider,
            model=settings.llm_model,
            prompt_version=str(result.get("prompt_version", "v1")),
            input_hash=f"scan:{scan_id}",
            output={
                "summary_paragraph": str(result.get("summary_paragraph", "")),
                "top_themes": [str(t) for t in result.get("top_themes", [])],
                "model_id": result.get("model_id"),
                "generated_by": result.get("generated_by", "template"),
            },
            created_at=datetime.now(UTC),
        )
    )
    session.commit()
