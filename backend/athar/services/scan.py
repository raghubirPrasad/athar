"""Scan: diff → rules → graph → score → narrate → commit → attest (SPEC §2, §8, §10, §12).

The one place the pipeline stages are joined. Everything it calls is pure; the side effects
(DB writes, the ledger transaction) live here.

Idempotency (CLAUDE.md non-negotiable 2): a scan is identified by
`(snapshot_month, ruleset_hash, snapshot_hash)`. Re-running it re-uses the existing `scans` row,
rewrites its findings and scores in place (the deterministic finding key makes that a no-op in
content), and asks the ledger for the existing commit index instead of sending a second
transaction. `make demo` twice therefore prints twelve "already anchored" lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from athar.config import Settings
from athar.db import models as m
from athar.detection.base import FindingDraft
from athar.detection.registry import rule_versions, run_all
from athar.domain import EstateView, Thresholds
from athar.drift.causal import causal_history
from athar.drift.diff import diff_snapshots
from athar.hashing import finding_instance, finding_key, instance_hash, ruleset_hash, snapshot_hash
from athar.ledger import verify as ledger_verify
from athar.log import get_logger
from athar.narrative import render_all
from athar.scoring.graph import build_graph
from athar.scoring.score import score_all
from athar.scoring.types import ScoreResult
from athar.services.estate_view import load_estate_view, load_thresholds

log = get_logger(__name__)


@dataclass
class ScanOutcome:
    scan_id: int
    month: int
    finding_count: int
    merkle_root: str
    snapshot_hash: str
    ruleset_hash: str
    ledger_status: str
    ledger_scan_index: int | None = None
    ledger_tx: str | None = None
    created: bool = True  # False when an existing scan row was re-used
    events_written: int = 0
    detail: str = ""
    warnings: list[str] = field(default_factory=list)


def current_ruleset_hash(thresholds: Thresholds) -> str:
    """Rules (id → version) plus the thresholds in force (SPEC §12.3)."""
    return ruleset_hash(rule_versions(), thresholds.as_dict())


def _snapshot_hash_for(session: Session, month: int) -> str:
    row = session.get(m.Snapshot, month)
    return snapshot_hash(dict(row.file_hashes or {})) if row else snapshot_hash({})


def _grants_for_month(session: Session, month: int) -> list[Any]:
    view = load_estate_view(session, month)
    return view.grants


def write_diff_events(session: Session, month: int) -> int:
    """`grant`/`revoke` events between month−1 and month (SPEC §9.1). Idempotent on event_id."""
    curr = load_estate_view(session, month)
    prev_rows = None
    if month > 1 and session.get(m.Snapshot, month - 1) is not None:
        prev_rows = load_estate_view(session, month - 1).grants
    events = diff_snapshots(prev_rows, curr.grants, curr.events, month)
    if not events:
        return 0
    existing = set(
        session.scalars(select(m.Event.event_id).where(m.Event.event_id.in_([e.event_id for e in events])))
    )
    written = 0
    for e in events:
        if e.event_id in existing:
            continue
        session.add(
            m.Event(
                event_id=e.event_id,
                month=e.month,
                kind=e.kind,
                identity_id=e.identity_id,
                cloud=e.cloud,
                grant_delta=e.grant_delta,
                trigger=e.trigger,
                note=e.note,
            )
        )
        written += 1
    session.flush()
    return written


def _existing_scan(session: Session, month: int, rules_hash: str, snap_hash: str) -> m.Scan | None:
    """The scan row this run re-uses: the NEWEST match for (month, ruleset, snapshot).

    Newest, not oldest: a month can carry several scan rows once its snapshot has been rewritten by
    an applied remediation, and the one a reader means by "the scan for month N" — the one `verify`
    and the ledger badge report on — is the latest. Re-using the oldest made `athar scan --month N`
    rewrite a row nobody was looking at, so the restore after a tamper appeared to do nothing.
    """
    return session.scalars(
        select(m.Scan)
        .where(
            m.Scan.snapshot_month == month,
            m.Scan.ruleset_hash == rules_hash,
            m.Scan.snapshot_hash == snap_hash,
        )
        .order_by(m.Scan.scan_id.desc())
    ).first()


def _first_seen_month(session: Session, key: str, month: int) -> int:
    """The earliest month this finding key was ever recorded (SPEC §10.1)."""
    earliest = session.scalars(
        select(m.Scan.snapshot_month)
        .join(m.Finding, m.Finding.scan_id == m.Scan.scan_id)
        .where(m.Finding.finding_key == key)
        .order_by(m.Scan.snapshot_month)
    ).first()
    return min(earliest, month) if earliest is not None else month


def build_findings(
    estate: EstateView,
    drafts: list[FindingDraft],
    scores: dict[str, ScoreResult],
    first_seen: dict[str, int],
) -> list[dict[str, Any]]:
    """Draft + score → the committed instance plus everything the API renders. Pure."""
    out: list[dict[str, Any]] = []
    for draft in drafts:
        key = finding_key(draft.identity_id, draft.rule_id)
        score = scores.get(draft.identity_id)
        causal = causal_history(estate, draft)
        instance = finding_instance(
            finding_key=key,
            identity_id=draft.identity_id,
            rule_id=draft.rule_id,
            severity=draft.severity,
            score=score.score if score else 0,
            snapshot_month=estate.month,
            first_seen_month=first_seen.get(key, estate.month),
            evidence_refs=draft.evidence_keys(),
            causal_event_ids=sorted(draft.causal_event_ids),
        )
        facts = dict(draft.facts)
        facts.setdefault("severity", draft.severity)
        grants = [g for g in estate.grants_for(draft.identity_id)]
        altitudes = render_all(
            draft.rule_id,
            facts,
            score=score,
            causal=causal,
            first_seen_month=instance["first_seen_month"],
            evidence_refs=[{"kind": e.kind, "ref": e.ref, "note": e.note} for e in draft.evidence],
            grants=grants,
            path=facts.get("path"),
        )
        out.append(
            {
                "instance": instance,
                "instance_hash": instance_hash(instance),
                "draft": draft,
                "facts": facts,
                "altitudes": altitudes,
                "causal": causal,
            }
        )
    out.sort(key=lambda f: (f["instance"]["rule_id"], f["instance"]["identity_id"]))
    return out


def _persist(
    session: Session,
    scan: m.Scan,
    findings: list[dict[str, Any]],
    scores: dict[str, ScoreResult],
    proofs: dict[str, tuple[str, list[str]]],
) -> None:
    session.execute(delete(m.Finding).where(m.Finding.scan_id == scan.scan_id))
    session.execute(delete(m.IdentityScore).where(m.IdentityScore.scan_id == scan.scan_id))
    session.flush()
    for f in findings:
        inst = f["instance"]
        _leaf, proof = proofs.get(f["instance_hash"], ("", []))
        session.add(
            m.Finding(
                finding_key=inst["finding_key"],
                scan_id=scan.scan_id,
                identity_id=inst["identity_id"],
                rule_id=inst["rule_id"],
                severity=inst["severity"],
                score=inst["score"],
                first_seen_month=inst["first_seen_month"],
                evidence_refs=inst["evidence_refs"],
                causal_event_ids=inst["causal_event_ids"],
                instance_hash=f["instance_hash"],
                leaf_proof=proof,
                status="open",
                facts=f["facts"],
            )
        )
    for identity_id, score in scores.items():
        session.add(
            m.IdentityScore(
                identity_id=identity_id,
                scan_id=scan.scan_id,
                blast_radius=score.blast_radius,
                reach=score.reach,
                exploitability=score.exploitability,
                compensating=score.compensating,
                score=score.score,
                severity=score.severity,
                line_items=score.line_items_json(),
                escalation_paths=score.paths_json(),
            )
        )
    session.flush()


def commit_index_for(
    session: Session, writer: Any, snap_hash: str, root: str, rules_hash: str, *, scan_id: int | None = None
) -> int | None:
    """An earlier commit of exactly this root, confirmed against the chain (SPEC §12.4 idempotency).

    Every candidate index is confirmed on-chain before it is reused, including the one on the row
    being written. That row already carries `root` but may still hold the index of a *different*
    root from an earlier run — which is what happens when a granted exception changes the findings
    and the month is re-scanned. Reusing it marked the new root "already anchored" against the old
    commit, so `athar verify` failed while the badge stayed green. Confirming on-chain settles both
    cases: an unchanged re-scan reuses its commit, a changed one gets a new commit.

    Shared with the parked-job retry in `services.wiring`, which has to make the same decision with
    a session of its own: the contract accepts duplicate commits by design, so whoever is about to
    send one is the only thing standing between the chain and two copies of the same root.
    """
    rows = session.scalars(
        select(m.Scan)
        .where(
            m.Scan.snapshot_hash == snap_hash,
            m.Scan.merkle_root == root,
            m.Scan.ruleset_hash == rules_hash,
            m.Scan.ledger_scan_index.is_not(None),
        )
        .order_by(m.Scan.scan_id)
    ).all()
    for row in rows:
        index = row.ledger_scan_index
        if index is None:
            continue
        try:
            commit = writer.client.get_commit(index)
        except Exception as exc:
            log.warning(
                "could not confirm an earlier commit; anchoring again",
                extra={"scan_id": scan_id, "error": type(exc).__name__},
            )
            return None
        if commit.findings_root.lower() == root.lower():
            return index
        log.info(
            "scan row points at a commit holding a different root; looking further",
            extra={"scan_id": row.scan_id, "index": index},
        )
    return None


def _anchor(
    session: Session,
    scan: m.Scan,
    root: str,
    snap_hash: str,
    rules_hash: str,
    count: int,
    writer: Any,
) -> tuple[str, int | None, str | None, str]:
    """Commit the root on-chain. Never raises: the ledger must not block the pipeline (SPEC §12.4)."""
    if writer is None:
        return "unanchored", None, None, "ledger disabled"

    def existing_index() -> int | None:
        return commit_index_for(session, writer, snap_hash, root, rules_hash, scan_id=scan.scan_id)

    try:
        receipt = writer.commit_scan(
            snap_hash, root, rules_hash, count, existing_index_lookup=existing_index, tag=scan.scan_id
        ).result(timeout=90)
    except Exception as exc:
        log.warning("scan not anchored", extra={"scan_id": scan.scan_id, "error": type(exc).__name__})
        return "unanchored", None, None, f"not anchored ({type(exc).__name__})"
    if receipt.already_anchored:
        return "already_anchored", receipt.scan_index, None, "already anchored"
    return "anchored", receipt.scan_index, receipt.tx_hash, "anchored"


def restorable_scan(session: Session, settings: Settings, scan_id: int) -> int | None:
    """The scan id that re-running `athar scan --month N` would rewrite, for the given scan's month.

    `None` when the estate on disk can no longer reproduce that month — its snapshot has been
    superseded by a later ingest — so nothing can restore it. Used by `athar tamper` to keep the
    demo's tamper beat reversible.
    """
    scan = session.get(m.Scan, scan_id)
    if scan is None:
        return None
    thresholds = load_thresholds(session, settings)
    match = _existing_scan(
        session,
        scan.snapshot_month,
        current_ruleset_hash(thresholds),
        _snapshot_hash_for(session, scan.snapshot_month),
    )
    return match.scan_id if match is not None else None


def run_scan(
    session: Session,
    settings: Settings,
    month: int,
    *,
    writer: Any = None,
    thresholds: Thresholds | None = None,
) -> ScanOutcome:
    """Run every stage for one snapshot month and persist the result."""
    started = datetime.now(UTC)
    if session.get(m.Snapshot, month) is None:
        raise ValueError(f"month {month} has not been ingested")
    thresholds = thresholds or load_thresholds(session, settings)
    rules_hash = current_ruleset_hash(thresholds)
    snap_hash = _snapshot_hash_for(session, month)

    events_written = write_diff_events(session, month)
    estate = load_estate_view(session, month)

    drafts = run_all(estate, thresholds)
    graph = build_graph(estate)
    by_identity: dict[str, list[FindingDraft]] = {}
    for d in drafts:
        by_identity.setdefault(d.identity_id, []).append(d)
    scores = score_all(estate, by_identity, graph)

    first_seen = {finding_key(d.identity_id, d.rule_id): 0 for d in drafts}
    for key in list(first_seen):
        first_seen[key] = _first_seen_month(session, key, month)
    findings = build_findings(estate, drafts, scores, first_seen)

    hashes = [f["instance_hash"] for f in findings]
    root = ledger_verify.compute_root(hashes)
    proofs = ledger_verify.leaf_proofs(hashes)

    scan = _existing_scan(session, month, rules_hash, snap_hash)
    created = scan is None
    if scan is None:
        scan = m.Scan(
            snapshot_month=month,
            ruleset_hash=rules_hash,
            started_at=started,
            snapshot_hash=snap_hash,
            ledger_status="pending",
        )
        session.add(scan)
        session.flush()
    scan.merkle_root = root
    scan.finding_count = len(findings)
    scan.finished_at = datetime.now(UTC)

    _persist(session, scan, findings, scores, proofs)

    status, index, tx, detail = _anchor(session, scan, root, snap_hash, rules_hash, len(findings), writer)
    scan.ledger_status = status
    if index is not None:
        scan.ledger_scan_index = index
    if tx is not None:
        scan.ledger_tx = tx
    session.flush()
    session.commit()

    log.info(
        "scan complete",
        extra={
            "scan_id": scan.scan_id,
            "month": month,
            "findings": len(findings),
            "root": root,
            "ledger": status,
        },
    )
    return ScanOutcome(
        scan_id=scan.scan_id,
        month=month,
        finding_count=len(findings),
        merkle_root=root,
        snapshot_hash=snap_hash,
        ruleset_hash=rules_hash,
        ledger_status=status,
        ledger_scan_index=scan.ledger_scan_index,
        ledger_tx=scan.ledger_tx,
        created=created,
        events_written=events_written,
        detail=detail,
    )
