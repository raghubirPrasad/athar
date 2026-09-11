"""`DbRepo.advance` and auto-remediation against a real database (SPEC §11.5, §11.6).

Both paths change the estate on disk and the database together, so neither can be pinned by a
unit test. The module owns a **private schema** and a **temporary estate** generated into a
`tmp_path` data directory: it never advances, and never disables an identity in, the demo estate
under `data/estate/` (SPEC §4.7 is forward-only — an advance there could not be undone).

A small estate keeps the re-simulations that `apply_remediations` performs cheap.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from athar.config import Settings, get_settings
from athar.db import models as m
from athar.security.auth import AuthUser
from athar.services import queries
from athar.services.repo import DbRepo
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

# Per-process so two test runs against one Postgres cannot drop each other's schema.
SCHEMA = f"athar_test_advance_{os.getpid()}"
SEED = 42
# Five months and eighty identities is the smallest estate this seed produces that carries more
# than one departed human past the SPEC §11.5 thirty-day gate with access still live.
MONTHS = 5
IDENTITIES = 80

ANALYST = AuthUser(user_id="usr-analyst", email="analyst@athar.local", role="analyst")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A throwaway ATHAR_DATA_DIR holding `estate/seed-42/month-01..MONTHS`."""
    generate = pytest.importorskip(
        "athar.generator.estate", reason="the generator lane is not on disk yet"
    ).generate_estate
    root = tmp_path_factory.mktemp("data")
    generate(seed=SEED, months=MONTHS, identities=IDENTITIES, out_dir=root / "estate")
    return root


@pytest.fixture(scope="module")
def settings(data_dir: Path) -> Settings:
    return get_settings().model_copy(update={"data_dir": str(data_dir), "athar_seed": SEED})


@pytest.fixture(scope="module")
def engine(db_url: str) -> Any:
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {SCHEMA}"))
    admin.dispose()
    scoped = create_engine(db_url, future=True, connect_args={"options": f"-csearch_path={SCHEMA}"})
    m.Base.metadata.create_all(scoped)
    yield scoped
    scoped.dispose()
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
    admin.dispose()


@pytest.fixture(scope="module")
def repo(engine: Any, settings: Settings) -> Any:
    """Every month on disk ingested and scanned once — the state `make demo` leaves behind."""
    from athar.services.ingest import estate_dir_for, ingest_all
    from athar.services.scan import run_scan

    session = Session(engine)
    ingest_all(session, estate_dir_for(settings))
    for month in range(1, MONTHS + 1):
        run_scan(session, settings, month, writer=None)
    instance = DbRepo(session, settings)
    instance._settings_row()  # the runtime row, with this build's thresholds (SPEC §7)
    yield instance
    instance.close()


def _findings(session: Session, scan_id: int) -> list[m.Finding]:
    return list(session.scalars(select(m.Finding).where(m.Finding.scan_id == scan_id)))


def _active_grants(session: Session, identity_id: str, month: int) -> list[str]:
    rows = session.scalars(
        select(m.Grant).where(m.Grant.identity_id == identity_id, m.Grant.snapshot_month == month)
    )
    return sorted(g.grant_id for g in rows if g.active)


def _latest_scan(session: Session, month: int) -> m.Scan:
    scan = queries.scan_for_month(session, month)
    assert scan is not None
    return scan


# ---------------------------------------------------------------------------
# SPEC §11.6 — the advance button runs the scheduler's cycle
# ---------------------------------------------------------------------------


def test_advance_simulates_ingests_and_scans_the_new_month(repo: Any, settings: Settings) -> None:
    before = repo.current_month()
    result = repo.advance(ANALYST)

    assert result.new_month == before + 1
    assert repo.current_month() == result.new_month
    assert result.scan.snapshot_month == result.new_month
    assert result.scan.finding_count > 0, "a drifting estate must produce findings"

    month_dir = Path(settings.data_dir) / "estate" / f"seed-{SEED}" / f"month-{result.new_month:02d}"
    assert month_dir.is_dir(), "the new month's native exports must be on disk (SPEC §4.7)"
    assert repo.session.get(m.Snapshot, result.new_month) is not None


def test_advance_runs_the_same_cycle_as_the_scheduler(repo: Any) -> None:
    """SPEC §11.6: the advance triggers the whole loop, not only its scan half."""
    result = repo.advance(ANALYST)
    scan = _latest_scan(repo.session, result.new_month)

    rows = _findings(repo.session, scan.scan_id)
    assert rows, "the new month must have findings for the cycle to investigate"
    assert any(r.status == "investigated" for r in rows), (
        "the cycle investigates new findings (SPEC §11.6); every one was left open"
    )
    cached = repo.session.get(m.LlmCache, queries.summary_cache_key(scan.scan_id))
    assert cached is not None, "the cycle ends with an executive summary cached for the Overview"
    assert str(cached.output.get("summary_paragraph", "")).strip()


def test_advance_writes_an_audit_row_naming_the_scan_it_produced(repo: Any) -> None:
    month = repo.current_month()
    row = repo.session.scalars(
        select(m.AuditLog)
        .where(m.AuditLog.action == "advance", m.AuditLog.subject_id == str(month))
        .order_by(m.AuditLog.id.desc())
        .limit(1)
    ).first()
    assert row is not None
    assert row.detail["scan_id"] == _latest_scan(repo.session, month).scan_id


# ---------------------------------------------------------------------------
# SPEC §11.5 — auto-remediation performs the action it records
# ---------------------------------------------------------------------------


def _set_auto(repo: Any, enabled: bool) -> None:
    repo._settings_row().auto_remediate_departed = enabled
    repo.session.commit()


def _except_identity(repo: Any, identity_id: str) -> None:
    """An unexpired break-glass entry in the governance register (SPEC §4.3)."""
    repo.session.add(
        m.GovernanceException(
            exception_id=f"exc-test-{identity_id}",
            identity_id=identity_id,
            exception_type="break-glass",
            approved_by="usr-approver",
            approved_on=date(2025, 9, 1),
            review_date=date(2099, 1, 1),
            expires_on=date(2099, 1, 1),
            justification="pinned by the test",
            source="register",
        )
    )
    repo.session.commit()


def test_auto_remediation_gate_flag_exception_and_the_action_itself(repo: Any, settings: Settings) -> None:
    """Flag off → nothing; flag on → the identity loses its grants; an exception is skipped."""
    from athar.services.remediation import DECISION_AUTO, _auto_candidates, auto_remediate

    month = repo.current_month()
    scan = _latest_scan(repo.session, month)
    candidates = _auto_candidates(repo.session, scan.scan_id, month)
    if len(candidates) < 2:
        pytest.skip("this estate has fewer than two departed humans past the 30-day gate")
    target, spared = candidates[0], candidates[1]
    target_grants = _active_grants(repo.session, target.identity_id, month)
    spared_grants = _active_grants(repo.session, spared.identity_id, month)
    assert target_grants and spared_grants, "an R3 finding must cite active grants"

    # --- flag off: nothing at all happens -----------------------------------
    _set_auto(repo, False)
    assert auto_remediate(repo.session, settings, scan.scan_id, writer=None) == []
    assert _active_grants(repo.session, target.identity_id, month) == target_grants
    assert _latest_scan(repo.session, month).scan_id == scan.scan_id, "no re-scan while the flag is off"
    still_open = repo.session.get(m.Finding, {"finding_key": target.finding_key, "scan_id": scan.scan_id})
    assert still_open is not None and still_open.status != "remediated"

    # --- an unexpired register entry keeps one identity out of the batch -----
    _except_identity(repo, spared.identity_id)

    # --- flag on: the action is performed, not only recorded -----------------
    _set_auto(repo, True)
    decisions = auto_remediate(repo.session, settings, scan.scan_id, writer=None)
    assert decisions, "a qualifying R3 finding must produce a decision"
    assert {d.decision for d in decisions} == {DECISION_AUTO}
    assert all(d.actor_user_id == "system:auto" for d in decisions)
    assert target.finding_key in {d.finding_key for d in decisions}
    assert spared.finding_key not in {d.finding_key for d in decisions}

    assert _active_grants(repo.session, target.identity_id, month) == [], (
        "disable_identity must actually remove the identity's access from the estate"
    )
    assert _active_grants(repo.session, spared.identity_id, month) == spared_grants, (
        "an identity with an unexpired exception must be left alone (SPEC §11.5)"
    )
    remediated = repo.session.get(m.Finding, {"finding_key": target.finding_key, "scan_id": scan.scan_id})
    assert remediated is not None and remediated.status == "remediated"

    entry = repo.session.scalars(
        select(m.AuditLog)
        .where(m.AuditLog.action == "auto_remediate", m.AuditLog.subject_id == target.finding_key)
        .order_by(m.AuditLog.id.desc())
        .limit(1)
    ).first()
    assert entry is not None
    assert entry.detail["action"] == "disable_identity"
    assert entry.detail["estate"] == "changed"

    # --- the re-scan no longer raises R3 on an identity with no access -------
    rescan = _latest_scan(repo.session, month)
    assert rescan.scan_id != scan.scan_id, "applying the action must re-ingest and re-scan"
    assert not [
        f
        for f in _findings(repo.session, rescan.scan_id)
        if f.identity_id == target.identity_id and f.rule_id == "R3"
    ]

    # --- second pass over the same scan changes nothing more ----------------
    decisions_again = auto_remediate(repo.session, settings, scan.scan_id, writer=None)
    assert {d.decision_id for d in decisions_again} <= {d.decision_id for d in decisions}
    assert _latest_scan(repo.session, month).scan_id == rescan.scan_id, "no second re-scan"
    assert _active_grants(repo.session, spared.identity_id, month) == spared_grants
    _set_auto(repo, False)
