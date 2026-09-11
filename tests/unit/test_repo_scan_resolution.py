"""`POST /scan` returns the scan that stands when it finishes, not the one it started (SPEC §11.5).

`DbRepo.run_scan` runs the scan and then auto-remediation. Auto-remediation disables departed
identities in the simulated estate, re-ingests the month and re-scans it, so by the time the
request returns, the row `run_scan` produced has been superseded. Handing that row back reports a
finding count for access that has since been removed, and points the dashboard at a scan older
than the one every other read resolves.

Driven over fakes: the behaviour under test is which scan id survives the call, and that needs no
Postgres, no estate and no chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class FakeScanRow:
    scan_id: int
    snapshot_month: int = 12
    finding_count: int = 0


@dataclass
class FakeOutcome:
    scan_id: int
    finding_count: int
    ledger_status: str = "anchored"


@dataclass
class FakeSession:
    commits: int = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:  # pragma: no cover - the happy path never rolls back
        pass


@dataclass
class FakeUser:
    user_id: str = "u-1"


@dataclass
class Recorder:
    audited: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A `DbRepo` whose scan, auto-remediation, audit and reads are all fakes."""
    from athar.services import queries, remediation
    from athar.services import scan as scan_mod
    from athar.services.repo import DbRepo

    rec = Recorder()

    monkeypatch.setattr(
        scan_mod,
        "run_scan",
        lambda session, settings, month, writer=None: FakeOutcome(scan_id=1, finding_count=106),
    )
    monkeypatch.setattr(remediation, "auto_remediate", lambda *a, **k: [])
    monkeypatch.setattr(
        remediation,
        "audit",
        lambda session, actor, action, kind, ref, detail: rec.audited.append(
            {"action": action, "ref": ref, "detail": detail}
        ),
    )
    monkeypatch.setattr(queries, "scan_out", lambda row: row)

    instance = DbRepo(FakeSession(), object())
    return instance, rec, queries


def test_it_returns_the_scan_auto_remediation_left_behind(repo: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-remediation re-scanned; the caller must be told about the row that now stands."""
    instance, rec, queries = repo
    current = FakeScanRow(scan_id=2, finding_count=91)
    monkeypatch.setattr(queries, "scan_for_month", lambda session, month: current)
    monkeypatch.setattr(queries, "scan_by_id", lambda session, scan_id: FakeScanRow(scan_id=scan_id))

    out = instance.run_scan(12, FakeUser())

    assert out.scan_id == 2, "the pre-remediation scan describes access that has been removed"
    assert rec.audited[0]["ref"] == "2", "the audit trail must name the scan that stands"
    assert rec.audited[0]["detail"]["findings"] == 91, "and its finding count, not the stale one"


def test_with_auto_remediation_off_it_returns_the_scan_it_ran(
    repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common path: nothing supersedes the scan, so re-resolving finds the same row."""
    instance, rec, queries = repo
    same = FakeScanRow(scan_id=1, finding_count=106)
    monkeypatch.setattr(queries, "scan_for_month", lambda session, month: same)
    monkeypatch.setattr(queries, "scan_by_id", lambda session, scan_id: FakeScanRow(scan_id=scan_id))

    out = instance.run_scan(12, FakeUser())

    assert out.scan_id == 1
    assert rec.audited[0]["detail"]["findings"] == 106


def test_a_month_with_no_readable_scan_row_falls_back_to_the_outcome(
    repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`scan_for_month` returning None must not turn a successful scan into scan 0."""
    instance, rec, queries = repo
    monkeypatch.setattr(queries, "scan_for_month", lambda session, month: None)
    monkeypatch.setattr(queries, "scan_by_id", lambda session, scan_id: FakeScanRow(scan_id=scan_id))

    out = instance.run_scan(12, FakeUser())

    assert out.scan_id == 1
    assert rec.audited[0]["detail"]["findings"] == 106
