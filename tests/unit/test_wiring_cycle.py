"""The governance tick acts on the scan that is current when it finishes (SPEC §11.5, §11.6).

Auto-remediation disables departed identities in the simulated estate, re-ingests the month and
re-scans it, so the scan `run_scan` returned at the top of the tick is superseded before the tick
is over. Investigating and summarising that superseded row would describe access the estate no
longer grants, and would cache the executive paragraph under a scan id nothing ever reads back:
every UI path resolves the newest scan of the month.

The cycle is driven here over fakes — no Postgres, no Anvil, no estate — because the thing under
test is which scan id the tick carries forward, not what a scan contains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class FakeScan:
    scan_id: int
    snapshot_month: int = 12
    finding_count: int = 0


@dataclass
class FakeSession:
    """Records the bound parameters of every `scalars()` statement; returns no rows."""

    queries: list[dict[str, Any]] = field(default_factory=list)
    commits: int = 0

    def scalars(self, stmt: Any) -> list[Any]:
        self.queries.append(dict(stmt.compile().params))
        return []

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:  # pragma: no cover - the happy path never rolls back
        pass


@dataclass
class FakeOutcome:
    scan_id: int
    finding_count: int = 0


@pytest.fixture
def cycle(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Drive `_run_cycle` with every collaborator faked; returns a recorder of what it was given."""
    from athar.services import agents, queries, remediation, wiring
    from athar.services import scan as scan_mod

    seen: dict[str, Any] = {"summarised": None, "remembered": None}

    monkeypatch.setattr(wiring, "drain_ledger_retries", lambda session, writer: 0)
    monkeypatch.setattr(queries, "current_month", lambda session: 12)
    monkeypatch.setattr(
        scan_mod, "run_scan", lambda session, settings, month, writer=None: FakeOutcome(scan_id=1)
    )

    def summarise(session: Any, settings: Any, scan: Any, regenerate: bool = False) -> dict[str, Any]:
        seen["summarised"] = scan
        return {"summary_paragraph": "."}

    def remember(session: Any, settings: Any, scan_id: int, result: dict[str, Any]) -> None:
        seen["remembered"] = scan_id

    monkeypatch.setattr(agents, "estate_summary_paragraph", summarise)
    monkeypatch.setattr(wiring, "_remember_summary", remember)
    monkeypatch.setattr(remediation, "auto_remediate", lambda *a, **k: [])
    seen["module"] = wiring
    seen["queries"] = queries
    return seen


def test_the_tick_carries_the_scan_auto_remediation_left_behind(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Auto-remediation re-scans; the tick must investigate and summarise the row it produced."""
    superseded, current = FakeScan(scan_id=1), FakeScan(scan_id=2)
    monkeypatch.setattr(cycle["queries"], "scan_for_month", lambda session, month: current)
    monkeypatch.setattr(cycle["queries"], "scan_by_id", lambda session, scan_id: superseded)
    session = FakeSession()

    cycle["module"]._run_cycle(session, object(), None)

    assert cycle["summarised"] is current, "the pre-remediation scan describes access already gone"
    assert cycle["remembered"] == 2, "the Overview reads the newest scan; cache under that id"
    assert session.queries, "the tick queried for findings to investigate"
    assert 2 in session.queries[0].values(), "findings came from the current scan, not the stale one"


def test_with_auto_remediation_off_the_tick_uses_the_scan_it_just_ran(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common path: nothing supersedes the scan, so re-resolving returns the same row."""
    just_run = FakeScan(scan_id=1)
    monkeypatch.setattr(cycle["queries"], "scan_for_month", lambda session, month: just_run)
    monkeypatch.setattr(cycle["queries"], "scan_by_id", lambda session, scan_id: just_run)

    cycle["module"]._run_cycle(FakeSession(), object(), None)

    assert cycle["summarised"] is just_run
    assert cycle["remembered"] == 1


def test_a_month_with_no_scan_row_falls_back_to_the_returned_id(
    cycle: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`scan_for_month` returning None must not silently end the tick before it investigates."""
    returned = FakeScan(scan_id=1)
    monkeypatch.setattr(cycle["queries"], "scan_for_month", lambda session, month: None)
    monkeypatch.setattr(cycle["queries"], "scan_by_id", lambda session, scan_id: returned)

    cycle["module"]._run_cycle(FakeSession(), object(), None)

    assert cycle["summarised"] is returned


@dataclass
class FakeFinding:
    finding_key: str
    status: str = "open"
    score: int = 90


def test_the_agent_half_stops_when_its_budget_is_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    """`POST /simulate/advance` runs this loop inline, behind a 120-second proxy timeout.

    With a cold cache and a real provider each investigation can take the full LLM timeout, so an
    unbounded loop turns a successful advance into a gateway timeout. A month that advanced,
    scanned and anchored is a complete result; the remaining investigations belong to the next tick.
    """
    from athar.services import agents, queries, remediation, wiring
    from athar.services import scan as scan_mod

    investigated: list[str] = []
    clock = {"t": 0.0}

    class Session:
        def scalars(self, stmt: Any) -> list[Any]:
            return [FakeFinding(f"f{i}") for i in range(5)]

        def commit(self) -> None:
            pass

        def rollback(self) -> None:  # pragma: no cover
            pass

    def investigate(session: Any, settings: Any, row: Any, regenerate: bool = False) -> None:
        investigated.append(row.finding_key)
        clock["t"] += 20.0  # each model call costs the full LLM timeout

    scan = FakeScan(scan_id=1)
    monkeypatch.setattr(wiring, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(wiring, "drain_ledger_retries", lambda session, writer: 0)
    monkeypatch.setattr(wiring, "_remember_summary", lambda *a, **k: None)
    monkeypatch.setattr(queries, "current_month", lambda session: 12)
    monkeypatch.setattr(queries, "scan_for_month", lambda session, month: scan)
    monkeypatch.setattr(queries, "scan_by_id", lambda session, scan_id: scan)
    monkeypatch.setattr(
        scan_mod, "run_scan", lambda session, settings, month, writer=None: FakeOutcome(scan_id=1)
    )
    monkeypatch.setattr(remediation, "auto_remediate", lambda *a, **k: [])
    monkeypatch.setattr(agents, "investigate_finding", investigate)
    monkeypatch.setattr(agents, "estate_summary_paragraph", lambda *a, **k: {"summary_paragraph": "."})

    wiring._run_cycle(Session(), object(), None, 12, agent_budget_seconds=45.0)

    assert investigated == ["f0", "f1", "f2"], "three at twenty seconds fits in forty-five, four does not"


def test_without_a_budget_every_finding_is_investigated(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scheduler passes no budget and does all of it — nothing here rations the timer's work."""
    from athar.services import agents, queries, remediation, wiring
    from athar.services import scan as scan_mod

    investigated: list[str] = []

    class Session:
        def scalars(self, stmt: Any) -> list[Any]:
            return [FakeFinding(f"f{i}") for i in range(5)]

        def commit(self) -> None:
            pass

        def rollback(self) -> None:  # pragma: no cover
            pass

    scan = FakeScan(scan_id=1)
    monkeypatch.setattr(wiring, "monotonic", lambda: 10_000.0)  # far past any plausible deadline
    monkeypatch.setattr(wiring, "drain_ledger_retries", lambda session, writer: 0)
    monkeypatch.setattr(wiring, "_remember_summary", lambda *a, **k: None)
    monkeypatch.setattr(queries, "current_month", lambda session: 12)
    monkeypatch.setattr(queries, "scan_for_month", lambda session, month: scan)
    monkeypatch.setattr(queries, "scan_by_id", lambda session, scan_id: scan)
    monkeypatch.setattr(
        scan_mod, "run_scan", lambda session, settings, month, writer=None: FakeOutcome(scan_id=1)
    )
    monkeypatch.setattr(remediation, "auto_remediate", lambda *a, **k: [])
    monkeypatch.setattr(
        agents,
        "investigate_finding",
        lambda s, st, row, regenerate=False: investigated.append(row.finding_key),
    )
    monkeypatch.setattr(agents, "estate_summary_paragraph", lambda *a, **k: {"summary_paragraph": "."})

    wiring._run_cycle(Session(), object(), None)

    assert len(investigated) == 5
