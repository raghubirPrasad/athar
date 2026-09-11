"""The governance tick drains ledger jobs an outage parked (SPEC §12.4).

`LedgerWriter.retry_pending()` has always existed and was never called, so the "background retry
drains the queue" half of SPEC §12.4 was a promise with no running thing behind it. It runs from
`_run_cycle` now, before anything in the tick anchors.

These tests drive a real :class:`LedgerWriter` over a fake node — so the job is parked by the same
code path a real outage takes — and a fake session, so no Postgres is needed.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from athar.db import models as m
from athar.ledger.client import LedgerUnavailable
from athar.ledger.writer import LedgerWriter
from athar.services.wiring import drain_ledger_retries

H = "0x" + "ab" * 32
LEAF = "0x" + "cd" * 32


class FakeNode:
    """A node that can be switched off: every call raises `LedgerUnavailable` while `down`."""

    writer_address = "0x000000000000000000000000000000000000dEaD"

    def __init__(self) -> None:
        self.down = False
        self.pending = 0
        self.sent: list[dict[str, Any]] = []

    def _check(self) -> None:
        if self.down:
            raise LedgerUnavailable()

    def pending_nonce(self) -> int:
        self._check()
        return self.pending

    def build_commit_tx(self, nonce: int, s: str, r: str, rs: str, count: int) -> Any:
        self._check()
        return {"nonce": nonce, "kind": "commit"}

    def build_decision_tx(
        self, nonce: int, idx: int, leaf: str, proof: list[str], d: int, a: str, e: str
    ) -> Any:
        self._check()
        return {"nonce": nonce, "kind": "decision"}

    def sign_and_send(self, tx: Any) -> str:
        self._check()
        self.pending += 1
        self.sent.append(tx)
        return f"0x{len(self.sent):064x}"

    def wait_for_receipt(self, tx_hash: str, timeout: float) -> Any:
        self._check()
        return {"blockNumber": 100 + len(self.sent), "status": 1, "transactionHash": tx_hash}

    def parse_scan_index(self, receipt: Any) -> int:
        return len([t for t in self.sent if t["kind"] == "commit"]) - 1


class FakeSession:
    """`get(model, pk)` over dicts the test seeds, plus a commit counter."""

    def __init__(self, *rows: Any) -> None:
        self.rows: dict[tuple[type, Any], Any] = {}
        for row in rows:
            pk = row.scan_id if isinstance(row, m.Scan) else row.decision_id
            self.rows[(type(row), pk)] = row
        self.commits = 0

    def get(self, model: type, pk: Any) -> Any:
        return self.rows.get((model, pk))

    def commit(self) -> None:
        self.commits += 1


def a_scan(scan_id: int = 5) -> m.Scan:
    return m.Scan(
        scan_id=scan_id,
        snapshot_month=12,
        ruleset_hash=H,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        finding_count=3,
        merkle_root=H,
        snapshot_hash=H,
        ledger_scan_index=None,
        ledger_tx=None,
        ledger_status="unanchored",
    )


def a_decision(decision_id: str = "dec-abc") -> m.Decision:
    return m.Decision(
        decision_id=decision_id,
        plan_id=None,
        finding_key="f" * 32,
        scan_id=5,
        decision="approved",
        actor_user_id="u1",
        evidence_hash=H,
        ledger_tx=None,
        ledger_status="unanchored",
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def node() -> FakeNode:
    return FakeNode()


@pytest.fixture
def writer(node: FakeNode) -> Iterator[LedgerWriter]:
    w = LedgerWriter(node, receipt_timeout=1.0)
    yield w
    w.stop()


def quiesce(writer: LedgerWriter) -> None:
    """Wait for the worker to finish parking and go idle, the way a real tick boundary does.

    `LedgerWriter._park_queued` empties the queue with the outage's exception after the failing
    job's future has already resolved, so a retry enqueued in that same instant can be swallowed
    by the tail of the job that failed. In the API the drain happens on a scheduler tick minutes
    after the outage and the window does not exist; here the two are microseconds apart. Stopping
    the worker returns only once it has finished, and `retry_pending` starts a fresh one.
    """
    writer.stop()


def park_a_commit(writer: LedgerWriter, node: FakeNode, scan_id: int = 5) -> None:
    """Anchor a scan while the node is down, exactly as `run_scan` does (services/scan.py)."""
    node.down = True
    future = writer.commit_scan(H, H, H, 3, tag=scan_id)
    with pytest.raises(LedgerUnavailable):
        future.result(timeout=5)
    quiesce(writer)
    assert writer.pending_count == 1


# ---------------------------------------------------------------- the retry


def test_scan_parked_by_an_outage_is_anchored_on_the_next_tick(writer: LedgerWriter, node: FakeNode) -> None:
    scan = a_scan()
    park_a_commit(writer, node, scan.scan_id)
    assert scan.ledger_status == "unanchored" and scan.ledger_scan_index is None

    node.down = False  # the node came back between ticks
    session = FakeSession(scan)
    assert drain_ledger_retries(session, writer) == 1

    assert scan.ledger_status == "anchored"
    assert scan.ledger_scan_index == 0
    assert scan.ledger_tx == "0x" + "0" * 63 + "1"
    assert writer.pending_count == 0
    assert session.commits == 1
    assert len(node.sent) == 1, "the parked job is sent exactly once, not duplicated"


def test_parked_decision_is_anchored_by_its_decision_id(writer: LedgerWriter, node: FakeNode) -> None:
    decision = a_decision()
    node.down = True
    future = writer.record_decision(0, LEAF, [], 1, H, H, tag=decision.decision_id)
    with pytest.raises(LedgerUnavailable):
        future.result(timeout=5)
    quiesce(writer)

    node.down = False
    session = FakeSession(decision)
    assert drain_ledger_retries(session, writer) == 1
    assert decision.ledger_status == "anchored"
    assert decision.ledger_tx == "0x" + "0" * 63 + "1"


def test_node_still_down_reparks_and_leaves_the_row_unanchored(writer: LedgerWriter, node: FakeNode) -> None:
    """The retry is not a one-shot: a failed drain must leave the job for the tick after."""
    scan = a_scan()
    park_a_commit(writer, node, scan.scan_id)
    session = FakeSession(scan)

    assert drain_ledger_retries(session, writer) == 0
    assert scan.ledger_status == "unanchored" and scan.ledger_scan_index is None
    assert session.commits == 0
    assert writer.pending_count == 1, "still parked, so the next tick tries again"

    node.down = False
    assert drain_ledger_retries(session, writer) == 1
    assert scan.ledger_status == "anchored"


def test_nothing_parked_is_a_no_op(writer: LedgerWriter, node: FakeNode) -> None:
    session = FakeSession(a_scan())
    assert drain_ledger_retries(session, writer) == 0
    assert session.commits == 0 and not node.sent


def test_no_writer_is_a_no_op() -> None:
    """The ledger-disabled and node-down-at-start-up paths leave `app.state.ledger_writer` None."""
    session = FakeSession(a_scan())
    assert drain_ledger_retries(session, None) == 0
    assert session.commits == 0


def test_a_job_whose_row_is_gone_is_not_counted(writer: LedgerWriter, node: FakeNode) -> None:
    """A tag with no row (a reset database) must not raise and must not claim a drain."""
    park_a_commit(writer, node, scan_id=999)
    node.down = False
    session = FakeSession(a_scan(5))
    assert drain_ledger_retries(session, writer) == 0
    assert session.commits == 0


def test_the_cycle_drains_before_it_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ordering is load-bearing: draining after `run_scan` could double-commit the same root.

    A parked commit is past its `existing_index_lookup`, so if the tick anchored the same root
    first, the retry would add a second on-chain commit of it (SPEC §12.4 idempotency).
    """
    from athar.services import queries, wiring

    calls: list[str] = []

    def record_drain(session: Any, writer: Any) -> int:
        calls.append("drain")
        return 0

    def record_month(session: Any) -> None:
        calls.append("month")
        return None  # nothing ingested, so the cycle stops here

    monkeypatch.setattr(wiring, "drain_ledger_retries", record_drain)
    monkeypatch.setattr(queries, "current_month", record_month)

    wiring._run_cycle(object(), object(), None)

    assert calls == ["drain", "month"]


def test_a_parked_commit_already_on_chain_is_not_sent_again(
    writer: LedgerWriter, node: FakeNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The idempotency hook runs before the job is queued, so a parked job is already past it.

    Reachable without anything exotic: the node drops mid-scan and the job parks; the node comes
    back; someone re-runs `athar scan --month N`, which finds no commit and anchors the root fresh;
    the next tick drains the parked job and anchors the identical root a second time. The contract
    accepts duplicate commits by design, so the caller is the only thing preventing it.
    """
    from athar.services import scan as scan_mod

    scan = a_scan()
    park_a_commit(writer, node, scan.scan_id)
    node.down = False
    # Meanwhile another run anchored the very same root, at index 4.
    monkeypatch.setattr(scan_mod, "commit_index_for", lambda *a, **k: 4)

    session = FakeSession(scan)
    assert drain_ledger_retries(session, writer) == 1

    assert scan.ledger_scan_index == 4
    assert scan.ledger_status == "already_anchored"
    assert node.sent == [], "the root was already on chain; nothing should have been sent again"


def test_a_parked_commit_not_on_chain_is_still_sent(
    writer: LedgerWriter, node: FakeNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must not swallow the job it exists to deliver."""
    from athar.services import scan as scan_mod

    scan = a_scan()
    park_a_commit(writer, node, scan.scan_id)
    node.down = False
    monkeypatch.setattr(scan_mod, "commit_index_for", lambda *a, **k: None)

    session = FakeSession(scan)
    assert drain_ledger_retries(session, writer) == 1

    assert scan.ledger_status == "anchored"
    assert len(node.sent) == 1
