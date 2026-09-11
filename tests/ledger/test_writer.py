"""Writer discipline (SPEC §12.4): one thread, local nonce, resync after any error, fail fast when down."""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from athar.config import get_settings
from athar.hashing import finding_instance, instance_hash
from athar.ledger import merkle, verify
from athar.ledger.client import (
    LedgerClient,
    LedgerError,
    LedgerTimeout,
    LedgerTxRejected,
    LedgerUnavailable,
)
from athar.ledger.writer import (
    DEFAULT_RECEIPT_TIMEOUT_SECONDS,
    CommitReceipt,
    DecisionReceipt,
    LedgerWriter,
    get_writer,
    reset_writer,
)
from web3 import Web3

from ._anvil import fresh_client, process_key

H = "0x" + "ab" * 32
LEAF = "0x" + "cd" * 32


class FakeClient:
    """Deterministic stand-in for LedgerClient: a node with a pending nonce and a mined-tx log."""

    writer_address = "0x000000000000000000000000000000000000dEaD"

    def __init__(self) -> None:
        self.pending = 0  # the node's view of the next nonce
        self.sent: list[dict[str, Any]] = []
        self.send_calls = 0
        self.resyncs = 0
        self.unavailable = False
        self.fail_next_sends: list[Exception] = []
        self.fail_next_receipts: list[Exception] = []

    def _check(self) -> None:
        if self.unavailable:
            raise LedgerUnavailable()

    def pending_nonce(self) -> int:
        self._check()
        self.resyncs += 1
        return self.pending

    def build_commit_tx(self, nonce: int, s: str, r: str, rs: str, count: int) -> Any:
        self._check()
        return {"nonce": nonce, "kind": "commit", "count": count}

    def build_decision_tx(
        self, nonce: int, idx: int, leaf: str, proof: list[str], d: int, a: str, e: str
    ) -> Any:
        self._check()
        return {"nonce": nonce, "kind": "decision", "scan_index": idx, "decision": d}

    def sign_and_send(self, tx: Any) -> str:
        self._check()
        self.send_calls += 1
        if self.fail_next_sends:
            raise self.fail_next_sends.pop(0)
        if tx["nonce"] != self.pending:
            raise LedgerTxRejected(f"nonce too low: expected {self.pending}, got {tx['nonce']}")
        self.pending += 1
        self.sent.append(tx)
        return f"0x{len(self.sent):064x}"

    def wait_for_receipt(self, tx_hash: str, timeout: float) -> Any:
        self._check()
        if self.fail_next_receipts:
            raise self.fail_next_receipts.pop(0)
        return {"blockNumber": 100 + len(self.sent), "status": 1, "transactionHash": tx_hash}

    def parse_scan_index(self, receipt: Any) -> int:
        return len([t for t in self.sent if t["kind"] == "commit"]) - 1


@pytest.fixture
def fake() -> FakeClient:
    return FakeClient()


@pytest.fixture
def writer(fake: FakeClient) -> Iterator[LedgerWriter]:
    w = LedgerWriter(fake, receipt_timeout=1.0)
    yield w
    w.stop()


# ---------------------------------------------------------------- unit


def test_commit_scan_sends_and_parses_scan_index(writer: LedgerWriter, fake: FakeClient) -> None:
    receipt = writer.commit_scan(H, H, H, 3).result(timeout=5)
    assert receipt == CommitReceipt(
        scan_index=0, tx_hash="0x" + "0" * 63 + "1", block_number=101, already_anchored=False
    )
    assert fake.sent[0]["nonce"] == 0 and fake.sent[0]["count"] == 3


def test_already_anchored_hook_short_circuits_without_sending(writer: LedgerWriter, fake: FakeClient) -> None:
    fut = writer.commit_scan(H, H, H, 3, existing_index_lookup=lambda: 7)
    assert fut.done()
    assert fut.result() == CommitReceipt(scan_index=7, tx_hash=None, block_number=None, already_anchored=True)
    assert fake.send_calls == 0
    # a lookup that finds nothing falls through to a real send
    assert (
        writer.commit_scan(H, H, H, 1, existing_index_lookup=lambda: None).result(timeout=5).already_anchored
        is False
    )
    assert fake.send_calls == 1


def test_nonce_increments_locally_without_resyncing_each_time(writer: LedgerWriter, fake: FakeClient) -> None:
    futures = [writer.commit_scan(H, H, H, i) for i in range(5)]
    assert [f.result(timeout=5).scan_index for f in futures] == [0, 1, 2, 3, 4]
    assert [t["nonce"] for t in fake.sent] == [0, 1, 2, 3, 4]
    assert fake.resyncs == 1  # once at start, then tracked locally


def test_nonce_resynchronises_after_an_error_and_retries_once(writer: LedgerWriter, fake: FakeClient) -> None:
    writer.commit_scan(H, H, H, 1).result(timeout=5)
    fake.pending += 1  # something else spent a nonce from the same key
    receipt = writer.commit_scan(H, H, H, 2).result(timeout=5)
    assert receipt.scan_index == 1
    assert [t["nonce"] for t in fake.sent] == [0, 2]
    assert fake.resyncs == 2 and fake.send_calls == 3  # first send rejected, one resync, one retry


def test_second_failure_surfaces_to_the_caller(writer: LedgerWriter, fake: FakeClient) -> None:
    fake.fail_next_sends = [LedgerTxRejected("gas too low"), LedgerTxRejected("gas too low again")]
    fut = writer.commit_scan(H, H, H, 1)
    with pytest.raises(LedgerTxRejected, match="again"):
        fut.result(timeout=5)
    assert fake.send_calls == 2
    assert writer.commit_scan(H, H, H, 1).result(timeout=5).scan_index == 0  # writer keeps working


def test_deterministic_contract_revert_is_not_retried(writer: LedgerWriter, fake: FakeClient) -> None:
    fake.fail_next_sends = [LedgerTxRejected("InvalidProof", error_name="InvalidProof")]
    fut = writer.record_decision(0, LEAF, [], 1, H, H)
    with pytest.raises(LedgerTxRejected) as info:
        fut.result(timeout=5)
    assert info.value.error_name == "InvalidProof"
    assert fake.send_calls == 1


def test_receipt_timeout_is_not_retried_but_nonce_resyncs_for_the_next_job(
    writer: LedgerWriter, fake: FakeClient
) -> None:
    """A timed-out tx is still in the pool: re-sending its nonce would only be rejected."""
    fake.fail_next_receipts = [LedgerTimeout("0x" + "0" * 63 + "1", 1.0)]
    fut = writer.commit_scan(H, H, H, 1)
    with pytest.raises(LedgerTimeout) as info:
        fut.result(timeout=5)
    assert info.value.tx_hash == "0x" + "0" * 63 + "1"
    assert fake.send_calls == 1  # no second send for the same job
    assert writer.commit_scan(H, H, H, 2).result(timeout=5).scan_index == 1
    assert [t["nonce"] for t in fake.sent] == [0, 1]
    assert fake.resyncs == 2  # start + resync after the timeout


def test_record_decision_returns_receipt(writer: LedgerWriter, fake: FakeClient) -> None:
    receipt = writer.record_decision(4, LEAF, [H], 2, H, H).result(timeout=5)
    assert isinstance(receipt, DecisionReceipt)
    assert receipt.block_number == 101 and receipt.tx_hash.startswith("0x")
    assert fake.sent[0] == {"nonce": 0, "kind": "decision", "scan_index": 4, "decision": 2}


def test_unreachable_node_fails_fast_parks_jobs_and_retry_pending_drains(
    writer: LedgerWriter, fake: FakeClient
) -> None:
    fake.unavailable = True
    started = time.monotonic()
    futures = [writer.commit_scan(H, H, H, i, tag=f"scan-{i}") for i in range(3)]
    for fut in futures:
        with pytest.raises(LedgerUnavailable):
            fut.result(timeout=5)
    assert time.monotonic() - started < 2.0
    assert writer.pending_count == 3 and fake.send_calls == 0

    fake.unavailable = False
    retried = writer.retry_pending()
    assert [r.tag for r in retried] == ["scan-0", "scan-1", "scan-2"]
    assert [r.future.result(timeout=5).scan_index for r in retried] == [0, 1, 2]
    assert writer.pending_count == 0 and writer.retry_pending() == []


def test_stop_and_restart_are_idempotent(writer: LedgerWriter, fake: FakeClient) -> None:
    writer.stop()
    writer.stop()
    assert writer.commit_scan(H, H, H, 1).result(timeout=5).scan_index == 0  # restarts lazily
    writer.start()
    writer.start()


def test_get_writer_is_a_process_singleton() -> None:
    reset_writer()
    try:
        settings = get_settings().model_copy(
            update={"ledger_rpc_url": "http://127.0.0.1:9", "ledger_contract_address": ""}
        )
        a = get_writer(settings)
        assert get_writer(settings) is a and get_writer() is a
        assert isinstance(a.client, LedgerClient)
        assert a.writer_address == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        assert a.client.contract_address is None
        assert a.receipt_timeout == DEFAULT_RECEIPT_TIMEOUT_SECONDS
        reset_writer()
        assert get_writer(settings) is not a
    finally:
        reset_writer()


def test_get_writer_tolerates_malformed_contract_address_and_reads_receipt_timeout() -> None:
    reset_writer()
    try:
        settings = get_settings().model_copy(
            update={
                "ledger_rpc_url": "http://127.0.0.1:9",
                "ledger_contract_address": "# empty = deploy on first API start",
                "ledger_receipt_timeout_seconds": 7,  # forward-compat: read via getattr until config declares it
            }
        )
        w = get_writer(settings)
        assert isinstance(w.client, LedgerClient) and w.client.contract_address is None
        assert w.receipt_timeout == 7.0
    finally:
        reset_writer()


# ---------------------------------------------------------------- integration (Anvil)


@pytest.fixture
def chain(rpc_url: str) -> Iterator[tuple[LedgerClient, LedgerWriter]]:
    client = fresh_client(rpc_url)
    w = LedgerWriter(client, receipt_timeout=30.0)
    yield client, w
    w.stop()


@pytest.mark.integration
def test_25_concurrent_commits_all_mine_without_nonce_errors(
    chain: tuple[LedgerClient, LedgerWriter],
) -> None:
    client, w = chain
    with ThreadPoolExecutor(max_workers=8) as pool:
        submitted = list(pool.map(lambda i: w.commit_scan(H, "0x" + f"{i:064x}", H, i), range(25)))
    receipts = [f.result(timeout=120) for f in submitted]
    assert sorted(r.scan_index for r in receipts) == list(range(25))
    assert len({r.tx_hash for r in receipts}) == 25
    assert all(not r.already_anchored and r.block_number is not None for r in receipts)
    assert client.commit_count() == 25
    for i in (0, 12, 24):  # pool.map keeps submission order, so receipts[i] is job i
        assert client.get_commit(receipts[i].scan_index).findings_root == "0x" + f"{i:064x}"


@pytest.mark.integration
def test_decision_roundtrip_and_bad_proof_rejected(chain: tuple[LedgerClient, LedgerWriter]) -> None:
    client, w = chain
    hashes = [
        instance_hash(
            finding_instance(
                finding_key=f"{i:032x}",
                identity_id=f"e{i}",
                rule_id="R1",
                severity="High",
                score=70,
                snapshot_month=2,
                first_seen_month=1,
                evidence_refs=["grant:g"],
                causal_event_ids=[],
            )
        )
        for i in range(5)
    ]
    root = verify.compute_root(hashes)
    idx = w.commit_scan(H, root, H, 5).result(timeout=60).scan_index
    leaf_hex, proof_hex = verify.leaf_proofs(hashes)[hashes[2]]
    receipt = w.record_decision(
        idx,
        leaf_hex,
        proof_hex,
        verify.DECISION_CODES["approved"],
        verify.actor_hash("approver-1"),
        verify.evidence_hash("p", "revoke_grant", None, None, "r"),
    ).result(timeout=60)
    assert receipt.tx_hash.startswith("0x") and receipt.block_number > 0
    assert client.verify_finding(idx, leaf_hex, proof_hex) is True

    bad = w.record_decision(idx, leaf_hex, proof_hex[:-1] if proof_hex else [H], 1, H, H)
    with pytest.raises(LedgerTxRejected) as info:
        bad.result(timeout=60)
    assert info.value.error_name == "InvalidProof"
    with pytest.raises(LedgerTxRejected) as info2:
        w.record_decision(idx, leaf_hex, proof_hex, 9, H, H).result(timeout=60)
    assert info2.value.error_name == "InvalidDecision"
    with pytest.raises(LedgerError):
        w.record_decision(idx + 1, leaf_hex, proof_hex, 1, H, H).result(timeout=60)
    assert w.commit_scan(H, root, H, 5).result(timeout=60).scan_index == idx + 1  # still healthy


@pytest.mark.integration
def test_writer_recovers_when_the_nonce_was_spent_outside_it(
    chain: tuple[LedgerClient, LedgerWriter], rpc_url: str
) -> None:
    client, w = chain
    assert w.commit_scan(H, H, H, 1).result(timeout=60).scan_index == 0
    # TEST ONLY: burn a nonce from the same key behind the writer's back (runtime code never signs elsewhere).
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    acct = w3.eth.account.from_key(process_key(rpc_url))
    tx = {
        "to": acct.address,
        "value": 0,
        "gas": 21000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
    }
    w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), timeout=60
    )
    assert w.commit_scan(H, H, H, 2).result(timeout=60).scan_index == 1
    assert client.commit_count() == 2


@pytest.mark.integration
def test_python_verify_agrees_with_contract_for_20_random_trees(
    chain: tuple[LedgerClient, LedgerWriter],
) -> None:
    import random

    client, w = chain
    rng = random.Random(20250910)
    trees = [
        [merkle.leaf_from_bytes(rng.randbytes(40)) for _ in range(rng.randint(1, 33))] for _ in range(20)
    ]
    futures = [w.commit_scan(H, merkle.to_hex(merkle.root(t)), H, len(t)) for t in trees]
    for leaves, fut in zip(trees, futures, strict=True):
        idx = fut.result(timeout=120).scan_index
        r = merkle.root(leaves)
        for leaf in rng.sample(leaves, min(3, len(leaves))):
            p = merkle.proof(leaves, leaf)
            assert merkle.verify(r, leaf, p) is True
            assert client.verify_finding(idx, leaf, p) is True
            tampered = bytes([leaf[0] ^ 0xFF]) + leaf[1:]
            assert merkle.verify(r, tampered, p) is client.verify_finding(idx, tampered, p) is False
            if p:
                assert merkle.verify(r, leaf, p[:-1]) is client.verify_finding(idx, leaf, p[:-1]) is False
    assert client.verify_finding(len(trees), trees[0][0], []) is False  # unknown scan -> false, no revert
