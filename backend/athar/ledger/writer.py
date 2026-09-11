"""Single ledger writer per process (SPEC §12.4).

Exactly one :class:`LedgerWriter` owns the signing key and the nonce. Every commit and decision
is a job on an internal queue drained by one background thread, which

- tracks ``next_nonce`` locally and increments it after each accepted transaction;
- resynchronises from ``eth_getTransactionCount(addr, "pending")`` after ANY error and then
  retries the job once (a deterministic contract revert — ``InvalidProof`` and friends — is
  reported straight away instead);
- on an unreachable node fails the job's future *fast* with :class:`LedgerUnavailable`, parks
  the job together with everything queued behind it, and lets :meth:`LedgerWriter.retry_pending`
  re-enqueue the parked jobs once the node is back.

Idempotency lives in the caller (services lane, SPEC §12.4): :meth:`LedgerWriter.commit_scan`
takes an ``existing_index_lookup`` hook that short-circuits with ``already_anchored=True``
without sending anything. No other code path signs. In development the key is Anvil's dev
account #0 — a publicly known key that never holds value (SPEC §12.5).
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast

from web3.types import TxParams, TxReceipt

from athar.config import Settings, get_settings
from athar.ledger.client import (
    LedgerClient,
    LedgerError,
    LedgerTimeout,
    LedgerTxRejected,
    LedgerUnavailable,
)
from athar.log import get_logger

log = get_logger(__name__)

DEFAULT_RECEIPT_TIMEOUT_SECONDS = 60.0
"""How long the worker waits for a receipt. Anvil mines every second; 60 s covers a stalled node."""

MAX_ATTEMPTS = 2
"""One send plus one retry after a nonce resync (SPEC §12.4)."""

JobKind = Literal["commit", "decision"]


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommitReceipt:
    """Outcome of :meth:`LedgerWriter.commit_scan`.

    ``already_anchored`` means the caller's lookup found an existing index and nothing was sent;
    ``tx_hash`` and ``block_number`` are then ``None``.
    """

    scan_index: int
    tx_hash: str | None
    block_number: int | None
    already_anchored: bool


@dataclass(frozen=True)
class DecisionReceipt:
    """Outcome of :meth:`LedgerWriter.record_decision`."""

    tx_hash: str
    block_number: int


@dataclass(frozen=True)
class RetriedJob:
    """A parked job that :meth:`LedgerWriter.retry_pending` re-enqueued; ``tag`` is the caller's."""

    kind: JobKind
    tag: Any
    future: Future[Any]


# ---------------------------------------------------------------------------
# the subset of LedgerClient the worker uses (lets tests substitute a fake)
# ---------------------------------------------------------------------------


class TxClient(Protocol):
    """Transaction surface of :class:`athar.ledger.client.LedgerClient` used by the worker thread."""

    @property
    def writer_address(self) -> str: ...

    def pending_nonce(self) -> int: ...

    def build_commit_tx(
        self,
        nonce: int,
        snapshot_hash: bytes | str,
        findings_root: bytes | str,
        ruleset_hash: bytes | str,
        finding_count: int,
    ) -> TxParams: ...

    def build_decision_tx(
        self,
        nonce: int,
        scan_index: int,
        finding_leaf: bytes | str,
        proof: list[bytes] | list[str],
        decision: int,
        actor_hash: bytes | str,
        evidence_hash: bytes | str,
    ) -> TxParams: ...

    def sign_and_send(self, tx: TxParams) -> str: ...

    def wait_for_receipt(self, tx_hash: str, timeout: float) -> TxReceipt: ...

    def parse_scan_index(self, receipt: TxReceipt) -> int: ...


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------


@dataclass
class _Job:
    kind: JobKind
    build: Callable[[int], TxParams]  # nonce -> unsigned tx
    finish: Callable[[str, TxReceipt], Any]  # (tx_hash, receipt) -> receipt dataclass
    future: Future[Any] = field(default_factory=Future)
    tag: Any = None
    attempts: int = 0


_STOP: Any = object()


# ---------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------


class LedgerWriter:
    """Serialises every signed transaction of this process through one thread (SPEC §12.4).

    Construct one per process via :func:`get_writer`; tests may build their own around a fresh
    client. The worker thread starts lazily on the first job and is a daemon, so it never keeps
    the API process alive.
    """

    def __init__(
        self,
        client: TxClient,
        *,
        receipt_timeout: float = DEFAULT_RECEIPT_TIMEOUT_SECONDS,
    ) -> None:
        self._client = client
        self._receipt_timeout = receipt_timeout
        self._queue: queue.Queue[Any] = queue.Queue()
        self._parked: list[_Job] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._next_nonce: int | None = None  # None -> resync from the node before the next send

    # ---- lifecycle --------------------------------------------------------

    @property
    def client(self) -> TxClient:
        return self._client

    @property
    def writer_address(self) -> str:
        return self._client.writer_address

    @property
    def receipt_timeout(self) -> float:
        """Seconds the worker waits for a receipt (`LEDGER_RECEIPT_TIMEOUT_SECONDS`)."""
        return self._receipt_timeout

    @property
    def pending_count(self) -> int:
        """Jobs parked after an outage, waiting for :meth:`retry_pending`."""
        with self._lock:
            return len(self._parked)

    @property
    def queued_count(self) -> int:
        return self._queue.qsize()

    def start(self) -> None:
        """Start the worker thread (idempotent)."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="athar-ledger-writer", daemon=True)
            self._thread.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        """Ask the worker to finish the queued jobs and exit; idempotent.

        A job enqueued concurrently with `stop` is still processed (the exiting worker restarts
        itself when something slipped in behind the sentinel), so no future is ever orphaned.
        """
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                return
        self._queue.put(_STOP)
        thread.join(timeout)

    # ---- public API ---------------------------------------------------------

    def commit_scan(
        self,
        snapshot_hash: str,
        findings_root: str,
        ruleset_hash: str,
        finding_count: int,
        *,
        existing_index_lookup: Callable[[], int | None] | None = None,
        tag: Any = None,
    ) -> Future[CommitReceipt]:
        """Queue a `commitScan`. Returns immediately; the future resolves when the tx is mined.

        ``existing_index_lookup`` is the idempotency hook (SPEC §12.4): it runs synchronously in
        the caller's thread (it usually queries the caller's DB session) and, if it returns an
        index, the future is already done with ``already_anchored=True`` and nothing is sent.
        """
        if existing_index_lookup is not None:
            existing = existing_index_lookup()
            if existing is not None:
                done: Future[CommitReceipt] = Future()
                done.set_result(
                    CommitReceipt(scan_index=existing, tx_hash=None, block_number=None, already_anchored=True)
                )
                return done

        client = self._client

        def build(nonce: int) -> TxParams:
            return client.build_commit_tx(nonce, snapshot_hash, findings_root, ruleset_hash, finding_count)

        def finish(tx_hash: str, receipt: TxReceipt) -> CommitReceipt:
            return CommitReceipt(
                scan_index=client.parse_scan_index(receipt),
                tx_hash=tx_hash,
                block_number=int(receipt["blockNumber"]),
                already_anchored=False,
            )

        job = _Job(kind="commit", build=build, finish=finish, tag=tag)
        self._enqueue(job)
        return cast(Future[CommitReceipt], job.future)

    def record_decision(
        self,
        scan_index: int,
        finding_leaf: str,
        proof: list[str],
        decision: int,
        actor_hash: str,
        evidence_hash: str,
        *,
        tag: Any = None,
    ) -> Future[DecisionReceipt]:
        """Queue a `recordDecision`. The contract enforces the inclusion proof and the code range."""
        client = self._client
        proof_copy = list(proof)

        def build(nonce: int) -> TxParams:
            return client.build_decision_tx(
                nonce, scan_index, finding_leaf, proof_copy, decision, actor_hash, evidence_hash
            )

        def finish(tx_hash: str, receipt: TxReceipt) -> DecisionReceipt:
            return DecisionReceipt(tx_hash=tx_hash, block_number=int(receipt["blockNumber"]))

        job = _Job(kind="decision", build=build, finish=finish, tag=tag)
        self._enqueue(job)
        return cast(Future[DecisionReceipt], job.future)

    def retry_pending(self, settled: Callable[[JobKind, Any], int | None] | None = None) -> list[RetriedJob]:
        """Re-enqueue every job parked by an outage, each with a fresh future (SPEC §12.4 retry).

        ``settled`` is the idempotency hook for the retry path, and it is not optional in spirit:
        ``commit_scan``'s own ``existing_index_lookup`` runs once, before the job is queued, so a
        parked job is already past it — and `GovernanceLedger.commitScan` accepts duplicate commits
        by design ("Idempotency is the caller's job"). Between the outage and the retry, the same
        root can perfectly well reach the chain another way: the node comes back, someone re-runs
        the scan, it finds no commit and anchors afresh. Without this hook the drained job would
        then put a second copy of that root on the chain.

        It is called here, in the caller's thread, *before* anything is re-enqueued — the only
        point at which the send can still be stopped. Returning an index resolves the job's future
        as ``already_anchored`` at that index and sends nothing; returning None re-enqueues it.
        The job is returned either way, so the caller records the row the same for both.
        """
        with self._lock:
            parked, self._parked = self._parked, []
        retried: list[RetriedJob] = []
        skipped = 0
        for job in parked:
            index = None
            if settled is not None:
                try:
                    index = settled(job.kind, job.tag)
                except Exception as exc:  # a failed check must not lose the job
                    log.warning(
                        "parked job idempotency check failed; retrying it",
                        extra={"kind": job.kind, "exc_type": type(exc).__name__},
                    )
                    index = None
            job.future = Future()
            job.attempts = 0
            if index is not None and job.kind == "commit":
                job.future.set_result(
                    CommitReceipt(scan_index=index, tx_hash=None, block_number=None, already_anchored=True)
                )
                skipped += 1
            else:
                self._enqueue(job)
            retried.append(RetriedJob(kind=job.kind, tag=job.tag, future=job.future))
        if retried:
            log.info(
                "ledger writer retrying parked jobs",
                extra={"count": len(retried), "already_anchored": skipped},
            )
        return retried

    # ---- worker -----------------------------------------------------------

    def _enqueue(self, job: _Job) -> None:
        self._queue.put(job)  # put first: a worker exiting on the sentinel checks the queue after us
        self.start()

    def _loop(self) -> None:
        while True:
            job = self._queue.get()
            if job is _STOP:
                with self._lock:
                    self._thread = None
                if not self._queue.empty():  # a job arrived behind the sentinel; hand it to a fresh worker
                    self.start()
                return
            self._execute(job)

    def _nonce(self) -> int:
        if self._next_nonce is None:
            self._next_nonce = self._client.pending_nonce()
        return self._next_nonce

    def _send(self, job: _Job) -> Any:
        nonce = self._nonce()
        tx = job.build(nonce)
        tx_hash = self._client.sign_and_send(tx)
        self._next_nonce = nonce + 1
        receipt = self._client.wait_for_receipt(tx_hash, self._receipt_timeout)
        return job.finish(tx_hash, receipt)

    def _execute(self, job: _Job) -> None:
        last: LedgerError | None = None
        while job.attempts < MAX_ATTEMPTS:
            job.attempts += 1
            try:
                result = self._send(job)
            except LedgerUnavailable as exc:
                self._next_nonce = None
                self._park(job, exc)
                self._park_queued(exc)
                return
            except LedgerError as exc:
                self._next_nonce = None  # resync from "pending" before any retry
                last = exc
                # Not retried: a contract revert is deterministic, and a receipt timeout means the
                # transaction is still in the pool — re-sending its nonce would only be rejected.
                # The caller gets `LedgerTimeout.tx_hash` and can check the receipt later.
                permanent = (isinstance(exc, LedgerTxRejected) and exc.error_name is not None) or isinstance(
                    exc, LedgerTimeout
                )
                log.warning(
                    "ledger transaction failed",
                    extra={
                        "kind": job.kind,
                        "attempt": job.attempts,
                        "error": str(exc),
                        "retry": not permanent,
                    },
                )
                if permanent:
                    break
                continue
            job.future.set_result(result)
            return
        job.future.set_exception(last or LedgerError("ledger job failed"))

    def _park(self, job: _Job, exc: LedgerUnavailable) -> None:
        with self._lock:
            self._parked.append(job)
        job.future.set_exception(exc)
        log.warning("ledger node unreachable; job parked", extra={"kind": job.kind, "attempt": job.attempts})

    def _park_queued(self, exc: LedgerUnavailable) -> None:
        """Fail everything already queued so callers do not each wait out a timeout."""
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                return
            if job is _STOP:
                self._queue.put(_STOP)
                return
            self._park(job, exc)


# ---------------------------------------------------------------------------
# process singleton
# ---------------------------------------------------------------------------

_writer: LedgerWriter | None = None
_writer_lock = threading.Lock()


def get_writer(settings: Settings | None = None) -> LedgerWriter:
    """The one writer of this process (SPEC §12.4). Built on first use from `settings`.

    The client is created with `LEDGER_CONTRACT_ADDRESS` if set (a malformed value is ignored);
    `ensure_deployed` on the API start-up path fixes the address on ``get_writer().client``
    before the first commit. The receipt timeout comes from `LEDGER_RECEIPT_TIMEOUT_SECONDS`.
    """
    global _writer
    with _writer_lock:
        if _writer is None:
            cfg = settings or get_settings()
            client = LedgerClient(cfg.ledger_rpc_url, cfg.ledger_private_key, cfg.ledger_contract_address)
            _writer = LedgerWriter(client, receipt_timeout=float(cfg.ledger_receipt_timeout_seconds))
        return _writer


def reset_writer() -> None:
    """Stop and forget the singleton (tests, process shutdown)."""
    global _writer
    with _writer_lock:
        writer, _writer = _writer, None
    if writer is not None:
        writer.stop()
