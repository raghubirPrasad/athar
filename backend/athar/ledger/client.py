"""web3 client for `GovernanceLedger` (SPEC §12.2, §12.5, §12.6).

Read-only calls (`commit_count`, `get_commit`, `verify_finding`, `has_code`) are safe from any
thread. The transaction helpers (`build_*_tx`, `sign_and_send`, `wait_for_receipt`) exist for
`ledger/writer.py`, which is the only code path allowed to sign at runtime (SPEC §12.4). The
single bootstrap exception is `deploy()`, run by `ensure_deployed` on API start-up before the
writer thread has sent anything; the writer then resynchronises its nonce from the node.

Every transport failure surfaces as :class:`LedgerUnavailable` whose message never contains
the RPC URL (it may hold credentials in a hosted deployment).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_checksum_address
from web3 import HTTPProvider, Web3
from web3.exceptions import (
    CannotHandleRequest,
    ContractCustomError,
    ContractLogicError,
    ProviderConnectionError,
    RequestTimedOut,
    TimeExhausted,
    Web3RPCError,
)
from web3.logs import DISCARD
from web3.types import Nonce, TxParams, TxReceipt, Wei

from athar.config import Settings, get_settings
from athar.db.models import LedgerMeta
from athar.log import get_logger

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from web3.contract import Contract

log = get_logger(__name__)

ARTIFACT_PATH = Path(__file__).parent / "artifacts" / "GovernanceLedger.json"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEPLOY_RECEIPT_TIMEOUT_SECONDS = 120.0

# Transport-level failures: the node is down, unreachable or not answering in time.
_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
    OSError,  # includes requests.exceptions.RequestException
    ProviderConnectionError,
    RequestTimedOut,
    CannotHandleRequest,
)


# ---------------------------------------------------------------------------
# errors and value objects
# ---------------------------------------------------------------------------


class LedgerError(Exception):
    """Base class for every ledger failure."""


class LedgerUnavailable(LedgerError):  # noqa: N818 — name fixed by SPEC §12.4
    """The node cannot be reached. The message deliberately omits the RPC URL."""

    def __init__(self, detail: str = "ledger node unreachable") -> None:
        super().__init__(detail)


class LedgerNotDeployed(LedgerError):  # noqa: N818 — family named after LedgerUnavailable
    """No contract address is known; call `ensure_deployed` first."""


class LedgerTxRejected(LedgerError):  # noqa: N818 — family named after LedgerUnavailable
    """The node refused the transaction at submission (nonce, gas, or a revert during estimation).

    `error_name` is set when the rejection is a contract custom error (`InvalidProof`, ...): such a
    rejection is deterministic and the writer does not retry it.
    """

    def __init__(self, detail: str, *, error_name: str | None = None) -> None:
        super().__init__(detail)
        self.error_name = error_name


class LedgerTxReverted(LedgerError):  # noqa: N818 — family named after LedgerUnavailable
    """The transaction was mined with status 0."""


class LedgerTimeout(LedgerError):  # noqa: N818 — family named after LedgerUnavailable
    """The receipt did not arrive in time; the transaction may still be mined later."""

    def __init__(self, tx_hash: str, timeout: float) -> None:
        super().__init__(f"no receipt for {tx_hash} within {timeout:.0f}s")
        self.tx_hash = tx_hash


class UnknownScanIndex(LedgerError):  # noqa: N818 — family named after LedgerUnavailable
    """`getCommit` reverted with `UnknownScan()`."""


@dataclass(frozen=True)
class DeployResult:
    address: str
    block_number: int
    tx_hash: str


@dataclass(frozen=True)
class ScanCommit:
    """Mirror of the Solidity `ScanCommit` struct; hashes as 0x-hex."""

    snapshot_hash: str
    findings_root: str
    ruleset_hash: str
    finding_count: int
    timestamp: int
    submitter: str


# ---------------------------------------------------------------------------
# artifact
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_artifact() -> dict[str, Any]:
    """ABI + bytecode written by `scripts/sync_contract_artifact.py` (`make contracts-build`)."""
    return cast(dict[str, Any], json.loads(ARTIFACT_PATH.read_text()))


def _error_selectors(abi: list[dict[str, Any]]) -> dict[str, str]:
    """4-byte selector (0x-hex) -> error name, for every custom error in the ABI."""
    out: dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "error":
            continue
        types = ",".join(inp["type"] for inp in entry.get("inputs", []))
        sig = f"{entry['name']}({types})"
        out["0x" + keccak(text=sig)[:4].hex()] = entry["name"]
    return out


def _hex(value: bytes | str) -> str:
    return value if isinstance(value, str) else "0x" + value.hex()


def _b32(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        b = value
    else:
        text = value[2:] if value.startswith(("0x", "0X")) else value
        b = bytes.fromhex(text)
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b


def checksum_or_none(value: str | None) -> ChecksumAddress | None:
    """Checksummed address, or ``None`` for an empty or malformed value.

    A malformed `LEDGER_CONTRACT_ADDRESS` (a stray comment, a truncated hex string) must never
    kill the process (CLAUDE.md non-negotiable 3); it is logged and treated as "not configured",
    which makes `ensure_deployed` fall back to `ledger_meta` or deploy.
    """
    if not value or not value.strip():
        return None
    try:
        return to_checksum_address(value.strip())
    except ValueError:
        log.warning("ignoring malformed ledger contract address", extra={"value": value[:48]})
        return None


# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------


class LedgerClient:
    """Thin, typed wrapper over web3 for one contract and one signing key.

    `private_key` defaults (via settings) to Anvil dev account #0 — a publicly known key that
    never holds value. Production would use an HSM-backed key (SPEC §12.1, §12.5).
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        contract_address: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        provider = HTTPProvider(
            rpc_url,
            request_kwargs={"timeout": timeout},
            exception_retry_configuration=None,  # fail fast; the writer owns retries
        )
        self._w3 = Web3(provider)
        self._account: LocalAccount = Account.from_key(private_key)
        self._contract_address: ChecksumAddress | None = checksum_or_none(contract_address)
        self._chain_id: int | None = None
        artifact = load_artifact()
        self._abi: list[dict[str, Any]] = artifact["abi"]
        self._bytecode: str = artifact["bytecode"]
        self._errors = _error_selectors(self._abi)

    # ---- identity ---------------------------------------------------------

    @property
    def writer_address(self) -> str:
        return str(self._account.address)

    @property
    def contract_address(self) -> str | None:
        return str(self._contract_address) if self._contract_address else None

    @contract_address.setter
    def contract_address(self, value: str | None) -> None:
        self._contract_address = checksum_or_none(value)

    @property
    def chain_id(self) -> int:
        if self._chain_id is None:
            with self._guard():
                cid = int(self._w3.eth.chain_id)
            self._chain_id = cid
        return self._chain_id

    def is_reachable(self) -> bool:
        try:
            _ = self.chain_id
        except LedgerUnavailable:
            return False
        return True

    # ---- error translation ------------------------------------------------

    class _guard:  # noqa: N801 — used as a context manager, reads like a keyword
        """Translate transport errors into `LedgerUnavailable` (no URL in the message)."""

        def __enter__(self) -> None:
            return None

        def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: Any) -> None:
            if exc is not None and isinstance(exc, _TRANSPORT_ERRORS):
                raise LedgerUnavailable() from None

    def _revert_info(self, exc: ContractLogicError) -> tuple[str, str | None]:
        """(human message, custom error name or None) for a revert surfaced by web3."""
        if isinstance(exc, ContractCustomError):
            data = str(exc.data or "")
            name = self._errors.get(data[:10])
            if name:
                return name, name
        return str(exc.message or exc), None

    # ---- contract handles -------------------------------------------------

    def _contract(self) -> Contract:
        if self._contract_address is None:
            raise LedgerNotDeployed("no contract address; run ensure_deployed first")
        return self._w3.eth.contract(address=self._contract_address, abi=self._abi)

    def has_code(self, address: str | None) -> bool:
        if not address:
            return False
        try:
            checksum = to_checksum_address(address)
        except ValueError:
            return False
        with self._guard():
            return len(self._w3.eth.get_code(checksum)) > 0

    # ---- read-only --------------------------------------------------------

    def commit_count(self) -> int:
        with self._guard():
            return int(self._contract().functions.commitCount().call())

    def get_commit(self, scan_index: int) -> ScanCommit:
        with self._guard():
            try:
                raw = self._contract().functions.getCommit(scan_index).call()
            except ContractLogicError as exc:
                raise UnknownScanIndex(self._revert_info(exc)[0]) from None
        snapshot_hash, findings_root, ruleset_hash, count, ts, submitter = raw
        return ScanCommit(
            snapshot_hash=_hex(bytes(snapshot_hash)),
            findings_root=_hex(bytes(findings_root)),
            ruleset_hash=_hex(bytes(ruleset_hash)),
            finding_count=int(count),
            timestamp=int(ts),
            submitter=str(submitter),
        )

    def verify_finding(self, scan_index: int, leaf: bytes | str, proof: list[bytes] | list[str]) -> bool:
        nodes = [_b32(p) for p in proof]
        with self._guard():
            return bool(self._contract().functions.verifyFinding(scan_index, _b32(leaf), nodes).call())

    # ---- transaction helpers (writer only) -------------------------------

    def pending_nonce(self) -> int:
        with self._guard():
            return int(self._w3.eth.get_transaction_count(self._account.address, "pending"))

    def _base_tx(self, nonce: int) -> TxParams:
        with self._guard():
            gas_price = self._w3.eth.gas_price
        return {
            "from": self._account.address,
            "nonce": Nonce(nonce),
            "chainId": self.chain_id,
            "gasPrice": Wei(gas_price),
        }

    def build_commit_tx(
        self,
        nonce: int,
        snapshot_hash: bytes | str,
        findings_root: bytes | str,
        ruleset_hash: bytes | str,
        finding_count: int,
    ) -> TxParams:
        fn = self._contract().functions.commitScan(
            _b32(snapshot_hash), _b32(findings_root), _b32(ruleset_hash), int(finding_count)
        )
        return self._build(fn, nonce)

    def build_decision_tx(
        self,
        nonce: int,
        scan_index: int,
        finding_leaf: bytes | str,
        proof: list[bytes] | list[str],
        decision: int,
        actor_hash: bytes | str,
        evidence_hash: bytes | str,
    ) -> TxParams:
        fn = self._contract().functions.recordDecision(
            int(scan_index),
            _b32(finding_leaf),
            [_b32(p) for p in proof],
            int(decision),
            _b32(actor_hash),
            _b32(evidence_hash),
        )
        return self._build(fn, nonce)

    def _build(self, fn: Any, nonce: int) -> TxParams:
        base = self._base_tx(nonce)
        with self._guard():
            try:
                return cast(TxParams, fn.build_transaction(base))
            except ContractLogicError as exc:
                message, name = self._revert_info(exc)
                raise LedgerTxRejected(message, error_name=name) from None

    def sign_and_send(self, tx: TxParams) -> str:
        """Sign with the writer key and broadcast. Only `LedgerWriter`'s thread may call this."""
        signed = self._account.sign_transaction(cast(dict[str, Any], tx))
        with self._guard():
            try:
                tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
            except Web3RPCError as exc:
                raise LedgerTxRejected(str(exc.message)) from None
        return "0x" + bytes(tx_hash).hex()

    def wait_for_receipt(self, tx_hash: str, timeout: float) -> TxReceipt:
        with self._guard():
            try:
                receipt = self._w3.eth.wait_for_transaction_receipt(
                    cast(Any, tx_hash), timeout=timeout, poll_latency=0.2
                )
            except TimeExhausted:
                raise LedgerTimeout(tx_hash, timeout) from None
        if int(receipt["status"]) != 1:
            raise LedgerTxReverted(f"transaction {tx_hash} reverted")
        return receipt

    def parse_scan_index(self, receipt: TxReceipt) -> int:
        """`scanIndex` from the `ScanCommitted` log of a commit receipt."""
        events = list(self._contract().events.ScanCommitted().process_receipt(receipt, errors=DISCARD))
        if not events:
            raise LedgerError("ScanCommitted event not found in receipt")
        return int(events[0]["args"]["scanIndex"])

    # ---- deployment -------------------------------------------------------

    def deploy(self) -> DeployResult:
        """Deploy from the committed artifact; the writer becomes admin, scanner and decider.

        Bootstrap only — call before the writer thread has sent anything (see module docstring).
        """
        factory = self._w3.eth.contract(abi=self._abi, bytecode=self._bytecode)
        base = self._base_tx(self.pending_nonce())
        with self._guard():
            tx = factory.constructor(self._account.address).build_transaction(base)
        tx_hash = self.sign_and_send(tx)
        receipt = self.wait_for_receipt(tx_hash, timeout=DEPLOY_RECEIPT_TIMEOUT_SECONDS)
        address = receipt.get("contractAddress")
        if not address:
            raise LedgerError("deployment receipt carries no contract address")
        self._contract_address = to_checksum_address(address)
        log.info(
            "ledger contract deployed",
            extra={"address": self.contract_address, "block": int(receipt["blockNumber"])},
        )
        return DeployResult(
            address=str(self._contract_address), block_number=int(receipt["blockNumber"]), tx_hash=tx_hash
        )


# ---------------------------------------------------------------------------
# start-up
# ---------------------------------------------------------------------------


def ensure_deployed(client: LedgerClient, session: Session, settings: Settings | None = None) -> LedgerMeta:
    """Resolve the contract address once per install (SPEC §12.5) and persist it in `ledger_meta`.

    Order: `LEDGER_CONTRACT_ADDRESS` if it has code, else the `ledger_meta` row if its address has
    code, else deploy. The row is upserted (id=1) in every branch so a second run reuses it and
    never redeploys. Commits the session: the address must survive whatever the caller does next.

    Raises :class:`LedgerUnavailable` when the node cannot be reached; the API start-up path must
    catch it and carry on with ``ledger_status = unanchored`` (SPEC §12.4 — the ledger never blocks
    the core pipeline).
    """
    cfg = settings or get_settings()
    meta = session.get(LedgerMeta, 1)

    configured = checksum_or_none(cfg.ledger_contract_address)
    if configured and client.has_code(configured):
        address = configured
        same_row = meta is not None and meta.contract_address.lower() == address.lower()
        block = meta.deployed_block if meta is not None and same_row else 0
        source = "config"
    elif meta and client.has_code(meta.contract_address):
        address, block = to_checksum_address(meta.contract_address), meta.deployed_block
        source = "ledger_meta"
    else:
        result = client.deploy()
        address, block = to_checksum_address(result.address), result.block_number
        source = "deployed"

    client.contract_address = address
    row = LedgerMeta(
        id=1,
        contract_address=str(address),
        chain_id=client.chain_id,
        deployed_block=int(block),
        writer_address=client.writer_address,
    )
    row = session.merge(row)
    session.commit()
    session.refresh(row)  # readable after the session closes even with expire_on_commit=True
    log.info("ledger contract resolved", extra={"address": str(address), "source": source})
    return row
