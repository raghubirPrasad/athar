"""Ledger verification and decision hashing (SPEC §12.6, §12.2). Pure given its inputs.

`verify_scan` rebuilds the findings root from the DB's instance hashes and compares it with the
commit read back from the chain; `verify_rows` re-derives every row's `instance_hash` from the
exported instance JSON and checks its inclusion proof against a root — what
``athar verify --csv`` does on the ``findings.json`` sidecar so a judge can verify a report
without trusting the dashboard.

Purpose and limits (SPEC §12.1) live here as constants so the UI and THREAT_MODEL quote one text.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from athar.hashing import canonical_json, instance_hash, keccak256_hex, sha256_hex
from athar.ledger import merkle
from athar.ledger.client import ScanCommit, UnknownScanIndex

# ---------------------------------------------------------------------------
# purpose and limits (SPEC §12.1) — quote, do not paraphrase
# ---------------------------------------------------------------------------

LEDGER_PURPOSE = (
    "Anchors each scan's findings root and each remediation decision so that post-hoc alteration "
    "of findings or decisions in the scanner's own database is detectable, disputes about when a "
    "finding existed or who approved a revocation can be settled, and a report cannot be edited "
    "before it reaches the board without the root failing to verify."
)

LEDGER_LIMITS = (
    "Does not defend against a compromised API host holding the writer key: whoever controls the "
    "key can anchor whatever that host produces. Production path: HSM-backed key, per-approver "
    "wallets and a permissioned chain. No IAM data is ever stored on-chain — only hashes, counts "
    "and timestamps."
)

ON_CHAIN: tuple[str, ...] = (
    "snapshotHash — keccak256 over the sorted file hashes of the month's manifest",
    "findingsRoot — Merkle root of the double-hashed finding instance hashes",
    "rulesetHash — keccak256 of the rule ids, versions and thresholds",
    "findingCount, block timestamp, submitter address",
    "per decision: scanIndex, finding leaf, decision code, keccak256(user_id), evidence hash",
)

NOT_ON_CHAIN: tuple[str, ...] = (
    "identities, principals, grants, credentials, activity, resources or any provider export",
    "finding narratives, severities, scores or status",
    "user ids, names or e-mail addresses (only keccak256(user_id))",
    "remediation plans, rationales or model output (only a hash of a hash)",
)

# ---------------------------------------------------------------------------
# decision codes (SPEC §12.2)
# ---------------------------------------------------------------------------

DECISION_CODES: dict[str, int] = {
    "approved": 1,
    "rejected": 2,
    "auto_remediated": 3,
    "remediation_applied": 4,
    "exception_granted": 5,
}
DECISION_NAMES: dict[int, str] = {code: name for name, code in DECISION_CODES.items()}


def actor_hash(user_id: str) -> str:
    """``keccak256(user_id)`` as 0x-hex — the only trace of the approver that goes on-chain."""
    return keccak256_hex(user_id.encode())


def evidence_hash(
    plan_id: str, action: str, model_id: str | None, prompt_version: str | None, rationale: str
) -> str:
    """``keccak256(canonical_json({plan_id, action, model_id, prompt_version, rationale_hash}))``.

    ``rationale_hash = sha256(rationale)`` so free text (possibly model-written) never reaches the
    chain, only a commitment to it. ``model_id`` / ``prompt_version`` are ``null`` for rule-proposed
    plans.
    """
    payload = {
        "plan_id": plan_id,
        "action": action,
        "model_id": model_id,
        "prompt_version": prompt_version,
        "rationale_hash": sha256_hex(rationale.encode()),
    }
    return keccak256_hex(canonical_json(payload))


# ---------------------------------------------------------------------------
# root and proofs from instance hashes
# ---------------------------------------------------------------------------


def leaves_from_instance_hashes(instance_hashes: Sequence[str]) -> list[bytes]:
    return [merkle.leaf_from_instance_hash(h) for h in instance_hashes]


def compute_root(instance_hashes: Sequence[str]) -> str:
    """Findings root (0x-hex) for a scan; the zero root when there are no findings."""
    return merkle.to_hex(merkle.root(leaves_from_instance_hashes(instance_hashes)))


def leaf_proofs(instance_hashes: Sequence[str]) -> dict[str, tuple[str, list[str]]]:
    """``instance_hash -> (leaf_hex, proof_hex_nodes)`` for every finding of a scan.

    The scan service stores the proof on each finding row (`findings.leaf_proof`) so exports and
    decisions never rebuild the tree.
    """
    leaves = leaves_from_instance_hashes(instance_hashes)
    out: dict[str, tuple[str, list[str]]] = {}
    for h, leaf in zip(instance_hashes, leaves, strict=True):
        if h in out:
            continue
        out[h] = (merkle.to_hex(leaf), [merkle.to_hex(n) for n in merkle.proof(leaves, leaf)])
    return out


# ---------------------------------------------------------------------------
# scan verification (SPEC §12.6)
# ---------------------------------------------------------------------------


class CommitReader(Protocol):
    """Read side of :class:`athar.ledger.client.LedgerClient`; tests pass a fake."""

    def get_commit(self, scan_index: int) -> ScanCommit: ...


@dataclass(frozen=True)
class VerifyResult:
    passed: bool
    computed_root: str
    chain_root: str | None
    scan_index: int
    finding_count: int
    detail: str

    @property
    def verdict(self) -> str:
        return "PASS" if self.passed else "FAIL"


def verify_scan(db_instance_hashes: Sequence[str], scan_index: int, client: CommitReader) -> VerifyResult:
    """Recompute the root from the DB's instance hashes and compare with `getCommit(scanIndex)`.

    FAIL when the roots differ, the on-chain finding count differs, or the index is unknown to the
    contract. A node that cannot be reached raises :class:`LedgerUnavailable` (nothing was verified;
    that is neither PASS nor FAIL).
    """
    count = len(db_instance_hashes)
    computed = compute_root(db_instance_hashes)
    try:
        commit = client.get_commit(scan_index)
    except UnknownScanIndex:
        return VerifyResult(
            passed=False,
            computed_root=computed,
            chain_root=None,
            scan_index=scan_index,
            finding_count=count,
            detail=f"FAIL: scan index {scan_index} is not on the chain",
        )
    chain_root = commit.findings_root.lower()
    if chain_root != computed.lower():
        detail = f"FAIL: computed root {computed} differs from on-chain root {chain_root}"
        return VerifyResult(False, computed, chain_root, scan_index, count, detail)
    if commit.finding_count != count:
        detail = f"FAIL: {count} findings in the database, {commit.finding_count} committed on-chain"
        return VerifyResult(False, computed, chain_root, scan_index, count, detail)
    detail = f"PASS: root matches on-chain commit {scan_index} ({count} findings)"
    return VerifyResult(True, computed, chain_root, scan_index, count, detail)


# ---------------------------------------------------------------------------
# row verification for exported reports (SPEC §12.6, §16)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RowVerify:
    finding_key: str
    passed: bool
    computed_leaf: str
    computed_instance_hash: str
    detail: str


class SidecarRowLike(Protocol):
    """Shape of `athar.export.types.SidecarFinding`; duck-typed so this module needs no import."""

    @property
    def finding_key(self) -> str: ...

    @property
    def instance(self) -> dict[str, Any]: ...

    @property
    def instance_hash(self) -> str: ...

    @property
    def proof(self) -> list[str]: ...


def rows_from_sidecar(findings: Sequence[SidecarRowLike]) -> list[dict[str, Any]]:
    """Adapt sidecar findings (``read_findings_json(...).findings``) to :func:`verify_rows` rows."""
    return [
        {
            "finding_key": f.finding_key,
            "instance": f.instance,
            "instance_hash": f.instance_hash,
            "proof": list(f.proof),
        }
        for f in findings
    ]


def verify_rows(rows: Sequence[Mapping[str, Any]], chain_root: str) -> list[RowVerify]:
    """Recompute each row's `instance_hash` from its instance JSON and check inclusion in `chain_root`.

    Each row is ``{"instance": dict, "proof": [hex...]}`` with optional ``finding_key`` and
    ``instance_hash`` (when present, a mismatch with the recomputed hash fails the row). A malformed
    proof or root fails the row instead of raising, so one bad line never aborts a report check.
    """
    try:
        root_bytes = merkle.bytes32_from_hex(chain_root)
    except ValueError:
        root_bytes = None
    out: list[RowVerify] = []
    for row in rows:
        instance = row.get("instance")
        if not isinstance(instance, dict):
            out.append(
                RowVerify(str(row.get("finding_key", "")), False, "", "", "FAIL: row has no instance JSON")
            )
            continue
        key = str(row.get("finding_key") or instance.get("finding_key", ""))
        computed_hash = instance_hash(instance)
        leaf = merkle.leaf_from_instance_hash(computed_hash)
        leaf_hex = merkle.to_hex(leaf)
        claimed = row.get("instance_hash")
        if claimed and str(claimed).lower() != computed_hash.lower():
            detail = f"FAIL: instance_hash {claimed} does not match recomputed {computed_hash}"
            out.append(RowVerify(key, False, leaf_hex, computed_hash, detail))
            continue
        if root_bytes is None:
            out.append(RowVerify(key, False, leaf_hex, computed_hash, "FAIL: malformed chain root"))
            continue
        try:
            path = [merkle.bytes32_from_hex(str(p)) for p in row.get("proof", [])]
        except (ValueError, TypeError):
            out.append(RowVerify(key, False, leaf_hex, computed_hash, "FAIL: malformed proof"))
            continue
        ok = merkle.verify(root_bytes, leaf, path)
        detail = (
            "PASS: leaf included in on-chain root" if ok else "FAIL: proof does not reach the on-chain root"
        )
        out.append(RowVerify(key, ok, leaf_hex, computed_hash, detail))
    return out
