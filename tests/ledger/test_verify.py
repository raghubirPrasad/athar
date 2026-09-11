"""Verification and decision hashing (SPEC §12.6, §12.2). Pure; no chain needed."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from athar.hashing import finding_instance, instance_hash
from athar.ledger import merkle, verify
from athar.ledger.client import ScanCommit, UnknownScanIndex
from eth_utils import keccak


def _instances(n: int) -> list[dict]:
    return [
        finding_instance(
            finding_key=f"{i:032x}",
            identity_id=f"emp-{i:04d}",
            rule_id="R1" if i % 2 else "R3",
            severity="High",
            score=60 + i,
            snapshot_month=3,
            first_seen_month=1,
            evidence_refs=[f"grant:g{i}", "grant:g0"],
            causal_event_ids=[],
        )
        for i in range(n)
    ]


def _commit(root: str, count: int) -> ScanCommit:
    return ScanCommit(
        snapshot_hash="0x" + "11" * 32,
        findings_root=root,
        ruleset_hash="0x" + "22" * 32,
        finding_count=count,
        timestamp=1_700_000_000,
        submitter="0x0000000000000000000000000000000000000001",
    )


@dataclass
class _FakeReader:
    commits: dict[int, ScanCommit]

    def get_commit(self, scan_index: int) -> ScanCommit:
        if scan_index not in self.commits:
            raise UnknownScanIndex("UnknownScan")
        return self.commits[scan_index]


# ---------------------------------------------------------------- codes and hashes


def test_decision_codes_match_spec() -> None:
    assert verify.DECISION_CODES == {
        "approved": 1,
        "rejected": 2,
        "auto_remediated": 3,
        "remediation_applied": 4,
        "exception_granted": 5,
    }
    assert verify.DECISION_NAMES[5] == "exception_granted"
    assert all(1 <= c <= 5 for c in verify.DECISION_CODES.values())


def test_actor_hash_is_keccak_of_user_id() -> None:
    assert verify.actor_hash("user-approver") == "0x" + keccak(b"user-approver").hex()
    assert verify.actor_hash("a") != verify.actor_hash("b")


def test_evidence_hash_follows_spec_recipe() -> None:
    rationale = "Drop the org-level admin grant; keep the read-only project role."
    payload = {
        "action": "revoke_grant",
        "model_id": "gemini-2.5-flash",
        "plan_id": "plan-1",
        "prompt_version": "v3",
        "rationale_hash": hashlib.sha256(rationale.encode()).hexdigest(),
    }
    expected = "0x" + keccak(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hex()
    assert verify.evidence_hash("plan-1", "revoke_grant", "gemini-2.5-flash", "v3", rationale) == expected


def test_evidence_hash_is_deterministic_and_sensitive() -> None:
    a = verify.evidence_hash("p", "revoke_grant", None, None, "why")
    assert a == verify.evidence_hash("p", "revoke_grant", None, None, "why")
    assert a != verify.evidence_hash("p", "revoke_grant", None, None, "why not")
    assert a != verify.evidence_hash("p", "revoke_grant", "model", "v1", "why")
    assert len(a) == 66 and a.startswith("0x")


# ---------------------------------------------------------------- root and proofs


def test_compute_root_empty_is_zero_root() -> None:
    assert verify.compute_root([]) == merkle.to_hex(merkle.ZERO_ROOT)


def test_leaf_proofs_cover_every_hash_and_verify() -> None:
    hashes = [instance_hash(i) for i in _instances(7)]
    hashes.append(hashes[0])  # duplicate row must not break the map
    root = merkle.bytes32_from_hex(verify.compute_root(hashes))
    proofs = verify.leaf_proofs(hashes)
    assert set(proofs) == set(hashes)
    for h, (leaf_hex, proof_hex) in proofs.items():
        assert leaf_hex == merkle.to_hex(merkle.leaf_from_instance_hash(h))
        assert merkle.verify(
            root, merkle.bytes32_from_hex(leaf_hex), [merkle.bytes32_from_hex(p) for p in proof_hex]
        )


# ---------------------------------------------------------------- verify_scan


def test_verify_scan_passes_when_root_and_count_match() -> None:
    hashes = [instance_hash(i) for i in _instances(5)]
    root = verify.compute_root(hashes)
    result = verify.verify_scan(hashes, 3, _FakeReader({3: _commit(root, 5)}))
    assert result.passed and result.verdict == "PASS"
    assert result.computed_root == root and result.chain_root == root
    assert result.scan_index == 3 and result.finding_count == 5
    assert result.detail.startswith("PASS")


def test_verify_scan_fails_when_a_severity_was_edited() -> None:
    insts = _instances(5)
    root = verify.compute_root([instance_hash(i) for i in insts])
    insts[2]["severity"] = "Low"  # the tamper demo (SPEC §12.6)
    result = verify.verify_scan([instance_hash(i) for i in insts], 0, _FakeReader({0: _commit(root, 5)}))
    assert not result.passed and result.verdict == "FAIL"
    assert result.chain_root == root and result.computed_root != root
    assert "differs" in result.detail


def test_verify_scan_fails_when_count_differs() -> None:
    hashes = [instance_hash(i) for i in _instances(4)]
    root = verify.compute_root(hashes)
    result = verify.verify_scan(hashes, 0, _FakeReader({0: _commit(root, 9)}))
    assert not result.passed
    assert "9 committed" in result.detail


def test_verify_scan_fails_for_unknown_scan_index() -> None:
    hashes = [instance_hash(i) for i in _instances(2)]
    result = verify.verify_scan(hashes, 42, _FakeReader({}))
    assert not result.passed and result.chain_root is None
    assert "42" in result.detail


def test_verify_scan_zero_findings_pass_against_zero_root() -> None:
    zero = merkle.to_hex(merkle.ZERO_ROOT)
    result = verify.verify_scan([], 0, _FakeReader({0: _commit(zero, 0)}))
    assert result.passed and result.finding_count == 0


# ---------------------------------------------------------------- verify_rows


def _rows(insts: list[dict]) -> tuple[list[dict], str]:
    hashes = [instance_hash(i) for i in insts]
    proofs = verify.leaf_proofs(hashes)
    rows = [
        {"finding_key": i["finding_key"], "instance": i, "instance_hash": h, "proof": proofs[h][1]}
        for i, h in zip(insts, hashes, strict=True)
    ]
    return rows, verify.compute_root(hashes)


def test_verify_rows_all_pass_for_an_honest_export() -> None:
    rows, root = _rows(_instances(6))
    results = verify.verify_rows(rows, root)
    assert len(results) == 6
    assert all(r.passed for r in results)
    assert [r.finding_key for r in results] == [r["finding_key"] for r in rows]
    assert results[0].computed_leaf == merkle.to_hex(merkle.leaf_from_instance_hash(rows[0]["instance_hash"]))


def test_verify_rows_detects_edited_severity_in_one_row() -> None:
    rows, root = _rows(_instances(6))
    rows[3]["instance"]["severity"] = "Low"
    del rows[3]["instance_hash"]  # a forger would drop the stale hash too
    results = verify.verify_rows(rows, root)
    assert [r.passed for r in results] == [True, True, True, False, True, True]
    assert "proof does not reach" in results[3].detail


def test_verify_rows_detects_claimed_hash_mismatch() -> None:
    rows, root = _rows(_instances(2))
    rows[0]["instance"]["score"] = 1
    results = verify.verify_rows(rows, root)
    assert not results[0].passed and "instance_hash" in results[0].detail
    assert results[1].passed


def test_verify_rows_malformed_input_fails_rows_without_raising() -> None:
    rows, root = _rows(_instances(3))
    rows[0]["proof"] = ["0xzz"]
    rows[1] = {"finding_key": "no-instance"}
    results = verify.verify_rows(rows, root)
    assert not results[0].passed and "malformed proof" in results[0].detail
    assert not results[1].passed and results[1].finding_key == "no-instance"
    assert results[2].passed
    assert all(not r.passed for r in verify.verify_rows(rows, "0x1234"))


def test_rows_from_sidecar_adapts_export_types() -> None:
    from athar.export.types import SidecarFinding

    rows, root = _rows(_instances(3))
    sidecar = [SidecarFinding(**r) for r in rows]
    adapted = verify.rows_from_sidecar(sidecar)
    assert adapted == rows
    assert all(r.passed for r in verify.verify_rows(adapted, root))


# ---------------------------------------------------------------- purpose text (SPEC §12.1)


def test_purpose_and_limits_say_what_spec_says() -> None:
    assert "post-hoc alteration" in verify.LEDGER_PURPOSE
    assert "writer key" in verify.LEDGER_LIMITS and "HSM" in verify.LEDGER_LIMITS
    assert "No IAM data" in verify.LEDGER_LIMITS
    assert any("grants" in line for line in verify.NOT_ON_CHAIN)
    assert any("findingsRoot" in line for line in verify.ON_CHAIN)
