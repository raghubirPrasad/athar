"""The committed ABI/bytecode artifact must match `forge build` (the API deploys from it)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
BUILT = CONTRACTS / "out" / "GovernanceLedger.sol" / "GovernanceLedger.json"
ARTIFACT = ROOT / "backend" / "athar" / "ledger" / "artifacts" / "GovernanceLedger.json"
FORGE = shutil.which("forge")


def _names(abi: list[dict], kind: str) -> set[str]:
    return {e["name"] for e in abi if e.get("type") == kind}


def test_committed_artifact_exposes_the_spec_interface() -> None:
    art = json.loads(ARTIFACT.read_text())
    abi = art["abi"]
    assert {"commitScan", "recordDecision", "verifyFinding", "getCommit", "commitCount"} <= _names(
        abi, "function"
    )
    assert {"ScanCommitted", "DecisionRecorded"} <= _names(abi, "event")
    assert {"InvalidProof", "UnknownScan", "InvalidDecision"} <= _names(abi, "error")
    assert art["bytecode"].startswith("0x") and len(art["bytecode"]) > 2


@pytest.mark.skipif(FORGE is None, reason="forge not on PATH")
def test_committed_artifact_matches_forge_build() -> None:
    subprocess.run([str(FORGE), "build"], cwd=CONTRACTS, check=True, capture_output=True, timeout=600)
    built = json.loads(BUILT.read_text())
    committed = json.loads(ARTIFACT.read_text())
    assert committed["abi"] == built["abi"], (
        "run scripts/sync_contract_artifact.py after changing the contract"
    )
    assert committed["bytecode"] == built["bytecode"]["object"]
