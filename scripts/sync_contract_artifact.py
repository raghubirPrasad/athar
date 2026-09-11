#!/usr/bin/env python3
"""Copy the forge build artifact (ABI + bytecode) into the backend so the API can deploy
without a Solidity toolchain in the container. Run via `make contracts-build`."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "contracts" / "out" / "GovernanceLedger.sol" / "GovernanceLedger.json"
DST = ROOT / "backend" / "athar" / "ledger" / "artifacts" / "GovernanceLedger.json"


def main() -> None:
    art = json.loads(SRC.read_text())
    slim = {
        "contractName": "GovernanceLedger",
        "abi": art["abi"],
        "bytecode": art["bytecode"]["object"],
        "metadata": {"compiler": art.get("metadata", {}).get("compiler", {})},
    }
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text(json.dumps(slim, indent=1, sort_keys=True) + "\n")
    print(f"wrote {DST.relative_to(ROOT)} ({len(slim['bytecode']) // 2} bytes of bytecode)")  # noqa: T201


if __name__ == "__main__":
    main()
