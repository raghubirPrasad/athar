"""findings.json sidecar (SPEC §16, §12.6). Pure.

Carries, per finding, the committed instance JSON (SPEC §10.1), its `instance_hash` and the
Merkle inclusion proof, so `athar verify --csv findings.csv --json findings.json` can recompute
every hash and check inclusion against the on-chain root without trusting the dashboard.
Canonical form: sorted keys, indent 2, UTF-8, trailing newline.
"""

from __future__ import annotations

import json
from typing import Any

from athar.export.types import VERIFY_COMMAND, ExportBundle, FindingsSidecar, SidecarFinding


def build_sidecar(bundle: ExportBundle) -> FindingsSidecar:
    """Typed sidecar from a bundle. Row order is preserved (the CSV and sidecar line up 1:1)."""
    return FindingsSidecar(
        scan=bundle.scan,
        merkle_root=bundle.scan.merkle_root,
        ledger_tx=bundle.scan.ledger_tx,
        contract_address=bundle.scan.contract_address,
        chain_id=bundle.scan.chain_id,
        findings=[
            SidecarFinding(
                finding_key=row.finding_key,
                instance=row.instance,
                instance_hash=row.instance_hash,
                proof=list(row.proof),
            )
            for row in bundle.rows
        ],
        verify_with=VERIFY_COMMAND,
    )


def write_findings_json(bundle: ExportBundle) -> bytes:
    payload: dict[str, Any] = build_sidecar(bundle).model_dump(mode="json")
    return (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def read_findings_json(data: bytes) -> FindingsSidecar:
    """Parse a sidecar back (schema-validated; raises pydantic.ValidationError on a bad file)."""
    return FindingsSidecar.model_validate_json(data)
