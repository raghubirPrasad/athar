"""findings.json sidecar (SPEC §16, §12.6)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _export_import import load_export_fixtures
from athar.export.csv_export import write_findings_csv
from athar.export.json_export import build_sidecar, read_findings_json, write_findings_json
from athar.export.types import VERIFY_COMMAND
from athar.hashing import instance_hash

fx = load_export_fixtures()


def test_sidecar_top_level_shape() -> None:
    payload = json.loads(write_findings_json(fx.make_bundle(3)))
    assert set(payload) == {
        "scan",
        "merkle_root",
        "ledger_tx",
        "contract_address",
        "chain_id",
        "findings",
        "verify_with",
    }
    assert payload["merkle_root"] == fx.ROOT
    assert payload["ledger_tx"] == fx.TX
    assert payload["contract_address"] == "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    assert payload["chain_id"] == 31337
    assert payload["verify_with"] == VERIFY_COMMAND == "athar verify --csv findings.csv --json findings.json"
    assert payload["scan"]["scan_id"] == 3 and payload["scan"]["generated_at"] == "2026-09-10T08:00:00+00:00"


def test_each_finding_carries_instance_hash_and_proof() -> None:
    bundle = fx.make_bundle(4)
    payload = json.loads(write_findings_json(bundle))
    assert len(payload["findings"]) == 4
    for entry, row in zip(payload["findings"], bundle.rows, strict=True):
        assert set(entry) == {"finding_key", "instance", "instance_hash", "proof"}
        assert entry["finding_key"] == row.finding_key
        assert entry["instance"] == row.instance
        assert entry["proof"] == row.proof and len(entry["proof"]) == 2


def test_instance_hash_in_sidecar_equals_hashing_instance_hash() -> None:
    payload = json.loads(write_findings_json(fx.make_bundle(6)))
    for entry in payload["findings"]:
        assert entry["instance_hash"] == instance_hash(entry["instance"])
        assert entry["instance"]["finding_key"] == entry["finding_key"]
        assert entry["instance"]["evidence_refs"] == sorted(entry["instance"]["evidence_refs"])


def test_sidecar_is_canonical_sorted_keys_indent_2_trailing_newline() -> None:
    data = write_findings_json(fx.make_bundle(2))
    text = data.decode("utf-8")
    assert text.endswith("\n")
    assert text == json.dumps(json.loads(text), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    assert text.startswith('{\n  "chain_id"')


def test_sidecar_lines_up_with_csv_rows_by_finding_key() -> None:
    bundle = fx.make_bundle(5)
    csv_keys = [line.split(",")[0] for line in write_findings_csv(bundle).decode().split("\r\n")[1:] if line]
    sidecar_keys = [f["finding_key"] for f in json.loads(write_findings_json(bundle))["findings"]]
    assert csv_keys == sidecar_keys


def test_sidecar_round_trips_through_read_findings_json() -> None:
    bundle = fx.make_bundle(3)
    parsed = read_findings_json(write_findings_json(bundle))
    assert parsed == build_sidecar(bundle)


def test_read_findings_json_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        read_findings_json(b'{"findings": "nope"}')


def test_unanchored_scan_serialises_nulls_not_strings() -> None:
    bundle = fx.make_bundle(
        1, scan=fx.scan_info(merkle_root=None, ledger_tx=None, ledger_status="unanchored")
    )
    payload = json.loads(write_findings_json(bundle))
    assert payload["merkle_root"] is None and payload["ledger_tx"] is None
    assert payload["scan"]["ledger_status"] == "unanchored"


def test_sidecar_is_deterministic() -> None:
    assert write_findings_json(fx.make_bundle(7)) == write_findings_json(fx.make_bundle(7))
