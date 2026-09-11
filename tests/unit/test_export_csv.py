"""CSV export (SPEC §16 columns, §15.2 escaping)."""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent))
from _export_import import load_export_fixtures
from athar.export.csv_export import escaped_row_cells, row_cells, write_findings_csv
from athar.export.escaping import escape_cell, is_formula_like
from athar.export.types import CSV_COLUMNS, NUMERIC_COLUMNS, FindingExportRow

fx = load_export_fixtures()

SPEC_COLUMNS = [
    "finding_key",
    "identity_id",
    "display_name",
    "identity_type",
    "department",
    "clouds",
    "rule_id",
    "rule_name",
    "severity",
    "risk_score",
    "blast_radius_pct",
    "first_seen_month",
    "causal_trigger",
    "plain_english_finding",
    "recommended_action",
    "attack_technique",
    "control_ref",
    "status",
    "instance_hash",
    "scan_id",
    "merkle_root",
    "ledger_tx",
]


def _parse(data: bytes) -> list[list[str]]:
    assert not data.startswith(b"\xef\xbb\xbf"), "no BOM"
    return list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))


# --- column order ---------------------------------------------------------


def test_column_order_matches_spec_exactly() -> None:
    assert list(CSV_COLUMNS) == SPEC_COLUMNS


def test_header_row_is_spec_columns_and_crlf_terminated() -> None:
    data = write_findings_csv(fx.make_bundle(2))
    assert data.split(b"\r\n")[0] == ",".join(SPEC_COLUMNS).encode()
    assert data.endswith(b"\r\n")
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_row_cells_follow_column_order_and_join_multivalues() -> None:
    bundle = fx.make_bundle(1)
    row = bundle.rows[0]
    cells = dict(zip(CSV_COLUMNS, row_cells(row, bundle.scan), strict=True))
    assert cells["clouds"] == "aws;azure" if row.clouds == ["aws", "azure"] else "gcp"
    assert cells["attack_technique"] == "T1078 (verify);T1098 (verify)"
    assert cells["control_ref"] == "ISO 27001 A.9.2.3 (verify)"
    assert cells["risk_score"] == str(row.risk_score)
    assert cells["blast_radius_pct"] == f"{row.blast_radius_pct:.2f}"
    assert cells["instance_hash"] == row.instance_hash


def test_row_ledger_refs_fall_back_to_scan_when_unset() -> None:
    bundle = fx.make_bundle(1)
    cells = dict(zip(CSV_COLUMNS, row_cells(bundle.rows[0], bundle.scan), strict=True))
    assert cells["scan_id"] == "3"
    assert cells["merkle_root"] == fx.ROOT
    assert cells["ledger_tx"] == fx.TX


def test_row_ledger_refs_override_scan_when_set() -> None:
    bundle = fx.make_bundle(1)
    row = fx.make_row(0, scan_id=9, merkle_root="0x" + "ee" * 32, ledger_tx="0x" + "ff" * 32)
    cells = dict(zip(CSV_COLUMNS, row_cells(row, bundle.scan), strict=True))
    assert (cells["scan_id"], cells["merkle_root"], cells["ledger_tx"]) == (
        "9",
        "0x" + "ee" * 32,
        "0x" + "ff" * 32,
    )


def test_unanchored_scan_leaves_ledger_cells_empty() -> None:
    bundle = fx.make_bundle(
        1, scan=fx.scan_info(merkle_root=None, ledger_tx=None, ledger_status="unanchored")
    )
    rows = _parse(write_findings_csv(bundle))
    assert rows[1][SPEC_COLUMNS.index("merkle_root")] == ""
    assert rows[1][SPEC_COLUMNS.index("ledger_tx")] == ""


# --- round trip -------------------------------------------------------------


def test_round_trip_parses_back_to_same_values() -> None:
    bundle = fx.make_bundle(30)
    parsed = _parse(write_findings_csv(bundle))
    assert parsed[0] == SPEC_COLUMNS
    assert len(parsed) == 31
    for line, row in zip(parsed[1:], bundle.rows, strict=True):
        assert line == escaped_row_cells(row, bundle.scan)
        assert line[0] == row.finding_key


def test_empty_bundle_writes_header_only() -> None:
    parsed = _parse(write_findings_csv(fx.make_bundle(0)))
    assert parsed == [SPEC_COLUMNS]


def test_cells_with_commas_quotes_and_newlines_survive_round_trip() -> None:
    nasty = 'He said "hi", then\r\nleft'
    bundle = fx.make_bundle(1, rows=[fx.make_row(0, plain_english_finding=nasty, display_name="A, B")])
    parsed = _parse(write_findings_csv(bundle))
    assert parsed[1][SPEC_COLUMNS.index("plain_english_finding")] == nasty
    assert parsed[1][SPEC_COLUMNS.index("display_name")] == "A, B"


# --- escaping -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ['=HYPERLINK("http://x")', "+1", "-1", "@SUM(A1)", "\tfoo", "\rfoo", "\nfoo", "  =1+1", " \t-cmd"],
)
def test_escape_cell_prefixes_formula_like_values(value: str) -> None:
    assert is_formula_like(value)
    assert escape_cell(value) == "'" + value


@pytest.mark.parametrize(
    "value", ["", "plain", "a=b", "R1", "0x1234", "1", "12.50", "Nahar Digital Authority"]
)
def test_escape_cell_leaves_safe_values_untouched(value: str) -> None:
    assert not is_formula_like(value)
    assert escape_cell(value) == value


def test_escape_cell_is_idempotent() -> None:
    once = escape_cell("=1")
    assert escape_cell(once) == once


def test_injected_formula_fixture_is_neutralised_in_output() -> None:
    row = fx.make_row(0, display_name='=HYPERLINK("http://evil.example")', department="-2+3")
    parsed = _parse(write_findings_csv(fx.make_bundle(1, rows=[row])))
    assert parsed[1][SPEC_COLUMNS.index("display_name")].startswith("'=")
    assert parsed[1][SPEC_COLUMNS.index("department")] == "'-2+3"


def test_numeric_columns_are_never_escaped_and_never_negative() -> None:
    bundle = fx.make_bundle(10)
    for row in bundle.rows:
        for column, raw, esc in zip(
            CSV_COLUMNS, row_cells(row, bundle.scan), escaped_row_cells(row, bundle.scan), strict=True
        ):
            if column in NUMERIC_COLUMNS:
                assert raw == esc and not raw.startswith("-")


def test_negative_numbers_are_rejected_at_the_model_boundary() -> None:
    with pytest.raises(ValueError):
        fx.make_row(0, risk_score=-1)
    with pytest.raises(ValueError):
        fx.make_row(0, first_seen_month=0)
    with pytest.raises(ValueError):
        fx.make_row(0, blast_radius_pct=-0.5)


_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40)
_TRIGGERED = st.one_of(
    _TEXT, st.tuples(st.sampled_from(["=", "+", "-", "@", "\t", "\r", "\n", " ="]), _TEXT).map("".join)
)


@settings(max_examples=150, deadline=None)
@given(name=_TRIGGERED, dept=_TRIGGERED, headline=_TRIGGERED, action=_TRIGGERED, cloud=_TRIGGERED)
def test_property_no_parsed_cell_starts_with_a_formula_trigger(
    name: str, dept: str, headline: str, action: str, cloud: str
) -> None:
    row = fx.make_row(
        0,
        display_name=name,
        department=dept,
        plain_english_finding=headline,
        recommended_action=action,
        clouds=[cloud],
    )
    parsed = _parse(write_findings_csv(fx.make_bundle(1, rows=[row])))
    assert len(parsed) == 2 and len(parsed[1]) == len(SPEC_COLUMNS)
    for cell in parsed[1]:
        assert cell[:1] not in ("=", "+", "-", "@", "\t", "\r", "\n")
        assert cell.lstrip(" \t\r\n\x0b\x0c")[:1] not in ("=", "+", "-", "@")


def test_model_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError):
        FindingExportRow(**{**fx.make_row(0).model_dump(), "bogus": 1})
