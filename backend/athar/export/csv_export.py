"""findings.csv writer (SPEC §16, §15.2). Pure: bytes in, bytes out.

Format: RFC 4180 — comma delimiter, `\\r\\n` line terminator, minimal quoting, UTF-8 **without** a
byte-order mark (a BOM would corrupt the first header cell for `athar verify --csv` and most
non-Excel consumers; Excel still opens plain UTF-8 correctly via Data > From Text).

Every cell passes `escaping.escape_cell`. Numeric columns (`NUMERIC_COLUMNS`) are formatted here
from non-negative ints/floats and therefore never begin with `-`; a guard raises if that
invariant is ever broken so a negative number can never silently reach a spreadsheet unescaped.
"""

from __future__ import annotations

import csv
import io

from athar.export.escaping import escape_cell, is_formula_like
from athar.export.types import (
    CSV_COLUMNS,
    MULTI_VALUE_SEPARATOR,
    NUMERIC_COLUMNS,
    ExportBundle,
    FindingExportRow,
    ScanInfo,
)

LINE_TERMINATOR = "\r\n"


def _fmt_int(value: int) -> str:
    return str(int(value))


def _fmt_float(value: float) -> str:
    return f"{float(value):.2f}"


def _join(values: list[str]) -> str:
    return MULTI_VALUE_SEPARATOR.join(values)


def row_cells(row: FindingExportRow, scan: ScanInfo) -> list[str]:
    """Raw (unescaped) cell strings in `CSV_COLUMNS` order. Row-level ledger refs fall back to the scan."""
    scan_id = row.scan_id if row.scan_id is not None else scan.scan_id
    merkle_root = row.merkle_root if row.merkle_root is not None else scan.merkle_root
    ledger_tx = row.ledger_tx if row.ledger_tx is not None else scan.ledger_tx
    values: dict[str, str] = {
        "finding_key": row.finding_key,
        "identity_id": row.identity_id,
        "display_name": row.display_name,
        "identity_type": row.identity_type,
        "department": row.department,
        "clouds": _join(row.clouds),
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "severity": row.severity,
        "risk_score": _fmt_int(row.risk_score),
        "blast_radius_pct": _fmt_float(row.blast_radius_pct),
        "first_seen_month": _fmt_int(row.first_seen_month),
        "causal_trigger": row.causal_trigger,
        "plain_english_finding": row.plain_english_finding,
        "recommended_action": row.recommended_action,
        "attack_technique": _join(row.attack_technique),
        "control_ref": _join(row.control_ref),
        "status": row.status,
        "instance_hash": row.instance_hash,
        "scan_id": _fmt_int(scan_id),
        "merkle_root": merkle_root or "",
        "ledger_tx": ledger_tx or "",
    }
    return [values[column] for column in CSV_COLUMNS]


def escaped_row_cells(row: FindingExportRow, scan: ScanInfo) -> list[str]:
    """`row_cells` with the §15.2 escape applied to every cell."""
    cells: list[str] = []
    for column, raw in zip(CSV_COLUMNS, row_cells(row, scan), strict=True):
        if column in NUMERIC_COLUMNS and is_formula_like(raw):
            # Unreachable by construction (pydantic ge=0 + our formatting). Fail loudly rather than emit.
            raise ValueError(f"numeric column {column!r} produced formula-like cell {raw!r}")
        cells.append(escape_cell(raw))
    return cells


def write_findings_csv(bundle: ExportBundle) -> bytes:
    """Serialise `bundle.rows` as findings.csv (header + one line per row), UTF-8, no BOM."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator=LINE_TERMINATOR)
    writer.writerow(CSV_COLUMNS)
    for row in bundle.rows:
        writer.writerow(escaped_row_cells(row, bundle.scan))
    return buffer.getvalue().encode("utf-8")
