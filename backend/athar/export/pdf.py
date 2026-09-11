"""findings.pdf writer (SPEC §16) — ReportLab platypus, A4. Pure: bundle in, bytes out.

Structure: cover · executive summary · department rollup + half-life tables · top findings
(headline + explanation, severity as a text label **and** a glyph, never colour alone) · appendix
of rule definitions · footer on every page with the Merkle root, the ledger tx, the verify command
and the page number.

Determinism: `invariant=1` pins ReportLab's creation date and document ID; the only timestamp in
the document is `bundle.scan.generated_at`, which the caller supplies. Same bundle → same bytes.
Long hex strings are set in Courier with CJK-style wrapping so they break cleanly at any character.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Sequence
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from athar.domain import SEVERITY_RANK
from athar.export.types import (
    ExportBundle,
    FindingExportRow,
    HalfLifeExportRow,
    RuleDef,
    ScanInfo,
)

TOP_FINDINGS_LIMIT = 25
VERIFY_HINT = "athar verify --csv"
FOOTER_FONT = "Courier"
FOOTER_SIZE = 6.5
_MARGIN = 18 * mm
USABLE_WIDTH = A4[0] - 2 * _MARGIN
_MONO = "Courier"
_BODY = "Helvetica"
_BOLD = "Helvetica-Bold"

#: ZapfDingbats glyphs (a standard PDF font, renders everywhere): Critical ■, High ◆, Medium ▲, Low ●.
SEVERITY_GLYPHS: dict[str, str] = {"Critical": "n", "High": "u", "Medium": "s", "Low": "l"}
_NONE_TEXT = "n/a"

Flowable = Any  # reportlab flowables are untyped


def _esc(text: str | None) -> str:
    return _xml_escape(text or "")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("athar-body", parent=base["BodyText"], fontName=_BODY, fontSize=9.5, leading=13)
    return {
        "title": ParagraphStyle("athar-title", parent=base["Title"], fontName=_BOLD, fontSize=22, leading=28),
        "h1": ParagraphStyle("athar-h1", parent=base["Heading1"], fontName=_BOLD, fontSize=15, leading=19),
        "h2": ParagraphStyle("athar-h2", parent=base["Heading2"], fontName=_BOLD, fontSize=11.5, leading=15),
        "body": body,
        "small": ParagraphStyle("athar-small", parent=body, fontSize=8, leading=10.5, textColor=colors.grey),
        "mono": ParagraphStyle(
            "athar-mono",
            parent=body,
            fontName=_MONO,
            fontSize=7.5,
            leading=9.5,
            wordWrap="CJK",
            alignment=TA_LEFT,
        ),
        "cell": ParagraphStyle("athar-cell", parent=body, fontSize=8, leading=10),
        "cell-mono": ParagraphStyle(
            "athar-cell-mono", parent=body, fontName=_MONO, fontSize=7, leading=9, wordWrap="CJK"
        ),
    }


def severity_label(severity: str) -> str:
    """Markup for a severity cell: glyph (ZapfDingbats) + the word. Text carries the meaning; glyph assists."""
    glyph = SEVERITY_GLYPHS.get(severity, "l")
    return f'<font face="ZapfDingbats">{glyph}</font> {_esc(severity)}'


def footer_lines(scan: ScanInfo) -> tuple[str, str, str]:
    """The SPEC §16 footer, split over three lines so two 66-char hashes fit inside the margins."""
    root = scan.merkle_root or "(not committed)"
    tx = scan.ledger_tx or f"({scan.ledger_status})"
    return (f"Merkle root {root} ·", f"tx {tx} ·", f"verify with: {VERIFY_HINT}")


def _make_on_page(scan: ScanInfo) -> Callable[[Canvas, Any], None]:
    lines = footer_lines(scan)
    width = A4[0]

    def on_page(canvas: Canvas, _doc: Any) -> None:
        canvas.saveState()
        canvas.setFont(FOOTER_FONT, FOOTER_SIZE)
        canvas.setFillColor(colors.black)
        canvas.setStrokeColor(colors.grey)
        canvas.line(_MARGIN, 15 * mm, width - _MARGIN, 15 * mm)
        for i, line in enumerate(lines):
            canvas.drawString(_MARGIN, (12 - 3.5 * i) * mm, line)
        canvas.drawRightString(width - _MARGIN, 5 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    return on_page


def _kv_table(pairs: Sequence[tuple[str, str]], st: dict[str, ParagraphStyle]) -> Table:
    data = [
        [Paragraph(f"<b>{_esc(k)}</b>", st["cell"]), Paragraph(_esc(v), st["cell-mono"])] for k, v in pairs
    ]
    table = Table(data, colWidths=[38 * mm, None], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _grid_table(
    header: Sequence[str],
    rows: Sequence[Sequence[str]],
    st: dict[str, ParagraphStyle],
    col_widths: Sequence[float | None] | None = None,
) -> Table:
    data: list[list[Any]] = [[Paragraph(f"<b>{_esc(h)}</b>", st["cell"]) for h in header]]
    data.extend([Paragraph(_esc(c), st["cell"]) for c in r] for r in rows)
    table = Table(data, colWidths=list(col_widths) if col_widths else None, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _cover(bundle: ExportBundle, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    scan = bundle.scan
    pairs = [
        ("Organisation", bundle.org_name),
        ("Tool", bundle.app_name),
        ("Scan", str(scan.scan_id)),
        ("Month", f"{scan.month_label} (snapshot month {scan.snapshot_month})"),
        ("Merkle root", scan.merkle_root or "(not committed)"),
        ("Ledger tx", scan.ledger_tx or f"(none — status: {scan.ledger_status})"),
        ("Ledger status", scan.ledger_status),
        (
            "Ledger scan index",
            str(scan.ledger_scan_index) if scan.ledger_scan_index is not None else _NONE_TEXT,
        ),
        ("Contract", scan.contract_address or _NONE_TEXT),
        ("Chain id", str(scan.chain_id) if scan.chain_id is not None else _NONE_TEXT),
        ("Ruleset hash", scan.ruleset_hash or _NONE_TEXT),
        ("Snapshot hash", scan.snapshot_hash or _NONE_TEXT),
        ("Generated at", scan.generated_at),
        ("Findings", str(len(bundle.rows))),
    ]
    return [
        Spacer(1, 30 * mm),
        Paragraph(f"{_esc(bundle.app_name)} — Access Governance Findings", st["title"]),
        Paragraph(_esc(bundle.org_name), st["h2"]),
        Spacer(1, 8 * mm),
        _kv_table(pairs, st),
        Spacer(1, 6 * mm),
        Paragraph(
            "Every finding in this report is committed to a Merkle tree whose root is anchored on the "
            "governance ledger. Recompute and check inclusion with "
            f"<font face='{_MONO}'>{VERIFY_HINT} findings.csv --json findings.json</font>.",
            st["small"],
        ),
        PageBreak(),
    ]


def _executive_summary(bundle: ExportBundle, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    text = bundle.executive_summary.strip() or "No executive summary was generated for this scan."
    flow: list[Flowable] = [Paragraph("Executive summary", st["h1"])]
    flow.extend(Paragraph(_esc(p), st["body"]) for p in text.split("\n\n"))
    if bundle.eval_sentence:
        flow.append(Spacer(1, 3 * mm))
        flow.append(Paragraph(f"<b>Evaluation:</b> {_esc(bundle.eval_sentence)}", st["body"]))
    flow.append(Spacer(1, 6 * mm))
    return flow


def _half_life_cells(row: HalfLifeExportRow) -> list[str]:
    hl = f"{row.half_life_months:.1f}" if row.half_life_months is not None else _NONE_TEXT
    return [row.department, str(row.grants), str(row.revocations), hl, row.label or ""]


def _rollup(bundle: ExportBundle, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    flow: list[Flowable] = [Paragraph("Department rollup", st["h1"])]
    if bundle.department_rollup:
        rows = [
            [
                r.department,
                str(r.identities),
                str(r.findings),
                str(r.critical),
                str(r.high),
                str(r.medium),
                str(r.low),
            ]
            for r in bundle.department_rollup
        ]
        flow.append(
            _grid_table(
                ["Department", "Identities", "Findings", "Critical", "High", "Medium", "Low"], rows, st
            )
        )
    else:
        flow.append(Paragraph("No department data for this scan.", st["body"]))
    flow.append(Spacer(1, 5 * mm))
    flow.append(Paragraph("Privilege half-life", st["h2"]))
    if bundle.halflife:
        flow.append(
            _grid_table(
                ["Department", "Grants", "Revocations", "Half-life (months)", "Label"],
                [_half_life_cells(r) for r in bundle.halflife],
                st,
            )
        )
    else:
        flow.append(
            Paragraph("Half-life is computed once at least two months have been ingested.", st["body"])
        )
    flow.append(Spacer(1, 6 * mm))
    return flow


def top_findings(rows: Sequence[FindingExportRow], limit: int = TOP_FINDINGS_LIMIT) -> list[FindingExportRow]:
    """Deterministic ordering: severity rank desc, risk score desc, then finding_key."""
    return sorted(rows, key=lambda r: (-SEVERITY_RANK.get(r.severity, -1), -r.risk_score, r.finding_key))[
        :limit
    ]


def _finding_block(index: int, row: FindingExportRow, st: dict[str, ParagraphStyle]) -> Flowable:
    heading = (
        f"{index}. {severity_label(row.severity)} · {_esc(row.rule_id)} {_esc(row.rule_name)} · "
        f"{_esc(row.display_name)} ({_esc(row.department)}) · score {row.risk_score}"
    )
    parts: list[Flowable] = [Paragraph(heading, st["h2"])]
    parts.append(Paragraph(_esc(row.plain_english_finding) or "(no headline)", st["body"]))
    if row.explanation.strip():
        parts.append(Paragraph(_esc(row.explanation), st["body"]))
    if row.recommended_action:
        parts.append(Paragraph(f"<b>Recommended action:</b> {_esc(row.recommended_action)}", st["body"]))
    parts.append(
        Paragraph(
            f"finding_key {_esc(row.finding_key)} · instance_hash {_esc(row.instance_hash)} · status {_esc(row.status)}",
            st["mono"],
        )
    )
    parts.append(Spacer(1, 3 * mm))
    return KeepTogether(parts)


def _top_findings(bundle: ExportBundle, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    selected = top_findings(bundle.rows)
    flow: list[Flowable] = [
        PageBreak(),
        Paragraph(f"Top findings ({len(selected)} of {len(bundle.rows)})", st["h1"]),
        Paragraph(
            "Severity is shown as a word plus a glyph, never by colour alone. The full list is in findings.csv.",
            st["small"],
        ),
    ]
    if not selected:
        flow.append(Paragraph("No findings in this scan.", st["body"]))
        return flow
    flow.extend(_finding_block(i, row, st) for i, row in enumerate(selected, start=1))
    return flow


def _rule_cells(rule: RuleDef) -> list[str]:
    return [
        rule.rule_id,
        rule.name,
        rule.severity,
        rule.summary,
        ", ".join(rule.attack_techniques) or _NONE_TEXT,
        ", ".join(rule.control_refs) or _NONE_TEXT,
    ]


def _appendix(bundle: ExportBundle, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    flow: list[Flowable] = [PageBreak(), Paragraph("Appendix — rule definitions", st["h1"])]
    if not bundle.rule_definitions:
        flow.append(Paragraph("No rule definitions were supplied.", st["body"]))
        return flow
    table = _grid_table(
        ["Rule", "Name", "Severity", "Summary", "ATT&CK", "Controls"],
        [_rule_cells(r) for r in bundle.rule_definitions],
        st,
        col_widths=[14 * mm, 30 * mm, 17 * mm, None, 36 * mm, 36 * mm],
    )
    flow.append(table)
    flow.append(Spacer(1, 3 * mm))
    flow.append(
        Paragraph(
            "Identifiers marked (verify) have not yet been checked against the primary source (docs/MAPPINGS.md).",
            st["small"],
        )
    )
    return flow


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def write_findings_pdf(bundle: ExportBundle, *, compress: bool = True) -> bytes:
    """Render the report. `compress=False` leaves content streams readable (tests grep the footer)."""
    st = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=_MARGIN + 9 * mm,
        title=f"{bundle.app_name} findings — scan {bundle.scan.scan_id} — {bundle.scan.month_label}",
        author=bundle.org_name,
        subject="Access governance findings report",
        creator=bundle.app_name,
        invariant=1,
        pageCompression=1 if compress else 0,
    )
    story: list[Flowable] = []
    story += _cover(bundle, st)
    story += _executive_summary(bundle, st)
    story += _rollup(bundle, st)
    story += _top_findings(bundle, st)
    story += _appendix(bundle, st)
    on_page = _make_on_page(bundle.scan)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()
