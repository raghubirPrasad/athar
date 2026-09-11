"""findings.pdf (SPEC §16): structure, footer, determinism, size."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from reportlab.pdfbase.pdfmetrics import stringWidth

sys.path.insert(0, str(Path(__file__).parent))
from _export_import import load_export_fixtures
from athar.export.pdf import (
    FOOTER_FONT,
    FOOTER_SIZE,
    SEVERITY_GLYPHS,
    USABLE_WIDTH,
    footer_lines,
    severity_label,
    top_findings,
    write_findings_pdf,
)

fx = load_export_fixtures()

_PAGE_RE = re.compile(rb"/Type\s*/Page(?![s/])")


def _page_count(pdf: bytes) -> int:
    return len(_PAGE_RE.findall(pdf))


@pytest.fixture(scope="module")
def pdf30() -> bytes:
    return write_findings_pdf(fx.make_bundle(30), compress=False)


def test_pdf_bytes_start_with_magic_and_end_with_eof(pdf30: bytes) -> None:
    assert pdf30.startswith(b"%PDF-")
    assert pdf30.rstrip().endswith(b"%%EOF")


def test_thirty_row_bundle_has_at_least_three_pages(pdf30: bytes) -> None:
    assert _page_count(pdf30) >= 3


def test_footer_on_every_page(pdf30: bytes) -> None:
    pages = _page_count(pdf30)
    assert pdf30.count(b"Merkle root " + fx.ROOT.encode()) == pages
    assert pdf30.count(b"verify with: athar verify --csv") == pages
    assert pdf30.count(b"tx " + fx.TX.encode()) == pages
    for n in range(1, pages + 1):
        assert f"Page {n}".encode() in pdf30


def test_cover_and_sections_are_present(pdf30: bytes) -> None:
    for needle in (
        b"Nahar Digital Authority",
        b"ATHAR",
        b"June 2026",
        b"2026-09-10T08:00:00+00:00",
        b"Executive summary",
        b"Department rollup",
        b"Privilege half-life",
        b"Top findings",
        b"rule definitions",
        rb"\(verify\)",  # PDF string literals escape parentheses
        b"precision 0.87 / recall 0.95",
    ):
        assert needle in pdf30, needle


def test_severity_is_text_label_plus_glyph_not_colour(pdf30: bytes) -> None:
    for sev in ("Critical", "High", "Medium", "Low"):
        assert sev.encode() in pdf30
        assert f'face="ZapfDingbats">{SEVERITY_GLYPHS[sev]}</font> {sev}' in severity_label(sev)
    assert b"ZapfDingbats" in pdf30


def test_document_metadata_from_bundle(pdf30: bytes) -> None:
    assert b"/Author (Nahar Digital Authority)" in pdf30
    assert b"/Title (ATHAR findings" in pdf30


def test_two_builds_are_byte_identical() -> None:
    a = write_findings_pdf(fx.make_bundle(12), compress=False)
    b = write_findings_pdf(fx.make_bundle(12), compress=False)
    assert a == b
    assert write_findings_pdf(fx.make_bundle(12)) == write_findings_pdf(fx.make_bundle(12))


def test_top_findings_capped_at_25_and_ordered_by_severity_then_score() -> None:
    rows = fx.make_bundle(40).rows
    top = top_findings(rows)
    assert len(top) == 25
    ranks = [(sev, score) for sev, score in ((r.severity, r.risk_score) for r in top)]
    order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    assert ranks == sorted(ranks, key=lambda t: (-order[t[0]], -t[1]))
    assert top_findings([]) == []


def test_empty_bundle_renders_empty_state_text() -> None:
    bundle = fx.make_bundle(
        0,
        department_rollup=[],
        halflife=[],
        rule_definitions=[],
        executive_summary="",
        eval_sentence=None,
        scan=fx.scan_info(
            merkle_root=None, ledger_tx=None, ledger_status="unanchored", contract_address=None, chain_id=None
        ),
    )
    pdf = write_findings_pdf(bundle, compress=False)
    assert pdf.startswith(b"%PDF-")
    assert b"No findings in this scan." in pdf
    assert b"No department data" in pdf
    assert b"No executive summary" in pdf
    assert b"No rule definitions" in pdf
    assert rb"Merkle root \(not committed\)" in pdf
    assert rb"tx \(unanchored\)" in pdf


def test_markup_characters_in_content_do_not_break_rendering() -> None:
    row = fx.make_row(
        0, display_name="<b>Bob</b> & Co", plain_english_finding="a < b && c > d", explanation="<script>"
    )
    pdf = write_findings_pdf(fx.make_bundle(1, rows=[row]), compress=False)
    assert pdf.startswith(b"%PDF-")


def test_five_hundred_rows_stays_under_one_megabyte() -> None:
    pdf = write_findings_pdf(fx.make_bundle(500))
    assert len(pdf) < 1_000_000
    assert _page_count(pdf) >= 3


def test_footer_lines_fit_inside_the_margins() -> None:
    for line in footer_lines(fx.scan_info()):
        assert stringWidth(line, FOOTER_FONT, FOOTER_SIZE) < USABLE_WIDTH * 0.8, line
