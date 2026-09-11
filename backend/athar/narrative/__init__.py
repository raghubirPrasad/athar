"""Narrative: three altitudes from templates (SPEC §10.2). No LLM; the rule engine decides."""

from athar.narrative.causal import render_causal
from athar.narrative.templates import (
    Altitudes,
    render_all,
    render_evidence,
    render_explanation,
    render_halflife_sentence,
    render_headline,
    render_line_items,
    render_score_line,
    rule_name,
    rule_summary,
)

__all__ = [
    "Altitudes",
    "render_all",
    "render_causal",
    "render_evidence",
    "render_explanation",
    "render_halflife_sentence",
    "render_headline",
    "render_line_items",
    "render_score_line",
    "rule_name",
    "rule_summary",
]
