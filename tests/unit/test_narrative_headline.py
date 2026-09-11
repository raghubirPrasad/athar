"""Headline altitude (SPEC §10.2): one business sentence, phrase table, no identifiers."""

from __future__ import annotations

import re

import pytest
from athar.detection.facts import RULE_SLOTS
from athar.narrative import phrases as p
from athar.narrative.examples import example_facts
from athar.narrative.templates import render_headline

RULE_IDS = sorted(RULE_SLOTS, key=lambda r: int(r[1:]))
IDENTIFIER = re.compile(
    r"(arn:|roles/|Microsoft\.|projects/|@|[0-9a-f]{8}-[0-9a-f]{4}-|AKIA|://|\bAWS\b|\bAzure\b|\bGCP\b)",
    re.IGNORECASE,
)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_headline_renders_one_sentence_for_every_rule(rule_id: str):
    text = render_headline(rule_id, example_facts(rule_id))
    assert text.endswith(".")
    assert text.count(". ") == 0, text
    assert "unknown" not in text.lower(), text


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_headline_has_no_identifiers_or_provider_terms(rule_id: str):
    text = render_headline(rule_id, example_facts(rule_id))
    assert not IDENTIFIER.search(text), text


def test_admin_at_org_uses_phrase_table():
    text = render_headline("R1", example_facts("R1"))
    assert "unrestricted control over everything in the account" in text
    assert "Maryam Al Falasi (Finance)" in text
    assert "wildcard" in text


def test_admin_at_project_scope_phrase():
    facts = example_facts("R1") | {"scope_level": "project", "wildcard": False}
    text = render_headline("R1", facts)
    assert "unrestricted control over an entire project" in text
    assert "wildcard" not in text


def test_dormant_days_become_months():
    text = render_headline("R2", example_facts("R2"))
    assert "has not been used in four months" in text
    assert p.months_from_days(124) == 4


def test_departed_uses_month_label():
    text = render_headline("R3", example_facts("R3"))
    assert "left the organisation in May 2026" in text


def test_retired_project_phrase():
    facts = example_facts("R3") | {
        "orphan_kind": "retired_project",
        "retired_month": 6,
        "project_id": "prj-7",
    }
    text = render_headline("R3", facts)
    assert "belongs to a project retired in February 2026" in text


def test_cross_cloud_admin_and_write_delete_phrases():
    assert "holds the same power in all three clouds" in render_headline("R4", example_facts("R4"))
    text = render_headline("R4", example_facts("R4") | {"power": "write_delete"})
    assert "can change and destroy resources in all three clouds" in text


def test_toxic_combination_self_grant_phrase():
    assert "can give themselves any permission they want" in render_headline("R5", example_facts("R5"))


def test_stale_key_phrase_in_months():
    assert "has not been rotated in 14 months" in render_headline("R6", example_facts("R6"))


def test_residency_no_mfa_unowned_phrases():
    assert "reaches sensitive data held outside approved regions" in render_headline(
        "R8", example_facts("R8")
    )
    assert "holds administrative power without multi-factor authentication" in render_headline(
        "R9", example_facts("R9")
    )
    assert "an account nobody in HR owns" in render_headline("R10", example_facts("R10"))


def test_missing_facts_render_unknown_without_raising():
    text = render_headline("R2", {"display_name": "Someone"})
    assert "Someone (no department)" in text
    assert "unknown period" in text


def test_none_facts_render_without_raising():
    text = render_headline("R3", {"display_name": None, "department": None, "departure_month": None})
    assert "An unnamed identity" in text
    assert "unknown" in text


def test_identifier_like_display_name_is_masked():
    facts = example_facts("R1") | {"display_name": "arn:aws:iam::123456789012:user/x"}
    text = render_headline("R1", facts)
    assert "arn:" not in text
    assert "An unnamed account" in text


def test_unknown_rule_falls_back_to_generic_sentence():
    text = render_headline("R42", {"display_name": "Anyone", "department": "HR"})
    assert text == "Anyone (HR) has an access finding under rule R42."


def test_absurd_month_numbers_render_unknown_not_raise():
    assert p.month_or_unknown(95693) == "unknown"
    assert p.month_or_unknown(0) == "unknown"
    assert p.month_or_unknown(True) == "unknown"
    assert p.month_or_unknown(9) == "May 2026"


def test_number_words():
    assert p.number_word(2) == "two"
    assert p.number_word(0) == "zero"
    assert p.number_word(10) == "10"
    assert p.number_word(12, below=21) == "twelve"
    assert p.number_word(34, below=21) == "34"
    assert p.count_phrase(1, "grant", "grants") == "one grant"
    assert p.join_and(["AWS", "Azure", "GCP"]) == "AWS, Azure and GCP"
    assert p.format_date("2026-03-12") == "12 March 2026"
    assert p.format_date("nonsense") == "an unknown date"
