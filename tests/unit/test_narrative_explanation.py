"""Explanation altitude (SPEC §10.2) and the causal sentence (SPEC §9.2)."""

from __future__ import annotations

import pytest
from athar.detection.facts import RULE_SLOTS
from athar.drift.types import CausalStep
from athar.narrative.causal import render_causal
from athar.narrative.examples import example_causal, example_facts, example_score
from athar.narrative.templates import render_explanation

RULE_IDS = sorted(RULE_SLOTS, key=lambda r: int(r[1:]))


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_explanation_renders_for_every_rule_without_optional_inputs(rule_id: str):
    text = render_explanation(rule_id, example_facts(rule_id))
    assert len(text) > 40
    assert "unknown" not in text.lower(), text


def test_explanation_mentions_since_when():
    text = render_explanation("R1", example_facts("R1"), first_seen_month=3)
    assert "since November 2025 (month 3)" in text


def test_explanation_blast_radius_sentence():
    text = render_explanation("R1", example_facts("R1"), score=example_score())
    assert "can reach 19% of the estate (six high-sensitivity resources)" in text


def test_causal_severity_falls_back_to_rule_declaration_then_score():
    facts = example_facts("R4")
    assert "Became Critical in month 7" in render_explanation(
        "R4", facts, causal=example_causal(), first_seen_month=7
    )
    facts["power"] = "write_delete"
    assert "Became High in month 7" in render_explanation(
        "R4", facts, causal=example_causal(), first_seen_month=7
    )
    facts["severity"] = "Medium"
    assert "Became Medium in month 7" in render_explanation(
        "R4", facts, causal=example_causal(), first_seen_month=7
    )


def test_explanation_includes_causal_sentence():
    text = render_explanation("R3", example_facts("R3"), causal=example_causal(), first_seen_month=7)
    assert "Became Critical in month 7" in text
    assert "employee departed in month 11" in text


def test_explanation_remediation_effect_per_rule():
    assert "Revoking or downgrading the two administrative grants" in render_explanation(
        "R1", example_facts("R1")
    )
    assert "Disabling the identity" in render_explanation("R3", example_facts("R3"))
    assert "Rotating or disabling the credential" in render_explanation("R6", example_facts("R6"))


def test_explanation_expired_exception_sentence():
    text = render_explanation("R1", example_facts("R1"))
    assert "break-glass exception recorded in the governance register expired on 12 March 2026" in text
    assert "the register, not cloud tags, is the source of truth" in text
    assert "exception" not in render_explanation("R3", example_facts("R3")).lower()


def test_explanation_uses_thresholds():
    text = render_explanation("R2", example_facts("R2"), thresholds={"dormant_days": 120})
    assert "dormancy threshold of 120 days" in text
    assert "dormancy threshold of 90 days" in render_explanation("R2", example_facts("R2"))


def test_explanation_r4_per_cloud_counts():
    text = render_explanation("R4", example_facts("R4"))
    assert "AWS (two scopes), Azure (one scope) and GCP (one scope)" in text


def test_explanation_r5_path_uses_canonical_terms():
    text = render_explanation("R5", example_facts("R5"))
    assert "two steps" in text
    assert "--grant-->" in text and "[g-aws-0042-05]" in text


def test_explanation_r8_lists_approved_regions():
    text = render_explanation("R8", example_facts("R8"))
    assert "europe-west1" in text
    assert "me-central-1, uaenorth, uaecentral and me-central1" in text


# --- causal ----------------------------------------------------------------------


def test_causal_matches_spec_example():
    text = render_causal(example_causal(), "Critical", first_seen_month=7)
    assert text == (
        "Became Critical in month 7 when a role change added GCP Owner. "
        "The AWS administrator grant from month 3 was never removed. "
        "Dormant since month 9; employee departed in month 11."
    )


def test_causal_empty_steps_is_empty_string():
    assert render_causal([], "High", 3) == ""


def test_causal_without_first_seen_uses_last_adding_step():
    steps = example_causal()
    assert render_causal(steps, "High").startswith("Became High in month 7")


def test_causal_unknown_trigger_and_dict_delta():
    steps = [
        CausalStep(
            4, "e1", "grant", "unknown", "azure", "", {"added": [{"cloud": "azure", "role": "Owner"}]}
        ),
        CausalStep(
            6, "e2", "revoke", "remediation", "azure", "", {"removed": [{"cloud": "azure", "role": "Owner"}]}
        ),
        CausalStep(8, "e3", "mfa_lapse", "mfa_lapse", None, "MFA disabled", {}),
    ]
    text = render_causal(steps, "High", first_seen_month=8)
    assert text.startswith("Became High in month 8 when an unrecorded change added Azure Owner.")
    assert "A grant was revoked in month 6; multi-factor authentication lapsed in month 8." in text


def test_causal_removed_grant_is_not_reported_as_never_removed():
    steps = [
        CausalStep(2, "e1", "grant", "role_change", "aws", "", {"added": ["AWS admin"]}),
        CausalStep(5, "e2", "revoke", "remediation", "aws", "", {"removed": ["AWS admin"]}),
        CausalStep(7, "e3", "grant", "role_change", "gcp", "", {"added": ["GCP Owner"]}),
    ]
    text = render_causal(steps, "High", first_seen_month=7)
    assert "never removed" not in text


def test_causal_is_order_independent():
    steps = example_causal()
    assert render_causal(list(reversed(steps)), "Critical", 7) == render_causal(steps, "Critical", 7)
