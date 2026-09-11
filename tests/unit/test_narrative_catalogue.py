"""catalogue.yaml is complete and every slot it references exists (SPEC §10.2)."""

from __future__ import annotations

import pytest
from athar.detection.facts import RULE_SLOTS, missing_slots, required_slots
from athar.narrative import catalogue
from athar.narrative.examples import EXAMPLE_FACTS, example_facts
from athar.narrative.slots import derive_slots, known_slots
from athar.narrative.templates import rule_name, rule_summary

RULE_IDS = sorted(RULE_SLOTS, key=lambda r: int(r[1:]))


def test_catalogue_loads_and_validates():
    doc = catalogue.load()
    assert set(doc["rules"]) == set(RULE_IDS)
    assert set(doc["rule_text"]) == set(RULE_IDS)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_has_required_entries(rule_id: str):
    for key in catalogue.ALTITUDE_KEYS:
        assert catalogue.template(rule_id, key), f"{rule_id}.{key} missing"
    assert rule_name(rule_id) and not rule_name(rule_id).startswith("Rule ")
    assert rule_summary(rule_id).endswith(".")


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_slot_in_catalogue_is_known(rule_id: str):
    allowed = set(required_slots(rule_id)) | known_slots(rule_id)
    for key in catalogue.ALTITUDE_KEYS:
        template = catalogue.template(rule_id, key)
        assert template is not None
        for slot in catalogue.template_slots(template):
            assert slot in allowed, f"{rule_id}.{key} uses unknown slot {slot}"


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_declared_derived_slots_match_what_derive_slots_produces(rule_id: str):
    required = set(required_slots(rule_id))
    produced = set(derive_slots(rule_id, example_facts(rule_id))) - required
    assert produced == known_slots(rule_id) - required  # R7 supplies grant_count itself


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_declares_its_spec_severity(rule_id: str):
    """SPEC §7 severities; the causal sentence falls back to these when no score is given."""
    assert catalogue.rule_text(rule_id)["severity"] in {"Low", "Medium", "High", "Critical"}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_example_facts_satisfy_required_slots(rule_id: str):
    assert missing_slots(rule_id, EXAMPLE_FACTS[rule_id]) == []


def test_headline_templates_only_use_name_and_department_facts():
    """Headline altitude: no identifiers beyond display name and department (SPEC §10.2)."""
    for rule_id in RULE_IDS:
        template = catalogue.template(rule_id, "headline")
        assert template is not None
        for slot in catalogue.template_slots(template):
            assert slot in {"display_name", "department_phrase"} or slot.endswith(("_phrase", "_clause")), (
                f"{rule_id} headline uses raw slot {slot}"
            )


def test_format_spec_in_template_is_rejected():
    with pytest.raises(catalogue.CatalogueError):
        catalogue.template_slots("{dormant_days:.2f}")


def test_validate_rejects_missing_rule():
    doc = {"rules": {}, "rule_text": {}}
    with pytest.raises(catalogue.CatalogueError):
        catalogue.validate(doc)


def test_validate_rejects_unknown_slot():
    doc = catalogue.load()
    broken = {
        "rules": {**doc["rules"], "R1": {**doc["rules"]["R1"], "headline": "{display_name} {no_such_slot}"}},
        "rule_text": doc["rule_text"],
    }
    with pytest.raises(catalogue.CatalogueError, match="no_such_slot"):
        catalogue.validate(broken)


def test_unknown_rule_is_safe():
    assert rule_name("R99") == "Rule R99"
    assert "R99" in rule_summary("R99")
