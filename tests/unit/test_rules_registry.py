"""Registry contract (SPEC §7): every rule registers, fires on a fixture estate with complete
facts and concrete evidence, and is byte-stable across runs (CLAUDE.md non-negotiables 4, 7, 8)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection import registry
from athar.detection.base import FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS, RULE_SLOTS, missing_slots
from athar.domain import ALLOWED_ACTIONS, SEVERITIES, Thresholds
from test_rules_support import access_graph, fake_build_graph, full_estate

RULE_IDS = [f"R{i}" for i in range(11)]


@pytest.fixture
def drafts(monkeypatch: pytest.MonkeyPatch) -> list[FindingDraft]:
    estate, paths = full_estate()
    monkeypatch.setattr(access_graph, "build_graph", fake_build_graph(paths))
    return registry.run_all(estate, Thresholds())


def test_all_eleven_rules_registered_in_numeric_order() -> None:
    assert [r.id for r in registry.all_rules()] == RULE_IDS
    assert registry.get_rule("R5").id == "R5"


def test_rule_versions_map() -> None:
    assert registry.rule_versions() == dict.fromkeys(RULE_IDS, "1.0")


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_metadata_contract(rule_id: str) -> None:
    rule: RuleSpec = registry.get_rule(rule_id)
    assert rule.name and rule.description
    assert rule.severity in SEVERITIES
    assert rule.allowed_actions == RULE_ALLOWED_ACTIONS[rule_id]
    assert set(rule.allowed_actions) <= set(ALLOWED_ACTIONS)
    for ref in (*rule.attack_techniques, *rule.control_refs):
        assert ref.endswith(" (verify)"), (
            f"{rule_id}: {ref!r} must carry the (verify) mark until MAPPINGS.md confirms it"
        )


def test_spec_7_attack_techniques_are_quoted_verbatim() -> None:
    expected = {
        "R1": ("T1078.004",),
        "R2": ("T1078.004",),
        "R3": ("T1078.004",),
        "R4": ("T1078.004",),
        "R5": ("T1098", "T1548"),
        "R6": ("T1098.001",),
        "R9": ("T1078.004", "T1556"),
        "R0": (),
        "R7": (),
        "R8": (),
        "R10": (),
    }
    for rule_id, techniques in expected.items():
        got = tuple(t.removesuffix(" (verify)") for t in registry.get_rule(rule_id).attack_techniques)
        assert got == techniques, rule_id


def test_every_rule_fires_on_the_fixture_estate(drafts: list[FindingDraft]) -> None:
    assert {d.rule_id for d in drafts} == set(RULE_IDS)


def test_every_draft_has_complete_facts(drafts: list[FindingDraft]) -> None:
    for d in drafts:
        assert missing_slots(d.rule_id, d.facts) == [], (d.rule_id, d.identity_id)
        assert d.facts["identity_id"] == d.identity_id
        assert d.facts["clouds"] == sorted(d.facts["clouds"])


def test_every_draft_cites_concrete_evidence(drafts: list[FindingDraft]) -> None:
    for d in drafts:
        assert len(d.evidence) >= 1, (d.rule_id, d.identity_id)
        assert all(e.ref for e in d.evidence)
        assert d.evidence == sorted(set(d.evidence), key=lambda e: (e.kind, e.ref, e.note))


def test_severity_is_the_rule_severity_unless_spec_says_otherwise(drafts: list[FindingDraft]) -> None:
    for d in drafts:
        static = registry.get_rule(d.rule_id).severity
        if d.rule_id == "R4":
            assert d.severity in ("Critical", "High")
        elif d.rule_id == "R6":
            assert d.severity in ("Medium", "High")
        else:
            assert d.severity == static, d.rule_id


def test_at_most_one_draft_per_identity_and_rule(drafts: list[FindingDraft]) -> None:
    keys = [(d.rule_id, d.identity_id) for d in drafts]
    assert len(keys) == len(set(keys))


def test_drafts_are_ordered_by_rule_then_identity(drafts: list[FindingDraft]) -> None:
    order = [(int(d.rule_id[1:]), d.identity_id) for d in drafts]
    assert order == sorted(order)


def test_facts_and_causal_ids_are_json_serialisable(drafts: list[FindingDraft]) -> None:
    for d in drafts:
        json.dumps({"facts": d.facts, "causal": d.causal_event_ids, "evidence": d.evidence_keys()})
        assert d.causal_event_ids == sorted(set(d.causal_event_ids))


def test_run_all_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    estate, paths = full_estate()
    monkeypatch.setattr(access_graph, "build_graph", fake_build_graph(paths))
    first = registry.run_all(estate, Thresholds())
    second = registry.run_all(estate, Thresholds())
    assert first == second
    assert [d.evidence_keys() for d in first] == [d.evidence_keys() for d in second]


def test_thresholds_are_taken_from_the_argument_only(monkeypatch: pytest.MonkeyPatch) -> None:
    estate, paths = full_estate()
    monkeypatch.setattr(access_graph, "build_graph", fake_build_graph(paths))
    loose = Thresholds(
        dormant_days=10_000, stale_key_days=10_000, approved_regions=("eu-west-1", "me-central-1")
    )
    fired = {d.rule_id for d in registry.run_all(estate, loose)}
    assert not {"R2", "R6", "R8"} & fired
    assert {"R1", "R3", "R4", "R9"} <= fired


def test_empty_estate_yields_nothing() -> None:
    from athar.domain import EstateView

    assert registry.run_all(EstateView(month=1), Thresholds()) == []


def test_rule_slots_cover_every_registered_rule() -> None:
    assert set(RULE_SLOTS) == set(RULE_IDS)


def test_expected_identities_per_rule(drafts: list[FindingDraft]) -> None:
    by_rule: dict[str, list[str]] = {}
    for d in drafts:
        by_rule.setdefault(d.rule_id, []).append(d.identity_id)
    assert by_rule["R3"] == ["emp-0002", "svc:prj-001:etl"]
    assert by_rule["R10"] == ["unlinked:gcp:user:ghost@nda.example"]
    assert by_rule["R7"] == ["emp-0001"]
    assert by_rule["R5"] == ["emp-0001"]
    assert by_rule["R9"] == ["emp-0001"] and by_rule["R4"] == ["emp-0001"]
