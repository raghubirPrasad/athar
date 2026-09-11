"""Investigate agent (SPEC §11.4): model path, deterministic template fallback, provenance."""

from __future__ import annotations

from athar.agents.cache import InMemoryCacheStore
from athar.agents.inputs import InvestigateInput, build_investigate_input
from athar.agents.investigate import investigate, template_investigate
from athar.detection.base import FindingDraft
from athar.domain import EstateView
from athar.drift.types import CausalStep

from tests.agents.conftest import HOSTILE_NAME, HOSTILE_NOTE, FakeTransport, make_client, rule_spec


def _inp(estate: EstateView, draft: FindingDraft, causal: list[CausalStep] | None = None) -> InvestigateInput:
    steps = (
        causal
        if causal is not None
        else [
            CausalStep(3, "ev-0001", "grant", "role_change", "aws", "AWS admin added", {"added": ["g-002"]}),
            CausalStep(9, "ev-0002", "departure", "departure", None, HOSTILE_NOTE, {}),
        ]
    )
    return build_investigate_input(
        estate, draft, None, steps, {"median_grants": 2}, rule_spec("R3", "Orphaned access")
    )


def test_template_hypothesis_for_departed_r3_names_the_cause_and_first_action(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    out = template_investigate(_inp(r3_estate, r3_draft))
    assert out.hypothesis.startswith(
        "Access is consistent with a departed employee whose grants were never revoked."
    )
    assert "departure (departure) in May 2026" in out.hypothesis
    assert "grant (role change) in November 2025" in out.hypothesis
    assert out.recommended_action == "disable_identity"
    assert out.is_expected_for_role is False
    assert out.evidence_cited == r3_draft.evidence_keys()
    assert 0.0 <= out.confidence <= 1.0
    assert "no language model was consulted" in out.rationale


def test_template_never_echoes_provider_text(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    out = template_investigate(_inp(r3_estate, r3_draft))
    for value in out.model_dump().values():
        assert HOSTILE_NOTE not in str(value)
        assert HOSTILE_NAME not in str(value)


def test_template_without_causal_history_says_so(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    out = template_investigate(_inp(r3_estate, r3_draft, []))
    assert "No recorded access-change event" in out.hypothesis


def test_template_is_deterministic(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    assert template_investigate(_inp(r3_estate, r3_draft)) == template_investigate(_inp(r3_estate, r3_draft))


def test_investigate_with_provider_none_returns_template_meta(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    res = investigate(_inp(r3_estate, r3_draft), make_client("none"), None)
    assert res.meta.generated_by == "template"
    assert res.meta.provider == "none"
    assert res.meta.model_id == "template"
    assert res.meta.prompt_version == "inv-v1"
    assert res.meta.cached is False
    assert res.output.recommended_action in rule_spec("R3").allowed_actions


def test_investigate_with_model_returns_validated_output_and_provenance(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    gem = FakeTransport(
        {
            "hypothesis": "The employee left in May 2026 and nobody revoked the AWS admin grant.",
            "is_expected_for_role": False,
            "evidence_cited": ["grant:g-002", "event:ev-0002", "bogus:x"],
            "confidence": 0.85,
            "recommended_action": "disable_identity",
            "rationale": "Departed identity with live admin access.",
        }
    )
    cache = InMemoryCacheStore()
    client = make_client("gemini", gemini=gem)
    res = investigate(_inp(r3_estate, r3_draft), client, cache)
    assert res.meta.generated_by == "model" and res.meta.provider == "gemini"
    assert res.meta.model_id == "fake-gemini" and res.meta.prompt_version == "inv-v1"
    assert res.output.recommended_action == "disable_identity"
    assert res.output.evidence_cited == ["grant:g-002", "event:ev-0002"]
    assert "dropped_unknown_evidence_refs" in res.meta.guard_flags
    # the system prompt reached the transport and states the untrusted-text rule
    assert "untrusted_text" in gem.calls[0].system
    assert "allowed_actions" in gem.calls[0].system
    again = investigate(_inp(r3_estate, r3_draft), client, cache)
    assert again.meta.cached is True and len(gem.calls) == 1


def test_investigate_regenerate_bypasses_cache(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    good = {"hypothesis": "h", "recommended_action": "disable_identity", "confidence": 0.5}
    gem = FakeTransport(good, {**good, "hypothesis": "h2"})
    cache = InMemoryCacheStore()
    client = make_client("gemini", gemini=gem)
    investigate(_inp(r3_estate, r3_draft), client, cache)
    res = investigate(_inp(r3_estate, r3_draft), client, cache, regenerate=True)
    assert res.output.hypothesis == "h2" and res.meta.cached is False and len(gem.calls) == 2


def test_invalid_model_action_is_replaced_by_rule_default_when_sentinel_not_allowed(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    """R3 does not allow `no_action_recommended`, so the guard's sentinel is replaced by the rule's first action."""
    gem = FakeTransport({"hypothesis": "h", "recommended_action": "no_action", "confidence": 0.5})
    res = investigate(_inp(r3_estate, r3_draft), make_client("gemini", gemini=gem), None)
    assert res.output.recommended_action == "disable_identity"
    assert "action_substituted_by_rule" in res.meta.guard_flags
    assert any(f.startswith("action_not_allowed") for f in res.meta.guard_flags)


def test_invalid_model_action_keeps_sentinel_when_rule_allows_it(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    gem = FakeTransport({"hypothesis": "h", "recommended_action": "format_disk", "confidence": 0.5})
    inp = build_investigate_input(r3_estate, r3_draft, None, [], {}, rule_spec("R1", "Wildcard privilege"))
    res = investigate(inp, make_client("gemini", gemini=gem), None)
    assert res.output.recommended_action == "no_action_recommended"
    assert "action_substituted_by_rule" not in res.meta.guard_flags
