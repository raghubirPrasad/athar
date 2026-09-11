"""Plan-remediation agent (SPEC §11.4): deterministic diff, engine-owned numbers, model plan validation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

import pytest
from athar.agents.cache import InMemoryCacheStore
from athar.agents.inputs import (
    ActivityFacts,
    FindingFacts,
    GrantFacts,
    IdentityFacts,
    PlanInput,
    build_plan_input,
)
from athar.agents.remediate import (
    PlanEngine,
    PlanResult,
    deterministic_plan,
    least_privilege_diff,
    plan_as_dict,
    plan_remediation,
    validate_plan,
)
from athar.agents.schemas import PlanOutput
from athar.detection.base import FindingDraft
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.domain import EstateView

from tests.agents.conftest import FakeTransport, make_client, rule_spec

AS_OF = date(2026, 8, 31)


def _g(gid: str, cloud: str = "aws", cat: str = "storage", verb: str = "read") -> GrantFacts:
    return GrantFacts(
        grant_id=gid,
        cloud=cloud,
        service_category=cat,
        verb=verb,
        scope_level="resource",
        scope_ref={"untrusted_text": "ref"},
        granted_via={"untrusted_text": "direct"},
    )


def _a(cloud: str, cat: str, count: int = 5) -> ActivityFacts:
    return ActivityFacts(
        cloud=cloud, service_category=cat, last_activity_at=date(2026, 8, 1), operation_count=count
    )


def _identity(status: str = "active") -> IdentityFacts:
    return IdentityFacts(
        identity_id="emp-0001",
        display_name={"untrusted_text": "Test Person"},
        identity_type="human",
        department="Finance",
        employment_status=status,
        external=False,
        mfa_enforced=True,
    )


def _inp(
    rule_id: str,
    grants: Sequence[GrantFacts],
    activity: Sequence[ActivityFacts] = (),
    *,
    status: str = "active",
    creds: Sequence[str] = (),
    facts: dict[str, object] | None = None,
) -> PlanInput:
    return PlanInput(
        finding=FindingFacts(finding_key="k", rule_id=rule_id, rule_name="n", severity="High", score=70),
        identity=_identity(status),
        facts=facts or {},
        grants=list(grants),
        activity_90d=list(activity),
        credential_refs=list(creds),
        allowed_actions=list(RULE_ALLOWED_ACTIONS[rule_id]),
        current_blast_radius=0.5,
        as_of=AS_OF,
    )


class SpyEngine:
    """Records what the agent asked for; returns fixed numbers so the source of truth is observable."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, keep: Sequence[str]) -> tuple[float, float]:
        self.calls.append(list(keep))
        return (0.123, 45.6)

    def engine(self) -> PlanEngine:
        return PlanEngine(compute_after=self)


# --- least_privilege_diff -------------------------------------------------------


def test_least_privilege_diff_keeps_used_pairs_and_read_verbs_drops_rest() -> None:
    grants = [
        _g("g-1", "aws", "storage", "write"),  # used → keep
        _g("g-2", "aws", "compute", "admin"),  # unused, not read → drop
        _g("g-3", "gcp", "data", "read"),  # read → keep even if unused
        _g("g-4", "azure", "identity", "grant"),  # unused → drop
    ]
    keep, drop = least_privilege_diff(grants, [_a("aws", "storage")])
    assert keep == ["g-1", "g-3"]
    assert drop == ["g-2", "g-4"]


def test_least_privilege_diff_ignores_zero_count_activity_and_is_sorted() -> None:
    grants = [_g("g-9", "aws", "compute", "write"), _g("g-1", "aws", "compute", "write")]
    keep, drop = least_privilege_diff(grants, [_a("aws", "compute", count=0)])
    assert keep == []
    assert drop == ["g-1", "g-9"]


def test_least_privilege_diff_empty_inputs() -> None:
    assert least_privilege_diff([], []) == ([], [])


# --- deterministic_plan -----------------------------------------------------------


def test_deterministic_plan_r3_disables_identity_and_drops_everything() -> None:
    inp = _inp("R3", [_g("g-1"), _g("g-2", verb="admin")], [_a("aws", "storage")], status="departed")
    plan = deterministic_plan(inp)
    assert plan.action == "disable_identity"
    assert plan.keep == [] and plan.drop == ["g-1", "g-2"]
    assert plan.params == {"identity_id": "emp-0001"}
    assert validate_plan(plan, inp) == []


def test_deterministic_plan_departed_identity_on_other_rule_disables_when_allowed() -> None:
    inp = _inp("R2", [_g("g-1"), _g("g-2", verb="admin")], status="departed")
    plan = deterministic_plan(inp)
    assert plan.action == "disable_identity"
    assert plan.drop == ["g-1", "g-2"]


def test_deterministic_plan_r6_rotates_credential_named_in_facts() -> None:
    inp = _inp(
        "R6",
        [_g("g-1", verb="write")],
        creds=["aws:key:AKIA0001", "aws:key:AKIA0002"],
        facts={"credential_ref": "aws:key:AKIA0002"},
    )
    plan = deterministic_plan(inp)
    assert plan.action == "rotate_or_disable_credential"
    assert plan.params == {"credential_ref": "aws:key:AKIA0002"}
    assert plan.keep == ["g-1"] and plan.drop == []
    assert validate_plan(plan, inp) == []


def test_deterministic_plan_r6_falls_back_to_first_active_credential() -> None:
    inp = _inp("R6", [_g("g-1")], creds=["aws:key:AKIA0001"], facts={"credential_ref": "aws:key:GONE"})
    assert deterministic_plan(inp).params == {"credential_ref": "aws:key:AKIA0001"}


def test_deterministic_plan_least_privilege_chooses_downgrade_when_something_drops() -> None:
    inp = _inp("R1", [_g("g-1", verb="write"), _g("g-2", "aws", "compute", "admin")], [_a("aws", "storage")])
    plan = deterministic_plan(inp)
    assert plan.action == "downgrade_to_least_privilege"
    assert plan.keep == ["g-1"] and plan.drop == ["g-2"]
    assert plan.params == {"grant_ids": ["g-2"]}
    assert validate_plan(plan, inp) == []


def test_deterministic_plan_nothing_to_drop_recommends_no_action() -> None:
    inp = _inp("R1", [_g("g-1", verb="read")], [])
    plan = deterministic_plan(inp)
    assert plan.action == "no_action_recommended"
    assert plan.keep == ["g-1"] and plan.drop == []
    assert plan.params == {}


def test_deterministic_plan_is_pure() -> None:
    inp = _inp("R1", [_g("g-1", verb="write"), _g("g-2", "aws", "compute", "admin")], [_a("aws", "storage")])
    assert deterministic_plan(inp) == deterministic_plan(inp)


# --- validate_plan ------------------------------------------------------------------


@pytest.fixture
def r1_inp() -> PlanInput:
    return _inp(
        "R1",
        [
            _g("g-1", "aws", "storage", "write"),
            _g("g-2", "aws", "compute", "admin"),
            _g("g-3", "gcp", "data", "read"),
        ],
        [_a("aws", "storage")],
    )


def test_validate_plan_accepts_a_valid_least_privilege_plan(r1_inp: PlanInput) -> None:
    plan = PlanOutput(action="revoke_grant", keep=["g-1", "g-3"], drop=["g-2"], confidence=0.8)
    assert validate_plan(plan, r1_inp) == []


def test_validate_plan_rejects_action_outside_allowed(r1_inp: PlanInput) -> None:
    plan = PlanOutput(action="disable_identity", keep=[], drop=["g-1", "g-2", "g-3"])
    assert "action_not_allowed" in validate_plan(plan, r1_inp)


def test_validate_plan_rejects_drop_not_subset_of_grants(r1_inp: PlanInput) -> None:
    plan = PlanOutput(action="revoke_grant", keep=["g-1", "g-3"], drop=["g-2", "g-999"])
    assert "drop_not_subset_of_grants" in validate_plan(plan, r1_inp)


def test_validate_plan_rejects_keep_of_unused_non_read_grant(r1_inp: PlanInput) -> None:
    plan = PlanOutput(action="revoke_grant", keep=["g-1", "g-2", "g-3"], drop=[])
    assert "keep_not_used_or_read" in validate_plan(plan, r1_inp)


def test_validate_plan_rejects_overlap_and_unaccounted_grants(r1_inp: PlanInput) -> None:
    v = validate_plan(PlanOutput(action="revoke_grant", keep=["g-1"], drop=["g-1"]), r1_inp)
    assert "keep_drop_overlap" in v and "grants_unaccounted" in v


def test_validate_plan_disable_identity_must_drop_all() -> None:
    inp = _inp("R3", [_g("g-1"), _g("g-2")], status="departed")
    v = validate_plan(PlanOutput(action="disable_identity", keep=["g-1"], drop=["g-2"]), inp)
    assert "disable_identity_must_drop_all" in v


def test_validate_plan_rotate_credential_requires_known_ref_and_no_drop() -> None:
    inp = _inp("R6", [_g("g-1")], creds=["aws:key:AKIA0001"])
    v = validate_plan(
        PlanOutput(
            action="rotate_or_disable_credential",
            params={"credential_ref": "aws:key:OTHER"},
            keep=[],
            drop=["g-1"],
        ),
        inp,
    )
    assert "credential_ref_not_in_input" in v and "non_grant_action_with_drop" in v


# --- plan_remediation ----------------------------------------------------------------


def test_template_fallback_uses_deterministic_plan_and_engine_numbers(r1_inp: PlanInput) -> None:
    spy = SpyEngine()
    res = plan_remediation(r1_inp, make_client("none"), None, engine=spy.engine())
    assert res.meta.generated_by == "template" and res.meta.model_id == "template"
    assert res.meta.prompt_version == "plan-v1"
    assert res.proposed_by == "rule"
    assert res.output.action == "downgrade_to_least_privilege"
    assert res.output.keep == ["g-1", "g-3"] and res.output.drop == ["g-2"]
    assert res.expected_blast_radius_after == 0.123
    assert res.privilege_reduction_pct == 45.6
    assert spy.calls == [["g-1", "g-3"]]
    assert res.violations == ()


def test_valid_model_plan_is_accepted_but_numbers_still_come_from_engine(r1_inp: PlanInput) -> None:
    gem = FakeTransport(
        {
            "action": "revoke_grant",
            "params": {"grant_ids": ["g-2"]},
            "keep": ["g-1", "g-3"],
            "drop": ["g-2"],
            "rationale": "compute admin is unused",
            "confidence": 0.9,
            "expected_blast_radius_after": 0.0,  # ignored: not a model field
            "privilege_reduction_pct": 100.0,
        }
    )
    spy = SpyEngine()
    res = plan_remediation(r1_inp, make_client("gemini", gemini=gem), None, engine=spy.engine())
    assert res.meta.generated_by == "model" and res.proposed_by == "model"
    assert res.meta.model_id == "fake-gemini"
    assert res.output.action == "revoke_grant"
    assert res.expected_blast_radius_after == 0.123 and res.privilege_reduction_pct == 45.6
    assert spy.calls == [["g-1", "g-3"]]
    assert not hasattr(res.output, "expected_blast_radius_after")


def test_model_plan_violating_rules_is_replaced_by_deterministic_diff(r1_inp: PlanInput) -> None:
    gem = FakeTransport(
        {"action": "revoke_grant", "keep": ["g-1", "g-2", "g-3"], "drop": [], "confidence": 0.9}
    )
    spy = SpyEngine()
    res = plan_remediation(r1_inp, make_client("gemini", gemini=gem), None, engine=spy.engine())
    assert res.meta.generated_by == "template"
    assert res.proposed_by == "rule"
    assert "keep_not_used_or_read" in res.violations
    assert res.output.keep == ["g-1", "g-3"] and res.output.drop == ["g-2"]
    assert spy.calls == [["g-1", "g-3"]]


def test_model_action_outside_allowed_is_neutralised_then_plan_rejected(r1_inp: PlanInput) -> None:
    gem = FakeTransport(
        {"action": "delete_account", "keep": ["g-1", "g-3"], "drop": ["g-2"], "confidence": 0.9}
    )
    res = plan_remediation(r1_inp, make_client("gemini", gemini=gem), None, engine=SpyEngine().engine())
    # guard rewrote the action to no_action_recommended; a non-grant action with drops violates the engine rules
    assert res.meta.generated_by == "template"
    assert "non_grant_action_with_drop" in res.violations
    assert any(f.startswith("action_not_allowed") for f in res.meta.guard_flags)
    assert res.output.action in r1_inp.allowed_actions


def test_plan_cache_hit_is_reported(r1_inp: PlanInput) -> None:
    gem = FakeTransport(
        {"action": "revoke_grant", "keep": ["g-1", "g-3"], "drop": ["g-2"], "confidence": 0.9}
    )
    cache = InMemoryCacheStore()
    client = make_client("gemini", gemini=gem)
    first = plan_remediation(r1_inp, client, cache, engine=SpyEngine().engine())
    second = plan_remediation(r1_inp, client, cache, engine=SpyEngine().engine())
    assert first.meta.cached is False and second.meta.cached is True
    assert len(gem.calls) == 1


def test_plan_remediation_accepts_bare_compute_after_callable(r1_inp: PlanInput) -> None:
    """The brief's contract: `compute_after(keep_grant_ids) -> (blast_radius_after, reduction_pct)`."""
    spy = SpyEngine()
    res = plan_remediation(r1_inp, make_client("none"), None, compute_after=spy)
    assert res.expected_blast_radius_after == 0.123 and res.privilege_reduction_pct == 45.6
    assert spy.calls == [["g-1", "g-3"]]


def test_plan_remediation_requires_exactly_one_engine_source(r1_inp: PlanInput) -> None:
    spy = SpyEngine()
    with pytest.raises(ValueError, match="exactly one"):
        plan_remediation(r1_inp, make_client("none"), None)
    with pytest.raises(ValueError, match="exactly one"):
        plan_remediation(r1_inp, make_client("none"), None, compute_after=spy, engine=spy.engine())
    assert spy.calls == []


def test_proportional_engine_scales_blast_radius_with_kept_grants() -> None:
    engine = PlanEngine.proportional(0.8, 4)
    assert engine.compute_after(["a", "b"]) == (0.4, 50.0)
    assert engine.compute_after([]) == (0.0, 100.0)
    assert PlanEngine.proportional(0.8, 0).compute_after([]) == (0.8, 0.0)


def test_plan_as_dict_has_row_shape() -> None:
    res = PlanResult(
        output=PlanOutput(action="revoke_grant", keep=["a"], drop=["b"], rationale="r", confidence=0.5),
        expected_blast_radius_after=0.1,
        privilege_reduction_pct=50.0,
        meta=plan_remediation(
            _inp("R1", [_g("a")]), make_client("none"), None, engine=SpyEngine().engine()
        ).meta,
    )
    row = plan_as_dict(res)
    assert row["action"] == "revoke_grant"
    assert row["proposed_by"] == "rule"
    assert row["expected_blast_radius_after"] == 0.1
    assert row["privilege_reduction_pct"] == 50.0
    assert row["prompt_version"] == "plan-v1"


def test_end_to_end_from_estate_r3(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    inp = build_plan_input(r3_estate, r3_draft, None, rule_spec("R3"), as_of=AS_OF)
    res = plan_remediation(
        inp, make_client("none"), None, engine=PlanEngine.proportional(1.0, len(inp.grants))
    )
    assert res.output.action == "disable_identity"
    assert res.output.drop == ["g-001", "g-002", "g-003"]
    assert res.privilege_reduction_pct == 100.0
    assert res.expected_blast_radius_after == 0.0
