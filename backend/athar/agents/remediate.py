"""Plan-remediation agent (SPEC §11.4). Pure apart from the injected LLM client.

The model may propose `{action, params, keep, drop, rationale, confidence}`; the
engine validates it against the rule engine's facts and recomputes
`expected_blast_radius_after` / `privilege_reduction_pct` through the caller's
`compute_after` (the scoring lane owns the graph). Any violation — action outside
`allowed_actions`, `drop ⊄ grants`, `keep ⊄ used-in-90-days ∪ read`, a grant left
unaccounted for — replaces the model plan with the deterministic least-privilege
diff. R3/departed → `disable_identity` dropping everything; R6 →
`rotate_or_disable_credential` with `{credential_ref}`.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from athar.agents.cache import CacheStore
from athar.agents.guard import unwrap
from athar.agents.inputs import ActivityFacts, GrantFacts, PlanInput, citation_values, payload
from athar.agents.llm_client import TEMPLATE_MODEL_ID, LlmClient, TemplateFallback
from athar.agents.prompts import PLAN_PROMPT_VERSION, PLAN_SYSTEM
from athar.agents.schemas import AgentMeta, PlanOutput
from athar.log import get_logger

log = get_logger(__name__)

TEMPLATE_CONFIDENCE = 0.6
READ_VERBS: frozenset[str] = frozenset({"read"})
GRANT_CHANGING_ACTIONS: frozenset[str] = frozenset(
    {"revoke_grant", "downgrade_to_least_privilege", "remove_cloud_access", "disable_identity"}
)
LEAST_PRIVILEGE_PREFERENCE: tuple[str, ...] = (
    "downgrade_to_least_privilege",
    "revoke_grant",
    "remove_cloud_access",
)
NO_CHANGE_PREFERENCE: tuple[str, ...] = ("no_action_recommended", "tag_as_exception")

ComputeAfter = Callable[[Sequence[str]], tuple[float, float]]
"""`compute_after(keep_grant_ids) -> (expected_blast_radius_after, privilege_reduction_pct)`."""


@dataclass(frozen=True)
class PlanEngine:
    """Deterministic recomputation of the after-state; supplied by the caller (scoring lane)."""

    compute_after: ComputeAfter

    @staticmethod
    def proportional(current_blast_radius: float, total_grants: int) -> PlanEngine:
        """Fallback engine when no graph is available: blast radius scales with kept grants."""

        def _after(keep: Sequence[str]) -> tuple[float, float]:
            if total_grants <= 0:
                return (current_blast_radius, 0.0)
            kept = len(set(keep))
            share = min(1.0, max(0.0, kept / total_grants))
            return (round(current_blast_radius * share, 6), round((1.0 - share) * 100.0, 2))

        return PlanEngine(compute_after=_after)


@dataclass(frozen=True)
class PlanResult:
    output: PlanOutput
    expected_blast_radius_after: float
    privilege_reduction_pct: float
    meta: AgentMeta
    violations: tuple[str, ...] = ()

    @property
    def proposed_by(self) -> str:
        """Value for `remediation_plans.proposed_by` (SPEC §11.5)."""
        return "model" if self.meta.generated_by == "model" else "rule"


# ---------------------------------------------------------------------------
# Deterministic plan
# ---------------------------------------------------------------------------


def used_pairs(activity_90d: Sequence[ActivityFacts]) -> set[tuple[str, str]]:
    return {(a.cloud, a.service_category) for a in activity_90d if a.operation_count > 0}


def least_privilege_diff(
    grants: Sequence[GrantFacts],
    activity_90d: Sequence[ActivityFacts],
    cited: Sequence[str] = (),
) -> tuple[list[str], list[str]]:
    """Keep grants whose (cloud, category) saw activity in the window or whose verb is read; drop the rest.

    `cited` are the grants the finding itself is about — the administrative grant behind R1, the two
    halves of an R5 combination. Those are dropped whether or not they were used recently: keeping a
    grant because someone exercised it is exactly the wrong answer when the grant is the finding.
    Everything else follows the activity window.
    """
    used = used_pairs(activity_90d)
    flagged = {str(c) for c in cited}
    keep: list[str] = []
    drop: list[str] = []
    for g in sorted(grants, key=lambda x: x.grant_id):
        if g.grant_id in flagged:
            drop.append(g.grant_id)
        elif (g.cloud, g.service_category) in used or g.verb in READ_VERBS:
            keep.append(g.grant_id)
        else:
            drop.append(g.grant_id)
    return keep, drop


def cited_grant_ids(inp: PlanInput) -> list[str]:
    """Grant ids the rule cited, from the finding's own facts (`grant_ids`, and R5's path)."""
    known = {g.grant_id for g in inp.grants}
    out: list[str] = []
    raw = inp.facts.get("grant_ids")
    if isinstance(raw, list):
        out.extend(str(x) for x in raw)
    path = inp.facts.get("path")
    if isinstance(path, list):
        for edge in path:
            if isinstance(edge, dict) and edge.get("grant_id"):
                out.append(str(edge["grant_id"]))
    return sorted({g for g in out if g in known})


def _pick(preferred: Sequence[str], allowed: Sequence[str]) -> str:
    for candidate in preferred:
        if candidate in allowed:
            return candidate
    return allowed[0] if allowed else "no_action_recommended"


def deterministic_plan(inp: PlanInput) -> PlanOutput:
    """Rule-derived plan: same input → same plan; never echoes provider text."""
    all_ids = [g.grant_id for g in inp.grants]
    allowed = inp.allowed_actions
    rule_id = inp.finding.rule_id
    departed = inp.identity.employment_status == "departed"

    if rule_id == "R3" or (departed and "disable_identity" in allowed):
        action = _pick(("disable_identity", "remove_cloud_access", "revoke_grant"), allowed)
        return PlanOutput(
            action=action,
            params={"identity_id": inp.identity.identity_id},
            keep=[],
            drop=list(all_ids),
            rationale=(
                "Deterministic plan: the identity is departed or orphaned, so every grant is dropped and "
                "the identity is disabled."
                if action == "disable_identity"
                else "Deterministic plan: the identity is orphaned, so every grant is dropped."
            ),
            confidence=TEMPLATE_CONFIDENCE,
        )

    if rule_id == "R6":
        # The finding's own credential, and the identity's active ones, reach the prompt wrapped
        # (SPEC §11.3); the plan quotes the bare ref an approver has to act on.
        cred = unwrap(inp.facts.get("credential_ref"))
        refs = citation_values(inp.credential_refs)
        credential_ref = (
            str(cred) if isinstance(cred, str) and cred in refs else (refs[0] if refs else str(cred or ""))
        )
        action = _pick(("rotate_or_disable_credential", "disable_identity"), allowed)
        drop = list(all_ids) if action == "disable_identity" else []
        keep = [] if action == "disable_identity" else list(all_ids)
        return PlanOutput(
            action=action,
            params={"credential_ref": credential_ref},
            keep=keep,
            drop=drop,
            rationale="Deterministic plan: the stale credential is rotated or disabled; grants are unchanged.",
            confidence=TEMPLATE_CONFIDENCE,
        )

    cited = cited_grant_ids(inp)
    keep, drop = least_privilege_diff(inp.grants, inp.activity_90d, cited)
    if drop:
        action = _pick(LEAST_PRIVILEGE_PREFERENCE, allowed)
        flagged = len([g for g in drop if g in set(cited)])
        rationale = (
            f"Deterministic least-privilege diff: {flagged} grant(s) cited by {rule_id} are dropped "
            f"regardless of recent use, along with {len(drop) - flagged} grant(s) with no activity in "
            f"the last 90 days and a non-read verb; {len(keep)} used or read-only grant(s) are kept."
            if flagged
            else (
                f"Deterministic least-privilege diff: {len(drop)} grant(s) with no activity in the last "
                f"90 days and a non-read verb are dropped; {len(keep)} used or read-only grant(s) are kept."
            )
        )
    else:
        action = _pick(NO_CHANGE_PREFERENCE, allowed)
        rationale = (
            "Deterministic least-privilege diff: every grant was used in the last 90 days or is read-only."
        )
    return PlanOutput(
        action=action,
        params={"grant_ids": list(drop)} if drop else {},
        keep=keep,
        drop=drop,
        rationale=rationale,
        confidence=TEMPLATE_CONFIDENCE,
    )


# ---------------------------------------------------------------------------
# Validation of a model plan
# ---------------------------------------------------------------------------


def validate_plan(plan: PlanOutput, inp: PlanInput) -> list[str]:
    """Violations of the rule-engine constraints (empty list == acceptable)."""
    violations: list[str] = []
    all_ids = {g.grant_id for g in inp.grants}
    keep, drop = set(plan.keep), set(plan.drop)
    used = used_pairs(inp.activity_90d)
    keepable = {
        g.grant_id for g in inp.grants if (g.cloud, g.service_category) in used or g.verb in READ_VERBS
    }

    if plan.action not in inp.allowed_actions:
        violations.append("action_not_allowed")
    if not drop <= all_ids:
        violations.append("drop_not_subset_of_grants")
    if not keep <= all_ids:
        violations.append("keep_not_subset_of_grants")
    if keep & drop:
        violations.append("keep_drop_overlap")
    if keep | drop != all_ids:
        violations.append("grants_unaccounted")  # SPEC? — stricter than §11.4; every grant must be placed

    if plan.action == "disable_identity":
        if keep or drop != all_ids:
            violations.append("disable_identity_must_drop_all")
    elif plan.action in GRANT_CHANGING_ACTIONS:
        if not keep <= keepable:
            violations.append("keep_not_used_or_read")
    else:
        # SPEC? — non-grant actions (rotate credential, exception, no action) must not change grants
        if drop:
            violations.append("non_grant_action_with_drop")
        if plan.action == "rotate_or_disable_credential":
            ref = plan.params.get("credential_ref")
            if not isinstance(ref, str) or ref not in citation_values(inp.credential_refs):
                violations.append("credential_ref_not_in_input")
    return violations


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


def _finish(output: PlanOutput, engine: PlanEngine, meta: AgentMeta, violations: Sequence[str]) -> PlanResult:
    after, reduction = engine.compute_after(list(output.keep))
    return PlanResult(
        output=output,
        expected_blast_radius_after=float(after),
        privilege_reduction_pct=float(reduction),
        meta=meta,
        violations=tuple(violations),
    )


def _template_meta(flags: Sequence[str] = ()) -> AgentMeta:
    return AgentMeta(
        provider="none",
        model_id=TEMPLATE_MODEL_ID,
        prompt_version=PLAN_PROMPT_VERSION,
        cached=False,
        generated_by="template",
        guard_flags=list(flags),
    )


def plan_remediation(
    inp: PlanInput,
    client: LlmClient,
    cache: CacheStore | None,
    *,
    compute_after: ComputeAfter | None = None,
    engine: PlanEngine | None = None,
    regenerate: bool = False,
) -> PlanResult:
    """Propose a plan; `compute_after(keep_grant_ids) -> (blast_radius_after, privilege_reduction_pct)`
    is the ONLY source of those two numbers (SPEC §11.4). Pass either `compute_after` or an `engine`
    wrapping it, never both."""
    if (compute_after is None) == (engine is None):
        raise ValueError("plan_remediation needs exactly one of compute_after= or engine=")
    if engine is None:
        assert compute_after is not None  # narrowed by the check above
        engine = PlanEngine(compute_after=compute_after)
    try:
        res = client.generate(
            PlanOutput,
            system=PLAN_SYSTEM,
            user_payload=payload(inp),
            prompt_version=PLAN_PROMPT_VERSION,
            cache=cache,
            regenerate=regenerate,
            allowed_actions=inp.allowed_actions,
        )
    except TemplateFallback as exc:
        log.info(
            "plan: template fallback", extra={"finding_key": inp.finding.finding_key, "why": exc.reasons}
        )
        return _finish(deterministic_plan(inp), engine, _template_meta(), ())

    model_plan = res.output
    assert isinstance(model_plan, PlanOutput)
    violations = validate_plan(model_plan, inp)
    if violations:
        log.info(
            "plan: model plan rejected, using deterministic diff",
            extra={"finding_key": inp.finding.finding_key, "violations": violations},
        )
        return _finish(deterministic_plan(inp), engine, _template_meta(res.guard_flags), violations)

    meta = AgentMeta(
        provider=res.provider,
        model_id=res.model_id,
        prompt_version=res.prompt_version,
        cached=res.cached,
        generated_by=res.generated_by,
        guard_flags=list(res.guard_flags),
    )
    return _finish(model_plan, engine, meta, ())


def plan_as_dict(result: PlanResult) -> dict[str, Any]:
    """Row-shaped view for `remediation_plans` (SPEC §11.5) including the engine's figures."""
    return {
        "action": result.output.action,
        "params": dict(result.output.params),
        "keep": list(result.output.keep),
        "drop": list(result.output.drop),
        "expected_blast_radius_after": result.expected_blast_radius_after,
        "privilege_reduction_pct": result.privilege_reduction_pct,
        "rationale": result.output.rationale,
        "confidence": result.output.confidence,
        "proposed_by": result.proposed_by,
        "model_id": result.meta.model_id,
        "prompt_version": result.meta.prompt_version,
        "violations": list(result.violations),
    }
