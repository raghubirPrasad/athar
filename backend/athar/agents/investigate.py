"""Investigate agent (SPEC §11.4). Pure apart from the injected LLM client.

Input: finding facts, causal history, department baseline, `allowed_actions`.
Output: `InvestigateOutput`. Fallback: a deterministic template built from the
rule id and the causal history (kinds, triggers and months only — never
provider free text). The template chooses the first allowed action, which the
rule registry orders by preference.
"""

from __future__ import annotations

from dataclasses import dataclass

from athar.agents.cache import CacheStore
from athar.agents.guard import NO_ACTION
from athar.agents.inputs import InvestigateInput, citation_values, payload
from athar.agents.llm_client import TEMPLATE_MODEL_ID, LlmClient, TemplateFallback
from athar.agents.prompts import INVESTIGATE_PROMPT_VERSION, INVESTIGATE_SYSTEM
from athar.agents.schemas import AgentMeta, InvestigateOutput
from athar.clock import month_label
from athar.log import get_logger

log = get_logger(__name__)

TEMPLATE_CONFIDENCE = 0.5

# Deterministic hypotheses per rule; phrased from canonical facts only.
RULE_HYPOTHESES: dict[str, str] = {
    "R0": "The provider action could not be mapped to the canonical model; the true privilege is unknown.",
    "R1": "The identity holds unrestricted or wildcard privilege that exceeds what its role requires.",
    "R2": "Access has gone unused for longer than the dormancy threshold and is likely no longer needed.",
    "R3": "Access is consistent with a departed employee or retired project whose grants were never revoked.",
    "R4": "The identity holds superuser-level control in more than one cloud, concentrating risk.",
    "R5": "The identity can raise its own privilege through a toxic combination of grants.",
    "R6": "A credential has not been rotated within policy and may be exposed or forgotten.",
    "R7": "The identity holds far more access than its departmental peers, suggesting accumulation.",
    "R8": "Access reaches resources outside the approved regions, drifting from residency policy.",
    "R9": "A privileged human identity operates without enforced MFA.",
    "R10": "A cloud principal could not be linked to any known identity and is unowned.",
}
DEFAULT_HYPOTHESIS = "Access exceeds what the identity's role and history justify."


@dataclass(frozen=True)
class InvestigateResult:
    output: InvestigateOutput
    meta: AgentMeta


def _history_sentence(inp: InvestigateInput) -> str:
    steps = inp.causal_history
    if not steps:
        return "No recorded access-change event precedes this finding."
    parts: list[str] = []
    for step in steps[-3:]:
        kind = str(step.get("kind", "event")).replace("_", " ")
        trigger = str(step.get("trigger", "unknown")).replace("_", " ")
        month = step.get("month")
        when = month_label(int(month)) if isinstance(month, int) and month >= 1 else "an unknown month"
        parts.append(f"{kind} ({trigger}) in {when}")
    return "Preceded by: " + "; ".join(parts) + "."


def default_action(inp: InvestigateInput) -> str:
    """The rule's preferred action: `allowed_actions` is ordered by preference in the registry."""
    return inp.allowed_actions[0] if inp.allowed_actions else NO_ACTION


def template_investigate(inp: InvestigateInput) -> InvestigateOutput:
    """Deterministic fallback: same input → same output; no untrusted text is echoed."""
    rule_id = inp.finding.rule_id
    hypothesis = RULE_HYPOTHESES.get(rule_id, DEFAULT_HYPOTHESIS)
    if rule_id == "R3" and inp.identity.employment_status == "departed":
        hypothesis = "Access is consistent with a departed employee whose grants were never revoked."
    action = default_action(inp)
    return InvestigateOutput(
        hypothesis=f"{hypothesis} {_history_sentence(inp)}",
        is_expected_for_role=False,
        evidence_cited=citation_values(inp.evidence_refs),
        confidence=TEMPLATE_CONFIDENCE,
        recommended_action=action,
        rationale=(
            f"Template fallback derived from rule {rule_id} ({inp.finding.rule_name}) facts and "
            f"{len(inp.causal_history)} causal event(s); no language model was consulted."
        ),
    )


def investigate(
    inp: InvestigateInput,
    client: LlmClient,
    cache: CacheStore | None,
    *,
    regenerate: bool = False,
) -> InvestigateResult:
    try:
        res = client.generate(
            InvestigateOutput,
            system=INVESTIGATE_SYSTEM,
            user_payload=payload(inp),
            prompt_version=INVESTIGATE_PROMPT_VERSION,
            cache=cache,
            regenerate=regenerate,
            allowed_actions=inp.allowed_actions,
        )
    except TemplateFallback as exc:
        log.info(
            "investigate: template fallback",
            extra={"finding_key": inp.finding.finding_key, "why": exc.reasons},
        )
        return InvestigateResult(
            output=template_investigate(inp),
            meta=AgentMeta(
                provider="none",
                model_id=TEMPLATE_MODEL_ID,
                prompt_version=INVESTIGATE_PROMPT_VERSION,
                cached=False,
                generated_by="template",
            ),
        )
    assert isinstance(res.output, InvestigateOutput)
    output, flags = res.output, list(res.guard_flags)
    if output.recommended_action not in inp.allowed_actions:
        # The guard neutralised an out-of-vocabulary action to "no_action_recommended"; when even that
        # sentinel is outside this rule's set (e.g. R3), the rule's preferred action stands in for it.
        # SPEC §11.3: recommended_action ∈ allowed_actions — the rule engine decides, never the model.
        output = output.model_copy(update={"recommended_action": default_action(inp)})
        flags.append("action_substituted_by_rule")
    return InvestigateResult(
        output=output,
        meta=AgentMeta(
            provider=res.provider,
            model_id=res.model_id,
            prompt_version=res.prompt_version,
            cached=res.cached,
            generated_by=res.generated_by,
            guard_flags=flags,
        ),
    )
