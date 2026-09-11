"""Executive-summary agent (SPEC §11.4). Pure apart from the injected LLM client.

Input: aggregate statistics only (counts per rule / department / severity, the
half-life table, top-3 headlines with names removed). Fallback: a static template
composed from the same counts.
"""

from __future__ import annotations

from dataclasses import dataclass

from athar.agents.cache import CacheStore
from athar.agents.inputs import SummaryInput, payload
from athar.agents.llm_client import TEMPLATE_MODEL_ID, LlmClient, TemplateFallback
from athar.agents.prompts import SUMMARY_PROMPT_VERSION, SUMMARY_SYSTEM
from athar.agents.schemas import AgentMeta, SummaryOutput
from athar.clock import month_label
from athar.config import APP_NAME
from athar.domain import SEVERITIES
from athar.drift.halflife import ALL_DEPARTMENTS
from athar.log import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class SummaryResult:
    output: SummaryOutput
    meta: AgentMeta


def _severity_clause(counts: dict[str, int]) -> str:
    parts = [f"{counts[s]} {s.lower()}" for s in reversed(SEVERITIES) if counts.get(s)]
    return ", ".join(parts) if parts else "none"


def _findings(count: int) -> str:
    return "finding" if count == 1 else "findings"


def template_summary(inp: SummaryInput) -> SummaryOutput:
    """Static template: same aggregates → same paragraph. Contains no identifiers or names."""
    total = sum(inp.counts_per_severity.values()) or sum(inp.counts_per_rule.values())
    when = month_label(inp.month) if inp.month >= 1 else "this month"
    sentences = [
        f"In {when}, {APP_NAME} holds {total} open access-governance {_findings(total)} for {inp.org_name} "
        f"({_severity_clause(inp.counts_per_severity)})."
    ]
    if inp.counts_per_department:
        dept, n = sorted(inp.counts_per_department.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        sentences.append(f"The most affected department is {dept} with {n} {_findings(n)}.")
    top_rules = sorted(inp.counts_per_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    if top_rules:
        names = [inp.rule_names.get(rid, rid) for rid, _ in top_rules]
        sentences.append("The most frequent issues are: " + "; ".join(names) + ".")
    # The estate-wide aggregate arrives as a row whose department is the literal "all"
    # (drift.halflife.halflife_overall). It is not a department and must not be listed as one.
    broken = sorted(
        {
            str(r.get("department"))
            for r in inp.halflife_table
            if r.get("label") == "Broken"
            and r.get("trigger") in (None, "all")
            and str(r.get("department")) != ALL_DEPARTMENTS
        }
    )
    if broken:
        sentences.append(
            "Access revocation is effectively broken in: "
            + ", ".join(broken)
            + " (grants are rarely removed)."
        )
    sentences.append(
        "Findings were produced by deterministic rules; this summary is a template and no language model was consulted."
    )
    themes = [inp.rule_names.get(rid, rid) for rid, _ in top_rules][:3]
    return SummaryOutput(summary_paragraph=" ".join(sentences), top_themes=themes)


def executive_summary(
    inp: SummaryInput,
    client: LlmClient,
    cache: CacheStore | None,
    *,
    regenerate: bool = False,
) -> SummaryResult:
    try:
        res = client.generate(
            SummaryOutput,
            system=SUMMARY_SYSTEM,
            user_payload=payload(inp),
            prompt_version=SUMMARY_PROMPT_VERSION,
            cache=cache,
            regenerate=regenerate,
            allowed_actions=(),
        )
    except TemplateFallback as exc:
        log.info("summary: template fallback", extra={"month": inp.month, "why": exc.reasons})
        return SummaryResult(
            output=template_summary(inp),
            meta=AgentMeta(
                provider="none",
                model_id=TEMPLATE_MODEL_ID,
                prompt_version=SUMMARY_PROMPT_VERSION,
                cached=False,
                generated_by="template",
            ),
        )
    assert isinstance(res.output, SummaryOutput)
    return SummaryResult(
        output=res.output,
        meta=AgentMeta(
            provider=res.provider,
            model_id=res.model_id,
            prompt_version=res.prompt_version,
            cached=res.cached,
            generated_by=res.generated_by,
            guard_flags=list(res.guard_flags),
        ),
    )
