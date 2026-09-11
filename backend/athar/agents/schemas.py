"""Output schemas for agent responses (SPEC §11.2, §11.4).

Every LLM response is validated against one of these models before the guard
(`agents/guard.py`) runs. `PlanOutput` deliberately has no
`expected_blast_radius_after` / `privilege_reduction_pct` fields: the engine
recomputes those (SPEC §11.4), they are never trusted from the model.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

GeneratedBy = Literal["model", "template"]


class InvestigateOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hypothesis: str = ""
    is_expected_for_role: bool = False
    evidence_cited: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    recommended_action: str = "no_action_recommended"
    rationale: str = ""


class PlanOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str = "no_action_recommended"
    params: dict[str, Any] = Field(default_factory=dict)
    keep: list[str] = Field(default_factory=list)
    drop: list[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: float = 0.0


class SummaryOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    summary_paragraph: str = ""
    top_themes: list[str] = Field(default_factory=list)  # capped at 3 by guard.validate_output


class AgentMeta(BaseModel):
    """Provenance attached to every agent result (SPEC §11.2: model_id + prompt_version)."""

    provider: str
    model_id: str
    prompt_version: str
    cached: bool
    generated_by: GeneratedBy
    guard_flags: list[str] = Field(default_factory=list)
