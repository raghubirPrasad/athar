"""Rule catalogue (SPEC §7). Static metadata, so it needs no repository and no database.

The Findings, Identities and Evaluation pages need rule ids with their names, severities and
control references before any finding has loaded; without this endpoint the frontend would have
to keep its own copy of the rule table and drift from the engine.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.problem import problem_responses
from athar.api.schemas import RuleOut
from athar.detection.registry import all_rules
from athar.narrative import rule_summary
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/rules", tags=["rules"], dependencies=[Depends(require_viewer)])


@router.get("", response_model=list[RuleOut], responses=problem_responses(401, 403))
def list_rules() -> list[RuleOut]:
    """Every registered rule, in id order. ATT&CK and control identifiers keep their (verify) marks."""
    return [
        RuleOut(
            rule_id=spec.id,
            name=spec.name,
            severity=spec.severity,
            version=spec.version,
            summary=rule_summary(spec.id),
            attack_techniques=list(spec.attack_techniques),
            control_refs=list(spec.control_refs),
            allowed_actions=list(spec.allowed_actions),
        )
        for spec in all_rules()
    ]
