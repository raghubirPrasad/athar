"""R0 Unmapped permission (SPEC §5.3, §7). Low.

A mapping miss becomes a finding, never a crash: any active grant whose verb is
`unknown` is cited so the mapping YAML can be extended.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, Thresholds

RULE_ID = "R0"
SEVERITY = "Low"


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in common.identity_ids(estate):
        # Effect is irrelevant here: an unmapped deny is as much a mapping miss as an allow.
        unmapped = sorted(
            (g for g in estate.grants_for(identity_id) if g.verb == "unknown"),
            key=lambda g: g.grant_id,
        )
        if not unmapped:
            continue
        first = unmapped[0]
        # The action that produced `verb=unknown`, not the statement's first action: a policy may
        # mix `s3:GetObject` (mapped) with `ce:Frobnicate` (not), and only the latter names the
        # mapping entry that would fix this finding.
        actions = common.unmapped_actions(first.raw_snippet)
        facts = common.common_facts(estate, identity_id)
        facts.update(
            cloud=first.cloud,
            raw_action=actions[0] if actions else "unknown",
            principal_ref=first.principal_ref,
            grant_ids=common.grant_ids(unmapped),
        )
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                common.grant_refs(unmapped),
                common.causal_event_ids(estate, identity_id, unmapped),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Unmapped permission",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=(),
        control_refs=(),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="A provider action or role the normaliser could not map to a canonical verb.",
    )
)
