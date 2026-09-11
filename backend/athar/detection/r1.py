"""R1 Wildcard / admin privilege (SPEC §7). High.

`verb=admin` at `scope_level ≥ project`, or a grant whose raw snippet still shows an
unexpanded full wildcard, with no unexpired `break-glass` / `approved-privileged-role`
entry in the governance exception register (SPEC §4.3). An expired entry does not
suppress: the rule fires and `exception_expired_on` carries the date.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, GrantRow, Thresholds, scope_at_least

RULE_ID = "R1"
SEVERITY = "High"
EXCEPTION_TYPES: tuple[str, ...] = ("break-glass", "approved-privileged-role")


def _is_privileged(grant: GrantRow) -> bool:
    return (grant.verb == "admin" and scope_at_least(grant.scope_level, "project")) or common.has_wildcard(
        grant
    )


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in common.identity_ids(estate):
        cited = [g for g in common.active_allow_grants(estate, identity_id) if _is_privileged(g)]
        if not cited:
            continue
        suppressed, expired_on, exc_evidence = common.register_exception(
            estate, identity_id, *EXCEPTION_TYPES
        )
        if suppressed:
            continue
        worst = common.worst_grant(cited)
        facts = common.common_facts(estate, identity_id)
        facts.update(
            cloud=worst.cloud,
            scope_level=worst.scope_level,
            scope_ref=worst.scope_ref,
            granted_via=worst.granted_via,
            grant_ids=common.grant_ids(cited),
            wildcard=any(common.has_wildcard(g) for g in cited),
            exception_expired_on=expired_on,
        )
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                [*common.grant_refs(cited), *exc_evidence],
                common.causal_event_ids(estate, identity_id, cited, "incident_response"),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Wildcard / admin privilege",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1078.004"),
        control_refs=common.verify("UAE IA T5", "ISO 27001:2022 A.5.15", "ISO 27001:2022 A.5.18"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="Administrative or wildcard privilege at project scope or above without a register entry.",
    )
)
