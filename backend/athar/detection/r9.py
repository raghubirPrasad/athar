"""R9 Privileged human without MFA (SPEC §7). High.

`identity_type=human` ∧ any active `admin | grant | impersonate` grant ∧ `mfa_enforced=false`.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, Thresholds

RULE_ID = "R9"
SEVERITY = "High"
PRIVILEGED_VERBS: frozenset[str] = frozenset({"admin", "grant", "impersonate"})


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in sorted(estate.identities):
        row = estate.identities[identity_id]
        if row.identity_type != "human" or row.mfa_enforced:
            continue
        cited = [g for g in common.active_allow_grants(estate, identity_id) if g.verb in PRIVILEGED_VERBS]
        if not cited:
            continue
        lapse_events = common.events_of_kind(estate, identity_id, "mfa_lapse")
        facts = common.common_facts(estate, identity_id)
        facts.update(
            privileged_verbs=sorted({g.verb for g in cited}),
            clouds_privileged=sorted({g.cloud for g in cited}),
            grant_ids=common.grant_ids(cited),
        )
        evidence = [
            *common.grant_refs(cited),
            *common.event_refs(lapse_events),
            EvidenceRef("identity", identity_id, "mfa_enforced=false"),
        ]
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                evidence,
                common.causal_event_ids(estate, identity_id, cited, "mfa_lapse"),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Privileged human without MFA",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1078.004", "T1556"),
        control_refs=common.verify("ISO 27001:2022 A.5.17", "ISO 27001:2022 A.8.5"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="A person holding admin, grant or impersonate rights whose MFA is not enforced.",
    )
)
