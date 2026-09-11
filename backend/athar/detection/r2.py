"""R2 Dormant access (SPEC §7). Medium.

No activity in any category for ≥ `dormant_days` before the snapshot's month-end while
any active grant with verb ∉ {read} exists; no unexpired `dr-failover` register entry
(SPEC §4.3). Thresholds come from the `Thresholds` argument only.
"""

from __future__ import annotations

from athar.clock import days_between
from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, Thresholds

RULE_ID = "R2"
SEVERITY = "Medium"
EXCEPTION_TYPES: tuple[str, ...] = ("dr-failover",)
# SPEC? "verb ∉ {read}" — an `unknown` verb is not known to be non-read, so it is not
# counted as standing privilege here; R0 already cites it.
_NON_PRIVILEGE_VERBS: frozenset[str] = frozenset({"read", "unknown"})


def _dormant_days(estate: EstateView, identity_id: str) -> int | None:
    """Days since last activity, or days present when there is no activity at all."""
    last = estate.last_activity(identity_id)
    if last is not None:
        return days_between(last, estate.as_of)
    return common.present_days(estate, identity_id)


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in sorted(estate.identities):
        cited = [
            g for g in common.active_allow_grants(estate, identity_id) if g.verb not in _NON_PRIVILEGE_VERBS
        ]
        if not cited:
            continue
        idle = _dormant_days(estate, identity_id)
        if idle is None or idle < thresholds.dormant_days:
            continue
        suppressed, expired_on, exc_evidence = common.register_exception(
            estate, identity_id, *EXCEPTION_TYPES
        )
        if suppressed:
            continue
        last = estate.last_activity(identity_id)
        evidence: list[EvidenceRef] = [*common.grant_refs(cited), *exc_evidence]
        activity_evidence = common.activity_refs(estate, identity_id)
        if activity_evidence:
            evidence.extend(activity_evidence)
        else:
            evidence.append(EvidenceRef("identity", identity_id, f"no activity recorded in {idle} days"))
        facts = common.common_facts(estate, identity_id)
        facts.update(
            dormant_days=idle,
            last_activity_at=common.iso(last),
            clouds_with_write=sorted({g.cloud for g in cited}),
            grant_ids=common.grant_ids(cited),
            exception_expired_on=expired_on,
        )
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                evidence,
                common.causal_event_ids(estate, identity_id, cited),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Dormant access",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1078.004"),
        control_refs=common.verify("ISO 27001:2022 A.5.18"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="Standing non-read access that has not been used within the dormancy window.",
    )
)
