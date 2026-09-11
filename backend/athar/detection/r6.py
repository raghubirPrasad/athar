"""R6 Stale credential (SPEC §7). Medium; High when an SA key is older than 365 days.

An active credential whose `last_rotated_at` (fallback `created_at`) is older than
`stale_key_days` at the snapshot's month-end. One draft per identity citing every stale
credential; the facts describe the worst one.
"""

from __future__ import annotations

from athar.clock import days_between
from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import CredentialRow, EstateView, Thresholds

RULE_ID = "R6"
SEVERITY = "Medium"
SEVERITY_SA_KEY = "High"
SA_KEY_HIGH_DAYS = 365


def _age_days(cred: CredentialRow, estate: EstateView) -> int | None:
    reference = cred.last_rotated_at or cred.created_at
    return days_between(reference, estate.as_of) if reference else None


def _is_high(kind: str, age: int) -> bool:
    return kind == "sa_key" and age > SA_KEY_HIGH_DAYS


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in common.identity_ids(estate):
        stale: list[tuple[CredentialRow, int]] = []
        for cred in sorted(estate.credentials_for(identity_id), key=lambda c: c.credential_ref):
            if not cred.active:
                continue
            age = _age_days(cred, estate)
            if age is not None and age > thresholds.stale_key_days:
                stale.append((cred, age))
        if not stale:
            continue
        # The credential that drives the severity comes first, then the oldest.
        worst, worst_age = sorted(
            stale, key=lambda t: (not _is_high(t[0].kind, t[1]), -t[1], t[0].credential_ref)
        )[0]
        facts = common.common_facts(estate, identity_id, extra_clouds={c.cloud for c, _ in stale})
        facts.update(
            credential_ref=worst.credential_ref,
            cloud=worst.cloud,
            kind=worst.kind,
            age_days=worst_age,
            last_rotated_at=common.iso(worst.last_rotated_at or worst.created_at),
            threshold_days=thresholds.stale_key_days,
            credential_refs=sorted(c.credential_ref for c, _ in stale),
        )
        evidence = [
            EvidenceRef("credential", c.credential_ref, f"{c.cloud} {c.kind} age {age} days")
            for c, age in stale
        ]
        causal = common.causal_event_ids_for_refs(
            estate, identity_id, "credential_ref", (c.credential_ref for c, _ in stale)
        )
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY_SA_KEY if _is_high(worst.kind, worst_age) else SEVERITY,
                evidence,
                causal,
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Stale credential",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1098.001"),
        control_refs=common.verify("ISO 27001:2022 A.5.17"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="An active key or password not rotated within the stale-credential window.",
    )
)
