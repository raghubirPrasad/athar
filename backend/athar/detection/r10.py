"""R10 Unowned principal (SPEC §6, §7). Medium.

The linker fell through every rule (`link_method=unlinked`). The normaliser gives such
principals a synthetic identity `unlinked:<cloud>:<principal_ref>`; the finding sits on
that identity and cites the principal row plus any grants it holds.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, PrincipalRow, Thresholds

RULE_ID = "R10"
SEVERITY = "Medium"
LINK_ATTEMPTS: tuple[str, ...] = ("hr_email", "entra_directory", "aws_username", "sa_project", "tag_owner")


def synthetic_identity_id(principal: PrincipalRow) -> str:
    return principal.identity_id or f"unlinked:{principal.cloud}:{principal.principal_ref}"


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    by_identity: dict[str, list[PrincipalRow]] = {}
    for principal in sorted(estate.principals.values(), key=lambda p: p.principal_ref):
        if principal.link_method == "unlinked":
            by_identity.setdefault(synthetic_identity_id(principal), []).append(principal)

    drafts: list[FindingDraft] = []
    for identity_id in sorted(by_identity):
        principals = by_identity[identity_id]
        refs = {p.principal_ref for p in principals}
        grants = {g.grant_id: g for g in common.active_allow_grants(estate, identity_id)}
        grants.update((g.grant_id, g) for g in estate.grants if g.active and g.principal_ref in refs)
        cited = sorted(grants.values(), key=lambda g: g.grant_id)
        first = principals[0]
        facts = common.common_facts(
            estate, identity_id, principal=first, extra_clouds={p.cloud for p in principals}
        )
        facts.update(
            cloud=first.cloud,
            principal_ref=first.principal_ref,
            principal_type=first.principal_type,
            link_attempts=list(LINK_ATTEMPTS),
            grant_ids=common.grant_ids(cited),
        )
        evidence = [
            *(
                EvidenceRef("principal", p.principal_ref, f"{p.cloud} {p.principal_type} unlinked")
                for p in principals
            ),
            *common.grant_refs(cited),
        ]
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
        name="Unowned principal",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=(),
        control_refs=common.verify("ISO 27001:2022 A.5.16"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="A cloud principal that could not be linked to any HR identity or project.",
    )
)
