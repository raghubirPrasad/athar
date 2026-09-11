"""R8 Data-residency drift (SPEC §7). High.

Any active grant on a `sensitivity=high` resource whose region is not in
`thresholds.approved_regions`. A grant is matched to resource rows by exact
`scope_ref`, by prefix for resource-level scopes, or by `project_ref` for project-level
scopes. Org/global scopes are not matched (R1 covers them). The region is the resource
row's; when the row carries none, the grant's own `region` stands in.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, GrantRow, ResourceRow, Thresholds

RULE_ID = "R8"
SEVERITY = "High"


def _resources_for(estate: EstateView, grant: GrantRow) -> list[ResourceRow]:
    exact = estate.resources.get(grant.scope_ref)
    if exact is not None and exact.cloud == grant.cloud:
        return [exact]
    same_cloud = sorted(
        (r for r in estate.resources.values() if r.cloud == grant.cloud), key=lambda r: r.resource_ref
    )
    if grant.scope_level == "resource":
        stem = grant.scope_ref.rstrip("*").rstrip("/")
        if not stem:
            return []
        return [r for r in same_cloud if r.resource_ref.startswith(stem) or stem.startswith(r.resource_ref)]
    if grant.scope_level == "project":
        return [
            r for r in same_cloud if common.project_ref_matches(grant.cloud, grant.scope_ref, r.project_ref)
        ]
    return []


def _region_of(grant: GrantRow, res: ResourceRow) -> str | None:
    return res.region or grant.region


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    approved = set(thresholds.approved_regions)
    drafts: list[FindingDraft] = []
    for identity_id in common.identity_ids(estate):
        hits: list[tuple[GrantRow, ResourceRow]] = []
        for grant in common.active_allow_grants(estate, identity_id):
            # SPEC? without a resource row the sensitivity is unknown, so grant.region alone
            # is not enough to fire ("evidence or it did not fire").
            for res in _resources_for(estate, grant):
                region = _region_of(grant, res)
                if res.sensitivity == "high" and region and region not in approved:
                    hits.append((grant, res))
        if not hits:
            continue
        first_grant, first_res = hits[0]
        facts = common.common_facts(estate, identity_id)
        facts.update(
            cloud=first_grant.cloud,
            region=_region_of(first_grant, first_res),
            approved_regions=sorted(approved),
            resource_ref=first_res.resource_ref,
            resource_sensitivity=first_res.sensitivity,
            grant_ids=common.grant_ids(g for g, _ in hits),
            resource_refs=sorted({r.resource_ref for _, r in hits}),
        )
        cited = list({g.grant_id: g for g, _ in hits}.values())
        evidence = [
            *common.grant_refs(cited),
            *(
                EvidenceRef(
                    "resource", r.resource_ref, f"{r.cloud} {_region_of(g, r)} sensitivity={r.sensitivity}"
                )
                for g, r in hits
            ),
        ]
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                evidence,
                common.causal_event_ids(estate, identity_id, cited, "region_drift"),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Data-residency drift",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=(),
        control_refs=common.verify(
            "UAE IA data residency", "DESC ISR data residency", "ISO 27001:2022 A.5.14"
        ),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="Access to a high-sensitivity resource that lives outside the approved regions.",
    )
)
