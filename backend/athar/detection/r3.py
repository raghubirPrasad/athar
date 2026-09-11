"""R3 Orphaned identity (SPEC §7). Critical.

A human with HR `employment_status=departed` for ≥ 1 month who still holds any active
grant (`orphan_kind=departed`), or a service identity whose project in the registry has
`status=retired` (`orphan_kind=retired_project`).
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, GrantRow, IdentityRow, ProjectRow, Thresholds

RULE_ID = "R3"
SEVERITY = "Critical"
_SVC_PREFIX = "svc:"


def _project_by_key(estate: EstateView, key: str) -> ProjectRow | None:
    """Match a project by project_id first, then by project_ref (SPEC §6 `svc:<project>:<name>`)."""
    if not key:
        return None
    return estate.projects.get(key) or estate.project_for_ref(key)


def _project_from_scope(estate: EstateView, grant: GrantRow) -> ProjectRow | None:
    resource = estate.resources.get(grant.scope_ref)
    if resource is not None and resource.project_ref:
        found = estate.project_for_ref(resource.project_ref)
        if found is not None:
            return found
    for prj in sorted(estate.projects.values(), key=lambda p: p.project_id):
        if prj.cloud == grant.cloud and common.project_ref_matches(
            grant.cloud, grant.scope_ref, prj.project_ref
        ):
            return prj
    return None


def _service_projects(estate: EstateView, row: IdentityRow, grants: list[GrantRow]) -> list[ProjectRow]:
    """Every registry project this service identity could belong to, most trustworthy first.

    A cloud tag can never remove a finding (CLAUDE.md non-negotiable 9). It used to: the tag was
    consulted before the grant scope and short-circuited it, so anyone with tagging rights could
    point `project` at a live project and make the retired one behind their grants invisible. All
    the candidates are returned instead, and the caller fires on any retired one — so provider data
    can still add a finding, and the evidence records which source named the project.
    """
    found: list[ProjectRow] = []
    seen: set[str] = set()

    def add(project: ProjectRow | None) -> None:
        if project is not None and project.project_id not in seen:
            seen.add(project.project_id)
            found.append(project)

    if row.identity_id.startswith(_SVC_PREFIX):
        parts = row.identity_id.split(":")
        if len(parts) >= 3:
            add(_project_by_key(estate, parts[1]))  # the linker's association (SPEC §6 rule 4)
    for grant in grants:
        add(_project_from_scope(estate, grant))  # derived by ATHAR from the grant's own scope
    tagged = row.tags.get("project") if isinstance(row.tags, dict) else None
    if isinstance(tagged, str):
        add(_project_by_key(estate, tagged))  # provider-controlled: may add, never suppress
    return found


def _service_project(estate: EstateView, row: IdentityRow, grants: list[GrantRow]) -> ProjectRow | None:
    """The project R3 reports on: a retired one if any candidate is retired, else the first."""
    candidates = _service_projects(estate, row, grants)
    for project in candidates:
        if project.status == "retired":
            return project
    return candidates[0] if candidates else None


def _departed(estate: EstateView, row: IdentityRow, grants: list[GrantRow]) -> FindingDraft | None:
    # SPEC? a departed row without departure_month cannot be shown to be ≥ 1 month old; skipped.
    if row.employment_status != "departed" or row.departure_month is None:
        return None
    if row.departure_month > estate.month - 1:
        return None
    departure_events = common.events_of_kind(estate, row.identity_id, "departure")
    facts = common.common_facts(estate, row.identity_id)
    facts.update(
        orphan_kind="departed",
        departure_month=row.departure_month,
        months_since_departure=estate.month - row.departure_month,
        project_id=None,
        retired_month=None,
        grant_ids=common.grant_ids(grants),
    )
    return common.draft(
        RULE_ID,
        row.identity_id,
        SEVERITY,
        [*common.grant_refs(grants), *common.event_refs(departure_events)],
        common.causal_event_ids(estate, row.identity_id, grants, "departure"),
        facts,
    )


def _retired(estate: EstateView, row: IdentityRow, grants: list[GrantRow]) -> FindingDraft | None:
    prj = _service_project(estate, row, grants)
    if prj is None or prj.status != "retired":
        return None
    retirement_events = common.events_of_kind(estate, row.identity_id, "project_retirement")
    facts = common.common_facts(estate, row.identity_id)
    facts.update(
        orphan_kind="retired_project",
        departure_month=None,
        months_since_departure=None,
        project_id=prj.project_id,
        retired_month=prj.retired_month,
        grant_ids=common.grant_ids(grants),
    )
    evidence = [
        *common.grant_refs(grants),
        *common.event_refs(retirement_events),
        EvidenceRef("project", prj.project_id, f"status={prj.status} retired_month={prj.retired_month}"),
    ]
    return common.draft(
        RULE_ID,
        row.identity_id,
        SEVERITY,
        evidence,
        common.causal_event_ids(estate, row.identity_id, grants, "project_retirement"),
        facts,
    )


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in sorted(estate.identities):
        row = estate.identities[identity_id]
        grants = common.active_allow_grants(estate, identity_id)
        if not grants:
            continue
        found = (
            _departed(estate, row, grants) if row.identity_type == "human" else _retired(estate, row, grants)
        )
        if found is not None:
            drafts.append(found)
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Orphaned identity",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1078.004"),
        control_refs=common.verify("ISO 27001:2022 A.5.18", "ISO 27001:2022 A.6.5"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="A departed employee or a retired project's service account that still holds access.",
    )
)
