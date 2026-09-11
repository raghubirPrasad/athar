"""Identity correlation — the linker (SPEC §6). Pure.

Rules, applied in order, recorded in `principals.link_method` with a `link_confidence`:
  1. hr_email        provider email / UPN equals HR `email` (case-insensitive)           exact
  2. entra_directory Azure objectId → entra-users.json → UPN → HR                        derived
  3. aws_username    AWS `UserName` equals an HR email local-part                        derived
  4. sa_project      service principal's project → registry → HR service row named like
                     the account, else synthetic identity `svc:<project_id>:<name>`       derived
  5. tag_owner       `owner` tag / label equals an HR email                              heuristic
  6. unlinked        synthetic identity `unlinked:<cloud>:<principal_ref>` → finding R10  heuristic

Synthetic identities are emitted as IdentityRows (`synthetic_identities`) so grants have a FK.
Cloud tags are evidence for *linking* only; they never suppress a finding (CLAUDE.md 9).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from athar.domain import IdentityRow, PrincipalRow, ProjectRow
from athar.normaliser.ids import normalise_email, svc_identity_id, unlinked_identity_id
from athar.normaliser.types import HrBundle, HrEmployee, RawPrincipal

UNASSIGNED = "Unassigned"
LINK_METHODS: tuple[str, ...] = (
    "hr_email",
    "entra_directory",
    "aws_username",
    "sa_project",
    "tag_owner",
    "unlinked",
)


@dataclass(frozen=True)
class Link:
    identity_id: str
    method: str
    confidence: str
    project: ProjectRow | None = None


def _rule_hr_email(p: RawPrincipal, hr: HrBundle) -> Link | None:
    emp = hr.employee_for_email(p.email)
    return Link(emp.employee_id, "hr_email", "exact") if emp else None


def _rule_entra_directory(
    p: RawPrincipal, hr: HrBundle, entra_users: Mapping[str, Mapping[str, Any]]
) -> Link | None:
    if p.cloud != "azure":
        return None
    record = entra_users.get(p.principal_ref) or entra_users.get(p.principal_ref.lower())
    if not record:
        return None
    for key in ("userPrincipalName", "mail"):
        emp = hr.employee_for_email(normalise_email(str(record.get(key) or "")))
        if emp:
            return Link(emp.employee_id, "entra_directory", "derived")
    return None


def _rule_aws_username(p: RawPrincipal, hr: HrBundle) -> Link | None:
    if p.cloud != "aws" or p.principal_type != "user":
        return None
    emp = hr.employee_for_local_part(p.name)
    return Link(emp.employee_id, "aws_username", "derived") if emp else None


def _rule_sa_project(p: RawPrincipal, hr: HrBundle) -> Link | None:
    project = hr.project_for(p.project_hint)
    if project is None:
        return None
    emp: HrEmployee | None = hr.service_employee_named(p.name)
    if emp is not None:
        return Link(emp.employee_id, "sa_project", "derived", project)
    return Link(svc_identity_id(project.project_id, p.name), "sa_project", "derived", project)


def _rule_tag_owner(p: RawPrincipal, hr: HrBundle) -> Link | None:
    owner = p.tags.get("owner") or p.tags.get("owner_email")
    emp = hr.employee_for_email(owner)
    return Link(emp.employee_id, "tag_owner", "heuristic") if emp else None


def link_one(p: RawPrincipal, hr: HrBundle, entra_users: Mapping[str, Mapping[str, Any]]) -> Link:
    return (
        _rule_hr_email(p, hr)
        or _rule_entra_directory(p, hr, entra_users)
        or _rule_aws_username(p, hr)
        or _rule_sa_project(p, hr)
        or _rule_tag_owner(p, hr)
        or Link(unlinked_identity_id(p.cloud, p.principal_ref), "unlinked", "heuristic")
    )


def link_principals(
    principals: Iterable[RawPrincipal],
    hr: HrBundle,
    entra_users: Mapping[str, Mapping[str, Any]] | None = None,
    projects: Iterable[ProjectRow] | None = None,
) -> list[PrincipalRow]:
    """Apply the §6 rules to every principal; deterministic (sorted by principal_ref)."""
    bundle = hr if projects is None else HrBundle(hr.employees, list(projects), hr.exceptions)
    users = entra_users or {}
    out: list[PrincipalRow] = []
    for p in sorted(principals, key=lambda x: (x.cloud, x.principal_ref)):
        link = link_one(p, bundle, users)
        out.append(
            PrincipalRow(
                principal_ref=p.principal_ref,
                cloud=p.cloud,
                principal_type=p.principal_type,
                identity_id=link.identity_id,
                raw=dict(p.raw),
                link_method=link.method,
                link_confidence=link.confidence,
            )
        )
    return out


def synthetic_identities(
    principals: Iterable[RawPrincipal],
    linked: Iterable[PrincipalRow],
    hr: HrBundle,
    month: int,
) -> list[IdentityRow]:
    """IdentityRows for `svc:` and `unlinked:` identities minted by the linker (one per id).

    An identity the HR feed already describes is never minted here: the feed is the record, and a
    second row for the same id would be a duplicate the upsert cannot resolve (a service account
    listed in `hr/employees.csv` and discovered again from its cloud principal).
    """
    raw_by_ref = {p.principal_ref: p for p in principals}
    out: dict[str, IdentityRow] = {}
    for row in sorted(linked, key=lambda r: r.principal_ref):
        identity_id = row.identity_id
        if not identity_id or identity_id in out or identity_id in hr.by_id:
            continue
        raw = raw_by_ref.get(row.principal_ref)
        tags: dict[str, Any] = dict(raw.tags) if raw else {}
        tags["principal_ref"] = row.principal_ref
        tags["cloud"] = row.cloud
        if identity_id.startswith("svc:"):
            project = hr.project_for(raw.project_hint if raw else None)
            if project is not None:
                tags["project"] = project.project_id
                tags["project_ref"] = project.project_ref
            out[identity_id] = IdentityRow(
                identity_id=identity_id,
                display_name=raw.name if raw else identity_id,
                identity_type="service",
                department=project.department if project else UNASSIGNED,
                employment_type="service",
                employment_status="active",
                hire_month=None,
                departure_month=None,
                external=False,
                mfa_enforced=False,
                tags=tags,
                contract_end_month=None,
                first_seen_month=month,
                last_seen_month=month,
            )
        elif identity_id.startswith("unlinked:"):
            out[identity_id] = IdentityRow(
                identity_id=identity_id,
                display_name=raw.name if raw else row.principal_ref,
                identity_type="service",
                department=UNASSIGNED,
                employment_type="service",
                employment_status="active",
                hire_month=None,
                departure_month=None,
                external=False,
                mfa_enforced=False,
                tags=tags,
                contract_end_month=None,
                first_seen_month=month,
                last_seen_month=month,
            )
    return [out[k] for k in sorted(out)]
