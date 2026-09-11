"""HR feed, project registry and governance exception register (SPEC §4.3, §4.6). Pure.

  hr/employees.csv   employee_id,email,display_name,department,title,employment_type,status,
                     start_date,end_date,contract_end,manager_id
  hr/projects.csv    project_id,name,department,status,retired_month,cloud,project_ref
  hr/exceptions.csv  identity_id,exception_type,approved_by,approved_on,review_date,expires_on,justification

`employees.csv` opens with a `#` SYNTHETIC marker (SPEC §4.1): the feed contains no real person
and every address is in the RFC 2606 reserved domain `nda.example`.

The exception register is the ONLY place a decoy's legitimacy is recorded (CLAUDE.md 9); cloud
tags are emitted by the provider writers for evidence and are never read as an exception. A
month's register carries the entries approved on or before that month's end, so an exception
appended by the approver workflow (SPEC §11.5) shows up from the month it was granted.
"""

from __future__ import annotations

from collections import defaultdict

from athar.generator.state import EstateState, Identity, MonthSnapshot
from athar.generator.writers import csv_text, iso_day

SYNTHETIC_MARKER = (
    "SYNTHETIC — Nahar Digital Authority simulated estate (SPEC §4.1). "
    "No real person, entity or address; nda.example is RFC 2606 reserved."
)

EMPLOYEE_COLUMNS: tuple[str, ...] = (
    "employee_id",
    "email",
    "display_name",
    "department",
    "title",
    "employment_type",
    "status",
    "start_date",
    "end_date",
    "contract_end",
    "manager_id",
)
PROJECT_COLUMNS: tuple[str, ...] = (
    "project_id",
    "name",
    "department",
    "status",
    "retired_month",
    "cloud",
    "project_ref",
)
EXCEPTION_COLUMNS: tuple[str, ...] = (
    "identity_id",
    "exception_type",
    "approved_by",
    "approved_on",
    "review_date",
    "expires_on",
    "justification",
)

_LEVEL_RANK: dict[str, int] = {"service": -1, "member": 0, "senior": 1, "lead": 2}


def managers(snapshot: MonthSnapshot) -> dict[str, str]:
    """`employee_id → manager_id`, derived from the org: the lowest-numbered active colleague of a
    higher level in the same department; for a service account, the project owner. Reporting lines
    are presentation only — no rule reads them — but an HR feed without them is not credible."""
    by_department: dict[str, list[Identity]] = defaultdict(list)
    for identity_id in sorted(snapshot.identities):
        ident = snapshot.identities[identity_id]
        if ident.is_human and ident.status == "active":
            by_department[ident.department].append(ident)
    out: dict[str, str] = {}
    for identity_id in sorted(snapshot.identities):
        ident = snapshot.identities[identity_id]
        if ident.is_human:
            rank = _LEVEL_RANK.get(ident.level, 0)
            senior = next(
                (
                    other.identity_id
                    for other in by_department.get(ident.department, ())
                    if _LEVEL_RANK.get(other.level, 0) > rank and other.identity_id != identity_id
                ),
                "",
            )
            out[identity_id] = senior
            continue
        project = snapshot.projects.get(ident.project_id or "")
        owner = project.owner_id if project and project.owner_id in snapshot.identities else None
        if owner is None:
            owner = next(
                (
                    other.identity_id
                    for other in by_department.get(ident.department, ())
                    if other.level == "lead"
                ),
                "",
            )
        out[identity_id] = owner or ""
    return out


def employees_csv(snapshot: MonthSnapshot) -> str:
    reports_to = managers(snapshot)
    rows = []
    for identity_id in sorted(snapshot.identities):
        ident = snapshot.identities[identity_id]
        rows.append(
            (
                ident.identity_id,
                ident.email,
                ident.display_name,
                ident.department,
                ident.title,
                ident.employment_type,
                ident.status,
                iso_day(ident.start_date),
                iso_day(ident.end_date),
                iso_day(ident.contract_end),
                reports_to.get(identity_id, ""),
            )
        )
    return csv_text(EMPLOYEE_COLUMNS, rows, comment=SYNTHETIC_MARKER)


def projects_csv(snapshot: MonthSnapshot) -> str:
    rows = [
        (
            project.project_id,
            project.name,
            project.department,
            project.status,
            "" if project.retired_month is None else project.retired_month,
            project.cloud,
            project.project_ref,
        )
        for project in sorted(snapshot.projects.values(), key=lambda p: p.project_id)
    ]
    return csv_text(PROJECT_COLUMNS, rows)


def exceptions_csv(state: EstateState, snapshot: MonthSnapshot) -> str:
    as_of = snapshot.as_of
    entries = sorted(
        (e for e in state.exceptions if e.approved_on <= as_of),
        key=lambda e: (e.identity_id, e.exception_type, e.approved_on),
    )
    rows = [
        (
            entry.identity_id,
            entry.exception_type,
            entry.approved_by,
            iso_day(entry.approved_on),
            iso_day(entry.review_date),
            iso_day(entry.expires_on),
            entry.justification,
        )
        for entry in entries
    ]
    return csv_text(EXCEPTION_COLUMNS, rows)


def hr_files(state: EstateState, snapshot: MonthSnapshot) -> dict[str, str]:
    return {
        "hr/employees.csv": employees_csv(snapshot),
        "hr/projects.csv": projects_csv(snapshot),
        "hr/exceptions.csv": exceptions_csv(state, snapshot),
    }
