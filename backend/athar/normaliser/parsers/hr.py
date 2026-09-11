"""HR feed, project registry and governance exception register (SPEC §4.3, §4.6). Pure.

  hr/employees.csv   employee_id,email,display_name,department,title,employment_type,status,
                     start_date,end_date,contract_end,manager_id   (a leading `# SYNTHETIC` line is skipped)
  hr/projects.csv    project_id,name,department,status,retired_month,cloud,project_ref
  hr/exceptions.csv  identity_id,exception_type,approved_by,approved_on,review_date,expires_on,justification

The register is the ONLY source rules consult for exceptions; cloud tags never are (CLAUDE.md 9).
"""

from __future__ import annotations

from athar.domain import ExceptionRow, ProjectRow
from athar.normaliser.ids import exception_id, normalise_email
from athar.normaliser.parsers.common import parse_date, read_csv_rows, text, text_or_none
from athar.normaliser.types import HrBundle, HrEmployee

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


def parse_employees(data: str, warnings: list[str] | None = None) -> list[HrEmployee]:
    _, rows = read_csv_rows(data)
    out: dict[str, HrEmployee] = {}
    for n, row in enumerate(rows, start=1):
        emp_id = text(row.get("employee_id"))
        if not emp_id:
            continue
        if emp_id in out and warnings is not None:
            warnings.append(f"duplicate employee_id {emp_id} (row {n} replaces earlier)")
        known = set(EMPLOYEE_COLUMNS)
        out[emp_id] = HrEmployee(
            employee_id=emp_id,
            email=normalise_email(row.get("email")),
            display_name=text(row.get("display_name")) or emp_id,
            department=text(row.get("department")) or "Unassigned",
            title=text(row.get("title")),
            employment_type=(text(row.get("employment_type")) or "staff").lower(),
            status=(text(row.get("status")) or "active").lower(),
            start_date=parse_date(row.get("start_date")),
            end_date=parse_date(row.get("end_date")),
            contract_end=parse_date(row.get("contract_end")),
            manager_id=text_or_none(row.get("manager_id")),
            row_number=n,
            extra={k: v for k, v in row.items() if k not in known and v},
        )
    return [out[k] for k in out]


def parse_projects(data: str) -> list[ProjectRow]:
    _, rows = read_csv_rows(data)
    out: dict[str, ProjectRow] = {}
    for row in rows:
        pid = text(row.get("project_id"))
        if not pid:
            continue
        retired = text_or_none(row.get("retired_month"))
        out[pid] = ProjectRow(
            project_id=pid,
            name=text(row.get("name")) or pid,
            department=text(row.get("department")) or "Unassigned",
            status=(text(row.get("status")) or "active").lower(),
            retired_month=int(float(retired)) if retired and retired.replace(".", "", 1).isdigit() else None,
            cloud=(text(row.get("cloud")) or "").lower(),
            project_ref=text(row.get("project_ref")) or pid,
        )
    return [out[k] for k in out]


def parse_exceptions(data: str) -> list[ExceptionRow]:
    _, rows = read_csv_rows(data)
    out: dict[str, ExceptionRow] = {}
    for row in rows:
        identity_id = text(row.get("identity_id"))
        exception_type = text(row.get("exception_type"))
        if not identity_id or not exception_type:
            continue
        approved_on = parse_date(row.get("approved_on"))
        review_date = parse_date(row.get("review_date"))
        expires_on = parse_date(row.get("expires_on"))
        exc_id = exception_id(identity_id, exception_type, approved_on, review_date, expires_on)
        out[exc_id] = ExceptionRow(
            exception_id=exc_id,
            identity_id=identity_id,
            exception_type=exception_type,
            approved_by=text(row.get("approved_by")),
            approved_on=approved_on,
            review_date=review_date,
            expires_on=expires_on,
            justification=text(row.get("justification")),
            source="register",
        )
    return [out[k] for k in out]


def parse_hr(files: dict[str, str], warnings: list[str] | None = None) -> HrBundle:
    """`files` maps `employees.csv` / `projects.csv` / `exceptions.csv` to decoded text."""
    return HrBundle(
        employees=parse_employees(files.get("employees.csv", ""), warnings),
        projects=parse_projects(files.get("projects.csv", "")),
        exceptions=parse_exceptions(files.get("exceptions.csv", "")),
    )
