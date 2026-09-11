"""Hand-built EstateView rows for unit tests. FROZEN — add helpers in your own module, not here."""

from __future__ import annotations

from datetime import date
from typing import Any

from athar.domain import (
    ActivityRow,
    CredentialRow,
    EstateView,
    EventRow,
    ExceptionRow,
    GrantRow,
    IdentityRow,
    PrincipalRow,
    ProjectRow,
    ResourceRow,
)


def identity(identity_id: str = "emp-0001", **kw: Any) -> IdentityRow:
    base: dict[str, Any] = dict(
        identity_id=identity_id,
        display_name="Test Person",
        identity_type="human",
        department="Finance",
        employment_type="staff",
        employment_status="active",
        hire_month=1,
        departure_month=None,
        external=False,
        mfa_enforced=True,
        tags={},
        contract_end_month=None,
        first_seen_month=1,
        last_seen_month=12,
    )
    base.update(kw)
    return IdentityRow(**base)


def principal(
    principal_ref: str, cloud: str = "aws", identity_id: str | None = "emp-0001", **kw: Any
) -> PrincipalRow:
    base: dict[str, Any] = dict(
        principal_ref=principal_ref,
        cloud=cloud,
        principal_type="user",
        identity_id=identity_id,
        raw={},
        link_method="hr_email",
        link_confidence="exact",
    )
    base.update(kw)
    return PrincipalRow(**base)


def grant(
    grant_id: str,
    identity_id: str = "emp-0001",
    principal_ref: str = "arn:aws:iam::123456789012:user/test",
    **kw: Any,
) -> GrantRow:
    base: dict[str, Any] = dict(
        grant_id=grant_id,
        identity_id=identity_id,
        principal_ref=principal_ref,
        cloud="aws",
        service_category="storage",
        verb="read",
        scope_level="resource",
        scope_ref="arn:aws:s3:::bucket/*",
        region="me-central-1",
        effect="allow",
        granted_via="direct",
        snapshot_month=12,
        raw_snippet={},
        source_file="aws/authorization-details.json",
        source_pointer="/UserDetailList/0",
        active=True,
    )
    base.update(kw)
    return GrantRow(**base)


def activity(
    identity_id: str = "emp-0001",
    cloud: str = "aws",
    category: str = "storage",
    last: date | None = date(2026, 8, 15),
    month: int = 12,
    count: int = 5,
) -> ActivityRow:
    return ActivityRow(
        identity_id=identity_id,
        cloud=cloud,
        service_category=category,
        snapshot_month=month,
        last_activity_at=last,
        operation_count=count,
    )


def credential(
    credential_ref: str = "aws:key:AKIA0001", identity_id: str = "emp-0001", **kw: Any
) -> CredentialRow:
    base: dict[str, Any] = dict(
        credential_ref=credential_ref,
        identity_id=identity_id,
        cloud="aws",
        kind="key",
        created_at=date(2025, 9, 1),
        last_rotated_at=date(2025, 9, 1),
        last_used_at=date(2026, 8, 1),
        active=True,
        snapshot_month=12,
    )
    base.update(kw)
    return CredentialRow(**base)


def resource(
    resource_ref: str,
    cloud: str = "aws",
    category: str = "storage",
    region: str = "me-central-1",
    sensitivity: str = "low",
    project_ref: str | None = None,
    month: int = 12,
) -> ResourceRow:
    return ResourceRow(
        resource_ref=resource_ref,
        cloud=cloud,
        service_category=category,
        region=region,
        project_ref=project_ref,
        sensitivity=sensitivity,
        snapshot_month=month,
    )


def project(
    project_id: str = "prj-001",
    status: str = "active",
    retired_month: int | None = None,
    cloud: str = "gcp",
    project_ref: str = "nda-analytics-prod",
    department: str = "Data Services",
) -> ProjectRow:
    return ProjectRow(
        project_id=project_id,
        name=project_id,
        department=department,
        status=status,
        retired_month=retired_month,
        cloud=cloud,
        project_ref=project_ref,
    )


def exception(
    identity_id: str = "emp-0001",
    exception_type: str = "break-glass",
    review_date: date | None = date(2027, 1, 1),
    expires_on: date | None = None,
    exception_id: str = "exc-001",
) -> ExceptionRow:
    return ExceptionRow(
        exception_id=exception_id,
        identity_id=identity_id,
        exception_type=exception_type,
        approved_by="ciso@nda.example",
        approved_on=date(2025, 9, 1),
        review_date=review_date,
        expires_on=expires_on,
        justification="test",
        source="register",
    )


def event(
    event_id: str,
    month: int,
    kind: str,
    identity_id: str | None = "emp-0001",
    cloud: str | None = "aws",
    trigger: str = "role_change",
    grant_delta: dict[str, Any] | None = None,
    note: str = "",
) -> EventRow:
    return EventRow(
        event_id=event_id,
        month=month,
        kind=kind,
        identity_id=identity_id,
        cloud=cloud,
        grant_delta=grant_delta or {},
        trigger=trigger,
        note=note,
    )


def estate(month: int = 12, **kw: Any) -> EstateView:
    """EstateView with dict/list kwargs: identities=[...], grants=[...], etc."""
    ids = {i.identity_id: i for i in kw.pop("identities", [])}
    prs = {p.principal_ref: p for p in kw.pop("principals", [])}
    res = {r.resource_ref: r for r in kw.pop("resources", [])}
    prj = {p.project_id: p for p in kw.pop("projects", [])}
    return EstateView(month=month, identities=ids, principals=prs, resources=res, projects=prj, **kw)
