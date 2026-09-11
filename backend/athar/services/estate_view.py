"""Build an in-memory EstateView for one snapshot month from the database (SPEC §5.1 → domain rows).

Rules, scoring and drift only ever see this view; they never touch the session.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from athar.config import Settings
from athar.db import models as m
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
    Thresholds,
)


def load_thresholds(session: Session, settings: Settings) -> Thresholds:
    """Runtime thresholds from the `settings` table, falling back to env defaults (SPEC §7)."""
    row = session.get(m.RuntimeSettings, 1)
    if row is None:
        return Thresholds(
            dormant_days=settings.dormant_days,
            stale_key_days=settings.stale_key_days,
            approved_regions=tuple(settings.approved_regions),
        )
    regions = tuple(str(r) for r in (row.approved_regions or settings.approved_regions))
    return Thresholds(
        dormant_days=row.dormant_days, stale_key_days=row.stale_key_days, approved_regions=regions
    )


def load_estate_view(session: Session, month: int) -> EstateView:
    """The estate as of `month`.

    Grants and activity are per-snapshot rows, so they filter on equality. `resources` and
    `credentials` are keyed by reference alone (SPEC §5.1), and their `snapshot_month` records the
    LAST month the row was seen — so an equality filter finds nothing for any month but the newest
    ingest, which silently made blast radius zero for every historical scan. They filter on `<=`
    instead: everything known by that month, which is the inventory the blast-radius denominator
    means (SPEC §8.2) and the set R6 ages credentials against.
    """
    identities = {
        r.identity_id: IdentityRow(
            identity_id=r.identity_id,
            display_name=r.display_name,
            identity_type=r.identity_type,
            department=r.department,
            employment_type=r.employment_type,
            employment_status=r.employment_status,
            hire_month=r.hire_month,
            departure_month=r.departure_month,
            external=bool(r.external),
            mfa_enforced=bool(r.mfa_enforced),
            tags=dict(r.tags or {}),
            contract_end_month=r.contract_end_month,
            first_seen_month=r.first_seen_month,
            last_seen_month=r.last_seen_month,
        )
        for r in session.scalars(
            select(m.Identity).where(m.Identity.first_seen_month <= month).order_by(m.Identity.identity_id)
        )
    }
    principals = {
        r.principal_ref: PrincipalRow(
            principal_ref=r.principal_ref,
            cloud=r.cloud,
            principal_type=r.principal_type,
            identity_id=r.identity_id,
            raw=dict(r.raw or {}),
            link_method=r.link_method,
            link_confidence=r.link_confidence,
        )
        for r in session.scalars(select(m.Principal).order_by(m.Principal.principal_ref))
    }
    grants = [
        GrantRow(
            grant_id=r.grant_id,
            identity_id=r.identity_id,
            principal_ref=r.principal_ref,
            cloud=r.cloud,
            service_category=r.service_category,
            verb=r.verb,
            scope_level=r.scope_level,
            scope_ref=r.scope_ref,
            region=r.region,
            effect=r.effect,
            granted_via=r.granted_via,
            snapshot_month=r.snapshot_month,
            raw_snippet=dict(r.raw_snippet or {}),
            source_file=r.source_file,
            source_pointer=r.source_pointer,
            active=bool(r.active),
        )
        for r in session.scalars(
            select(m.Grant).where(m.Grant.snapshot_month == month).order_by(m.Grant.grant_id)
        )
    ]
    activity = [
        ActivityRow(
            identity_id=r.identity_id,
            cloud=r.cloud,
            service_category=r.service_category,
            snapshot_month=r.snapshot_month,
            last_activity_at=r.last_activity_at,
            operation_count=r.operation_count,
        )
        for r in session.scalars(
            select(m.Activity)
            .where(m.Activity.snapshot_month == month)
            .order_by(m.Activity.identity_id, m.Activity.cloud, m.Activity.service_category)
        )
    ]
    credentials = [
        CredentialRow(
            credential_ref=r.credential_ref,
            identity_id=r.identity_id,
            cloud=r.cloud,
            kind=r.kind,
            created_at=r.created_at,
            last_rotated_at=r.last_rotated_at,
            last_used_at=r.last_used_at,
            active=bool(r.active),
            snapshot_month=r.snapshot_month,
        )
        for r in session.scalars(
            select(m.Credential)
            .where(m.Credential.snapshot_month <= month)
            .order_by(m.Credential.credential_ref)
        )
    ]
    resources = {
        r.resource_ref: ResourceRow(
            resource_ref=r.resource_ref,
            cloud=r.cloud,
            service_category=r.service_category,
            region=r.region,
            project_ref=r.project_ref,
            sensitivity=r.sensitivity,
            snapshot_month=r.snapshot_month,
        )
        for r in session.scalars(
            select(m.Resource).where(m.Resource.snapshot_month <= month).order_by(m.Resource.resource_ref)
        )
    }
    projects = {
        r.project_id: ProjectRow(
            project_id=r.project_id,
            name=r.name,
            department=r.department,
            status=r.status,
            retired_month=r.retired_month,
            cloud=r.cloud,
            project_ref=r.project_ref,
        )
        for r in session.scalars(select(m.Project).order_by(m.Project.project_id))
    }
    exceptions = [
        ExceptionRow(
            exception_id=r.exception_id,
            identity_id=r.identity_id,
            exception_type=r.exception_type,
            approved_by=r.approved_by,
            approved_on=r.approved_on,
            review_date=r.review_date,
            expires_on=r.expires_on,
            justification=r.justification,
            source=r.source,
        )
        for r in session.scalars(select(m.GovernanceException).order_by(m.GovernanceException.exception_id))
    ]
    events = [
        EventRow(
            event_id=r.event_id,
            month=r.month,
            kind=r.kind,
            identity_id=r.identity_id,
            cloud=r.cloud,
            grant_delta=dict(r.grant_delta or {}),
            trigger=r.trigger,
            note=r.note,
        )
        for r in session.scalars(
            select(m.Event).where(m.Event.month <= month).order_by(m.Event.month, m.Event.event_id)
        )
    ]
    return EstateView(
        month=month,
        identities=identities,
        principals=principals,
        grants=grants,
        activity=activity,
        credentials=credentials,
        resources=resources,
        projects=projects,
        exceptions=exceptions,
        events=events,
    )
