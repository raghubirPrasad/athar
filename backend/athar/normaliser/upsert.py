"""Idempotent persistence of a NormalisedMonth (SPEC §5.1; CLAUDE.md non-negotiable 2).

Every CPM table is written with `INSERT … ON CONFLICT` on its natural key, so ingesting the same
month twice yields identical rows. Per-month row sets (grants, activity) are reconciled: rows of
that month absent from the new ingest are deactivated (grants — they may be cited as evidence by
an earlier scan) or deleted (activity). `identities.first_seen_month` / `last_seen_month` are
maintained across months and the HR-derived columns only move forward.

# SPEC? §5.1 keys `credentials` and `resources` by bare ref while `load_estate_view` filters both
# by `snapshot_month`. Rather than leak a month qualifier into refs that rules, events and
# remediation compare verbatim, a credential / resource is one row whose `snapshot_month` is the
# latest month it was observed in (never moved backwards). A scan of the current month sees them
# all; a re-scan of an older month sees none. Foundation change request: add snapshot_month to
# both primary keys.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import ColumnElement

from athar.db import models as m
from athar.log import get_logger
from athar.normaliser.pipeline import NormalisedMonth

log = get_logger(__name__)
CHUNK = 500


@dataclass
class UpsertStats:
    month: int
    identities: int = 0
    principals: int = 0
    grants: int = 0
    grants_deactivated: int = 0
    activity: int = 0
    activity_deleted: int = 0
    credentials: int = 0
    credentials_deactivated: int = 0
    resources: int = 0
    resources_deleted: int = 0
    projects: int = 0
    exceptions: int = 0
    events: int = 0
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _chunks(rows: Sequence[dict[str, Any]]) -> Iterable[Sequence[dict[str, Any]]]:
    for i in range(0, len(rows), CHUNK):
        yield rows[i : i + CHUNK]


def _dedupe(
    rows: Sequence[dict[str, Any]], keys: Sequence[str], *, prefer: str | None = None
) -> list[dict[str, Any]]:
    """One row per natural key, in first-seen order.

    Postgres refuses an `ON CONFLICT DO UPDATE` that would touch the same row twice inside one
    statement, and a normalised month legitimately carries a key twice: a service identity linked
    from two clouds, or a principal a provider exported twice. Last occurrence wins (the rule the
    upload validator already documents for duplicate principals); `prefer` instead keeps the row
    with the greatest value of that column, which is how an identity seen in several months keeps
    its newest HR state.
    """
    out: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = tuple(row.get(k) for k in keys)
        current = out.get(key)
        if current is None or prefer is None or (row.get(prefer) or 0) >= (current.get(prefer) or 0):
            out[key] = row
    return list(out.values())


def _rows(items: Iterable[Any]) -> list[dict[str, Any]]:
    return [asdict(x) for x in items]


def _rowcount(result: Any) -> int:
    """Rows touched by an UPDATE / DELETE (`CursorResult.rowcount`; 0 when the driver has none)."""
    return int(getattr(result, "rowcount", 0) or 0)


def _cloud_filter(column: Any, clouds: Sequence[str]) -> ColumnElement[bool]:
    """Reconciliation only touches the clouds this ingest actually carried (a single-provider
    upload must not deactivate the other providers' rows for the month)."""
    return column.in_(list(clouds))


def _upsert(
    session: Session,
    model: type[m.Base],
    rows: Sequence[dict[str, Any]],
    keys: Sequence[str],
    set_cols: Sequence[str],
) -> int:
    if not rows:
        return 0
    rows = _dedupe(rows, keys)
    for chunk in _chunks(rows):
        stmt = insert(model).values(list(chunk))
        stmt = stmt.on_conflict_do_update(
            index_elements=list(keys), set_={c: getattr(stmt.excluded, c) for c in set_cols}
        )
        session.execute(stmt)
    return len(rows)


# ---------------------------------------------------------------------------
# Per-table writers
# ---------------------------------------------------------------------------

_IDENTITY_FORWARD = (
    "display_name",
    "identity_type",
    "department",
    "employment_type",
    "employment_status",
    "hire_month",
    "departure_month",
    "external",
    "mfa_enforced",
    "tags",
    "contract_end_month",
)


def _upsert_identities(session: Session, rows: Sequence[dict[str, Any]]) -> int:
    """first_seen = LEAST, last_seen = GREATEST; other columns move forward only (a re-ingest of an
    older month never regresses a newer HR status)."""
    if not rows:
        return 0
    rows = _dedupe(rows, ["identity_id"], prefer="last_seen_month")
    for chunk in _chunks(rows):
        stmt = insert(m.Identity).values(list(chunk))
        newer = stmt.excluded.last_seen_month >= m.Identity.last_seen_month
        set_: dict[str, Any] = {
            c: case((newer, getattr(stmt.excluded, c)), else_=getattr(m.Identity, c))
            for c in _IDENTITY_FORWARD
        }
        set_["first_seen_month"] = func.least(m.Identity.first_seen_month, stmt.excluded.first_seen_month)
        set_["last_seen_month"] = func.greatest(m.Identity.last_seen_month, stmt.excluded.last_seen_month)
        session.execute(stmt.on_conflict_do_update(index_elements=["identity_id"], set_=set_))
    return len(rows)


def _upsert_grants(
    session: Session, month: int, clouds: Sequence[str], rows: Sequence[dict[str, Any]]
) -> tuple[int, int]:
    cols = [c for c in (rows[0] if rows else {}) if c != "grant_id"]
    written = _upsert(session, m.Grant, rows, ["grant_id"], cols)
    if not clouds:
        return written, 0
    keep = [r["grant_id"] for r in rows]
    stmt = update(m.Grant).where(
        m.Grant.snapshot_month == month, m.Grant.active.is_(True), _cloud_filter(m.Grant.cloud, clouds)
    )
    if keep:
        stmt = stmt.where(m.Grant.grant_id.not_in(keep))
    result = session.execute(stmt.values(active=False))
    return written, _rowcount(result)


def _upsert_activity(
    session: Session, month: int, clouds: Sequence[str], rows: Sequence[dict[str, Any]]
) -> tuple[int, int]:
    keys = ["identity_id", "cloud", "service_category", "snapshot_month"]
    written = _upsert(session, m.Activity, rows, keys, ["last_activity_at", "operation_count"])
    if not clouds:
        return written, 0
    present = {(r["identity_id"], r["cloud"], r["service_category"]) for r in rows}
    existing = session.execute(
        select(m.Activity.identity_id, m.Activity.cloud, m.Activity.service_category).where(
            m.Activity.snapshot_month == month, _cloud_filter(m.Activity.cloud, clouds)
        )
    ).all()
    stale = [row for row in existing if (row[0], row[1], row[2]) not in present]
    deleted = 0
    for identity_id, cloud, category in stale:
        result = session.execute(
            delete(m.Activity).where(
                m.Activity.snapshot_month == month,
                m.Activity.identity_id == identity_id,
                m.Activity.cloud == cloud,
                m.Activity.service_category == category,
            )
        )
        deleted += _rowcount(result)
    return written, deleted


def _upsert_credentials(
    session: Session, month: int, clouds: Sequence[str], rows: Sequence[dict[str, Any]]
) -> tuple[int, int]:
    if rows:
        for chunk in _chunks(rows):
            stmt = insert(m.Credential).values(list(chunk))
            newer = stmt.excluded.snapshot_month >= m.Credential.snapshot_month
            set_: dict[str, Any] = {
                c: case((newer, getattr(stmt.excluded, c)), else_=getattr(m.Credential, c))
                for c in (
                    "identity_id",
                    "cloud",
                    "kind",
                    "created_at",
                    "last_rotated_at",
                    "last_used_at",
                    "active",
                )
            }
            # FIRST sighting, not the last: `credentials` and `resources` are keyed by reference
            # alone (SPEC §5.1), so the month column is all a historical view has to decide whether
            # the row existed yet. Keeping the last sighting stamped every surviving row with the
            # newest month, and `load_estate_view` then found none of them for any earlier month.
            set_["snapshot_month"] = func.least(m.Credential.snapshot_month, stmt.excluded.snapshot_month)
            session.execute(stmt.on_conflict_do_update(index_elements=["credential_ref"], set_=set_))
    if not clouds:
        return len(rows), 0
    # Anything this cloud knew by now and no longer exports is deactivated. Months are ingested in
    # ascending order (`athar seed`, `athar ingest`), so the newest ingest sets the final state.
    keep = [r["credential_ref"] for r in rows]
    stmt_stale = update(m.Credential).where(
        m.Credential.snapshot_month <= month,
        m.Credential.active.is_(True),
        _cloud_filter(m.Credential.cloud, clouds),
    )
    if keep:
        stmt_stale = stmt_stale.where(m.Credential.credential_ref.not_in(keep))
    result = session.execute(stmt_stale.values(active=False))
    return len(rows), _rowcount(result)


def _upsert_resources(
    session: Session, month: int, clouds: Sequence[str], rows: Sequence[dict[str, Any]]
) -> tuple[int, int]:
    if rows:
        for chunk in _chunks(rows):
            stmt = insert(m.Resource).values(list(chunk))
            newer = stmt.excluded.snapshot_month >= m.Resource.snapshot_month
            set_: dict[str, Any] = {
                c: case((newer, getattr(stmt.excluded, c)), else_=getattr(m.Resource, c))
                for c in ("cloud", "service_category", "region", "project_ref", "sensitivity")
            }
            set_["snapshot_month"] = func.least(
                m.Resource.snapshot_month, stmt.excluded.snapshot_month
            )  # first sighting
            session.execute(stmt.on_conflict_do_update(index_elements=["resource_ref"], set_=set_))
    if not clouds:
        return len(rows), 0
    # Resources accumulate. A resource that existed in months 1-6 and was deleted afterwards is
    # still part of month 3's estate, and deleting the row would make every historical blast radius
    # wrong. `snapshot_month` records when it first appeared; the view filters on that.
    return len(rows), 0


def _upsert_snapshot(
    session: Session, month: int, file_hashes: dict[str, str], ingested_at: datetime | None
) -> None:
    """One row per month; a re-ingest replaces the manifest. `ingested_at` is an operational
    timestamp (SPEC §5.1: the only place the real clock is allowed) supplied by the caller, and
    defaults to now(UTC) here because the snapshots table requires it."""
    stmt = insert(m.Snapshot).values(
        snapshot_month=month,
        ingested_at=ingested_at or datetime.now(UTC),
        file_hashes=dict(file_hashes),
    )
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=["snapshot_month"],
            set_={"ingested_at": stmt.excluded.ingested_at, "file_hashes": stmt.excluded.file_hashes},
        )
    )


def _advance_clock(session: Session, month: int) -> None:
    stmt = insert(m.EstateClock).values(id=1, current_month=month)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=["id"], set_={"current_month": func.greatest(m.EstateClock.current_month, month)}
        )
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def upsert_month(session: Session, nm: NormalisedMonth, ingested_at: datetime | None = None) -> UpsertStats:
    """Persist one normalised month. Idempotent; the caller owns the transaction.

    Per-month row sets are reconciled only for the clouds in `nm.clouds`, so a single-provider
    upload (`pipeline.provider_rows_to_month`) leaves the other providers' rows for that month alone.
    """
    clouds = list(nm.clouds)
    stats = UpsertStats(month=nm.month, warnings=list(nm.warnings))
    stats.identities = _upsert_identities(session, _rows(nm.identities))
    prow = _rows(nm.principals)
    stats.principals = _upsert(
        session,
        m.Principal,
        prow,
        ["principal_ref"],
        ["cloud", "principal_type", "identity_id", "raw", "link_method", "link_confidence"],
    )
    stats.grants, stats.grants_deactivated = _upsert_grants(session, nm.month, clouds, _rows(nm.grants))
    stats.activity, stats.activity_deleted = _upsert_activity(session, nm.month, clouds, _rows(nm.activity))
    stats.credentials, stats.credentials_deactivated = _upsert_credentials(
        session, nm.month, clouds, _rows(nm.credentials)
    )
    stats.resources, stats.resources_deleted = _upsert_resources(
        session, nm.month, clouds, _rows(nm.resources)
    )
    stats.projects = _upsert(
        session,
        m.Project,
        _rows(nm.projects),
        ["project_id"],
        ["name", "department", "status", "retired_month", "cloud", "project_ref"],
    )
    stats.exceptions = _upsert(
        session,
        m.GovernanceException,
        _rows(nm.exceptions),
        ["exception_id"],
        [
            "identity_id",
            "exception_type",
            "approved_by",
            "approved_on",
            "review_date",
            "expires_on",
            "justification",
            "source",
        ],
    )
    stats.events = _upsert(
        session,
        m.Event,
        _rows(nm.events),
        ["event_id"],
        ["month", "kind", "identity_id", "cloud", "grant_delta", "trigger", "note"],
    )
    _upsert_snapshot(session, nm.month, nm.file_hashes, ingested_at)
    _advance_clock(session, nm.month)
    session.flush()
    log.info("upserted month", extra={k: v for k, v in stats.as_dict().items() if k != "warnings"})
    return stats
