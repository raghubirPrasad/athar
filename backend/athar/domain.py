"""Shared domain vocabulary and in-memory rows (SPEC §5.2, §7, §11.4).

Everything here is pure data: frozen dataclasses mirroring the CPM so that rules,
scoring, drift and narrative code can run on an `EstateView` without a database.
`services/estate_view.py` builds an EstateView from the DB; tests build one by hand.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

from athar.clock import month_end

Cloud = Literal["aws", "azure", "gcp"]
CLOUDS: tuple[str, ...] = ("aws", "azure", "gcp")

Verb = Literal["read", "write", "delete", "admin", "grant", "impersonate", "billing", "unknown"]
VERBS: tuple[str, ...] = ("read", "write", "delete", "admin", "grant", "impersonate", "billing")
CONTROL_VERBS: frozenset[str] = frozenset({"write", "delete", "admin", "grant", "billing"})

ScopeLevel = Literal["resource", "project", "org", "global"]
SCOPE_LEVELS: tuple[str, ...] = ("resource", "project", "org", "global")
SCOPE_RANK: dict[str, int] = {"resource": 0, "project": 1, "org": 2, "global": 3}
SCOPE_MULTIPLIER: dict[str, float] = {"resource": 1.0, "project": 1.5, "org": 2.5, "global": 4.0}

Category = Literal["compute", "storage", "network", "identity", "data", "security", "billing", "unknown"]
CATEGORIES: tuple[str, ...] = ("compute", "storage", "network", "identity", "data", "security", "billing")

Severity = Literal["Low", "Medium", "High", "Critical"]
SEVERITIES: tuple[str, ...] = ("Low", "Medium", "High", "Critical")
SEVERITY_RANK: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITY_FLOOR: dict[str, int] = {"Critical": 75, "High": 50, "Medium": 25, "Low": 0}

ExceptionType = Literal["break-glass", "dr-failover", "approved-privileged-role", "time-boxed"]

ALLOWED_ACTIONS: tuple[str, ...] = (
    "revoke_grant",
    "downgrade_to_least_privilege",
    "disable_identity",
    "rotate_or_disable_credential",
    "remove_cloud_access",
    "tag_as_exception",
    "no_action_recommended",
)

FindingStatus = Literal[
    "open", "investigated", "remediation_proposed", "approved", "remediated", "rejected", "exception_granted"
]

DEPARTMENTS: tuple[str, ...] = (
    "Finance",
    "HR",
    "Platform Engineering",
    "Data Services",
    "Smart Services",
    "Cyber Security",
    "Field Operations",
    "Contractors",
)


def severity_band(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def scope_at_least(level: str, minimum: str) -> bool:
    return SCOPE_RANK.get(level, -1) >= SCOPE_RANK[minimum]


# ---------------------------------------------------------------------------
# Rows (mirror SPEC §5.1 column for column)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityRow:
    identity_id: str
    display_name: str
    identity_type: str  # human | service
    department: str
    employment_type: str  # staff | contractor | service
    employment_status: str  # active | departed | on_leave
    hire_month: int | None
    departure_month: int | None
    external: bool
    mfa_enforced: bool
    tags: dict[str, Any]
    contract_end_month: int | None
    first_seen_month: int
    last_seen_month: int


@dataclass(frozen=True)
class PrincipalRow:
    principal_ref: str
    cloud: str
    principal_type: str
    identity_id: str | None
    raw: dict[str, Any]
    link_method: str
    link_confidence: str


@dataclass(frozen=True)
class GrantRow:
    grant_id: str
    identity_id: str
    principal_ref: str
    cloud: str
    service_category: str
    verb: str
    scope_level: str
    scope_ref: str
    region: str | None
    effect: str
    granted_via: str
    snapshot_month: int
    raw_snippet: dict[str, Any]
    source_file: str
    source_pointer: str
    active: bool = True


@dataclass(frozen=True)
class ActivityRow:
    identity_id: str
    cloud: str
    service_category: str
    snapshot_month: int
    last_activity_at: date | None
    operation_count: int


@dataclass(frozen=True)
class CredentialRow:
    credential_ref: str
    identity_id: str
    cloud: str
    kind: str  # key | password | sa_key
    created_at: date | None
    last_rotated_at: date | None
    last_used_at: date | None
    active: bool
    snapshot_month: int


@dataclass(frozen=True)
class ResourceRow:
    resource_ref: str
    cloud: str
    service_category: str
    region: str | None
    project_ref: str | None
    sensitivity: str  # low | high
    snapshot_month: int


@dataclass(frozen=True)
class ProjectRow:
    project_id: str
    name: str
    department: str
    status: str  # active | retired
    retired_month: int | None
    cloud: str
    project_ref: str


@dataclass(frozen=True)
class ExceptionRow:
    exception_id: str
    identity_id: str
    exception_type: str
    approved_by: str
    approved_on: date | None
    review_date: date | None
    expires_on: date | None
    justification: str
    source: str = "register"

    def is_valid_on(self, on: date) -> bool:
        """Unexpired: neither review_date nor expires_on has passed (SPEC §4.3)."""
        if self.review_date is not None and self.review_date < on:
            return False
        return not (self.expires_on is not None and self.expires_on < on)


@dataclass(frozen=True)
class EventRow:
    event_id: str
    month: int
    kind: str
    identity_id: str | None
    cloud: str | None
    grant_delta: dict[str, Any]
    trigger: str
    note: str


@dataclass(frozen=True)
class Thresholds:
    dormant_days: int = 90
    stale_key_days: int = 180
    approved_regions: tuple[str, ...] = ("me-central-1", "uaenorth", "uaecentral", "me-central1")

    def as_dict(self) -> dict[str, Any]:
        return {
            "dormant_days": self.dormant_days,
            "stale_key_days": self.stale_key_days,
            "approved_regions": sorted(self.approved_regions),
        }


# ---------------------------------------------------------------------------
# EstateView: one snapshot month, fully in memory, with indexes
# ---------------------------------------------------------------------------


@dataclass
class EstateView:
    month: int
    identities: dict[str, IdentityRow] = field(default_factory=dict)
    principals: dict[str, PrincipalRow] = field(default_factory=dict)
    grants: list[GrantRow] = field(default_factory=list)
    activity: list[ActivityRow] = field(default_factory=list)
    credentials: list[CredentialRow] = field(default_factory=list)
    resources: dict[str, ResourceRow] = field(default_factory=dict)
    projects: dict[str, ProjectRow] = field(default_factory=dict)
    exceptions: list[ExceptionRow] = field(default_factory=list)
    events: list[EventRow] = field(
        default_factory=list
    )  # all months ≤ self.month, ordered by (month, event_id)

    _grants_by_identity: dict[str, list[GrantRow]] = field(default_factory=dict, repr=False)
    _activity_by_identity: dict[str, list[ActivityRow]] = field(default_factory=dict, repr=False)
    _credentials_by_identity: dict[str, list[CredentialRow]] = field(default_factory=dict, repr=False)
    _exceptions_by_identity: dict[str, list[ExceptionRow]] = field(default_factory=dict, repr=False)
    _events_by_identity: dict[str, list[EventRow]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.reindex()

    def reindex(self) -> None:
        g: dict[str, list[GrantRow]] = defaultdict(list)
        for row in self.grants:
            g[row.identity_id].append(row)
        self._grants_by_identity = dict(g)
        a: dict[str, list[ActivityRow]] = defaultdict(list)
        for act in self.activity:
            a[act.identity_id].append(act)
        self._activity_by_identity = dict(a)
        c: dict[str, list[CredentialRow]] = defaultdict(list)
        for cred in self.credentials:
            c[cred.identity_id].append(cred)
        self._credentials_by_identity = dict(c)
        e: dict[str, list[ExceptionRow]] = defaultdict(list)
        for exc in self.exceptions:
            e[exc.identity_id].append(exc)
        self._exceptions_by_identity = dict(e)
        ev: dict[str, list[EventRow]] = defaultdict(list)
        for evt in sorted(self.events, key=lambda x: (x.month, x.event_id)):
            if evt.identity_id:
                ev[evt.identity_id].append(evt)
        self._events_by_identity = dict(ev)

    # -- helpers used by rules / scoring ---------------------------------------
    @property
    def as_of(self) -> date:
        """The snapshot's month-end date; dormancy and expiry compare against this."""
        return month_end(self.month)

    def grants_for(self, identity_id: str, *, active_only: bool = True) -> list[GrantRow]:
        rows = self._grants_by_identity.get(identity_id, [])
        return [r for r in rows if r.active] if active_only else list(rows)

    def activity_for(self, identity_id: str) -> list[ActivityRow]:
        return list(self._activity_by_identity.get(identity_id, []))

    def last_activity(self, identity_id: str) -> date | None:
        dates = [a.last_activity_at for a in self.activity_for(identity_id) if a.last_activity_at]
        return max(dates) if dates else None

    def credentials_for(self, identity_id: str) -> list[CredentialRow]:
        return list(self._credentials_by_identity.get(identity_id, []))

    def exceptions_for(self, identity_id: str, *, types: tuple[str, ...] | None = None) -> list[ExceptionRow]:
        rows = self._exceptions_by_identity.get(identity_id, [])
        return [r for r in rows if types is None or r.exception_type in types]

    def valid_exception(self, identity_id: str, *types: str) -> ExceptionRow | None:
        """First unexpired register entry of one of the given types, else None."""
        for row in self.exceptions_for(identity_id, types=types or None):
            if row.is_valid_on(self.as_of):
                return row
        return None

    def expired_exception(self, identity_id: str, *types: str) -> ExceptionRow | None:
        for row in self.exceptions_for(identity_id, types=types or None):
            if not row.is_valid_on(self.as_of):
                return row
        return None

    def events_for(self, identity_id: str) -> list[EventRow]:
        return list(self._events_by_identity.get(identity_id, []))

    def clouds_for(self, identity_id: str) -> list[str]:
        return sorted({g.cloud for g in self.grants_for(identity_id)})

    def project_for_ref(self, project_ref: str) -> ProjectRow | None:
        for p in self.projects.values():
            if p.project_ref == project_ref:
                return p
        return None
