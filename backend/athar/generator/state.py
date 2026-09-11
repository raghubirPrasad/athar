"""In-memory state of the simulated estate (SPEC §4.2, §4.7, §11.5).

Mutable dataclasses owned by the simulator; a `MonthSnapshot` is a deep copy taken at the
end of each simulated month (the snapshot files describe the state at the END of month N).
`EstateState` is the complete in-memory result that writers, ground truth and tests use.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from athar.clock import month_end
from athar.domain import ALLOWED_ACTIONS

PASSWORD_ROTATION_DAYS = 90  # console passwords rotate on a 90-day policy while the person is employed

REMEDIATION_ACTIONS: tuple[str, ...] = tuple(
    a for a in ALLOWED_ACTIONS if a not in ("tag_as_exception", "no_action_recommended")
)


@dataclass
class SimConstants:
    aws_account_id: str
    azure_tenant_id: str
    azure_subscription_id: str
    azure_sandbox_subscription_id: str  # non-production subscription where region drift lands (SPEC §4.2)
    azure_management_group: str
    gcp_org_id: str
    gcp_folder_id: str
    azure_custom_role_guids: dict[str, str]
    aws_ids: dict[str, str]  # group / role / policy → AWS unique id

    @property
    def azure_subscription_scope(self) -> str:
        return f"/subscriptions/{self.azure_subscription_id}"

    @property
    def azure_sandbox_scope(self) -> str:
        return f"/subscriptions/{self.azure_sandbox_subscription_id}"

    @property
    def azure_mg_scope(self) -> str:
        return f"/providers/Microsoft.Management/managementGroups/{self.azure_management_group}"


@dataclass
class Project:
    project_id: str
    name: str
    slug: str
    department: str
    status: str  # active | retired
    retired_month: int | None
    cloud: str
    project_ref: str  # aws tag / azure RG / gcp projectId
    created_month: int
    kind: str  # department | delivery | dr
    protected: bool
    gcp_number: str
    created_on: date
    region: str
    owner_id: str | None = None


@dataclass
class Identity:
    identity_id: str
    kind: str  # human | service
    display_name: str
    email: str
    department: str
    title: str
    level: str  # member | senior | lead | service
    employment_type: str  # staff | contractor | service
    status: str  # active | departed | on_leave
    start_date: date
    end_date: date | None
    contract_end: date | None
    manager_id: str | None
    clouds: tuple[str, ...]
    mfa: bool
    role_key: tuple[str, str] | None  # (department, level) for humans
    profile: str  # active | light | dormant | never
    dormant_from: int | None
    created_month: int
    departure_month: int | None
    project_id: str | None
    sa_name: str | None
    aws_user_id: str
    azure_object_id: str
    azure_app_id: str | None
    password_offset: int
    decoy: str | None
    protected: bool
    tags: dict[str, str] = field(default_factory=dict)
    removed_clouds: set[str] = field(default_factory=set)
    disabled_clouds: set[str] = field(default_factory=set)
    key_policy: str = "none"  # auto | manual | none
    azure_description: str = ""
    console_disabled: bool = False  # AWS console login disabled by a remediation (SPEC §11.5)

    @property
    def is_human(self) -> bool:
        return self.kind == "human"

    def password_last_changed(self, as_of: date) -> date:
        """Console password rotation on a fixed 90-day cadence anchored on the start date.

        Rotation stops at departure (nobody changes a leaver's password), so a departed
        person's password ages — the same fact the AWS credential report will show.
        """
        cutoff = as_of
        if self.status == "departed" and self.end_date is not None:
            cutoff = min(cutoff, self.end_date)
        anchor = self.start_date + timedelta(days=self.password_offset)
        if anchor > cutoff:
            return self.start_date
        periods = (cutoff - anchor).days // PASSWORD_ROTATION_DAYS
        return anchor + timedelta(days=periods * PASSWORD_ROTATION_DAYS)

    @property
    def username(self) -> str:
        """AWS IAM UserName: HR email local-part for humans (SPEC §6 rule 3), `svc-…` for services."""
        return self.email.split("@")[0]

    def present_in(self, cloud: str) -> bool:
        return cloud in self.clouds and cloud not in self.removed_clouds

    def aws_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:user/{self.username}"

    def gcp_member(self, project_ref: str | None) -> str:
        if self.is_human:
            return f"user:{self.email}"
        return f"serviceAccount:{self.sa_name}@{project_ref}.iam.gserviceaccount.com"

    def principal_refs(self, constants: SimConstants, project_ref: str | None) -> dict[str, tuple[str, ...]]:
        """Every native identifier a normaliser might use as `principal_ref`, per cloud."""
        refs: dict[str, tuple[str, ...]] = {}
        if "aws" in self.clouds:
            refs["aws"] = (self.aws_arn(constants.aws_account_id), self.username, self.aws_user_id)
        if "azure" in self.clouds:
            refs["azure"] = (self.azure_object_id, self.email, self.display_name)
        if "gcp" in self.clouds:
            member = self.gcp_member(project_ref)
            refs["gcp"] = (member, member.split(":", 1)[1])
        return refs


@dataclass
class Grant:
    grant_ref: str
    identity_id: str
    cloud: str
    kind: str  # aws_managed | aws_inline | aws_group | azure_role | gcp_role
    name: str
    scope_ref: str
    scope_level: str
    category: str
    verbs: tuple[str, ...]
    services: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    project_id: str | None
    granted_month: int
    event_id: str | None
    granted_on: date
    native_scopes: tuple[str, ...] = ()  # the provider scope strings emitted (AWS lists bucket + bucket/*)
    native_id: str = ""  # Azure role-assignment GUID
    origin: str = ""  # role:<dept>:<level> | service | incident | drift | decoy
    revoked_month: int | None = None
    revoked_event_id: str | None = None
    wildcard: bool = False
    unmapped: bool = False
    effect: str = "allow"  # SPEC §5.2; a `deny` row cancels an allow at equal or higher scope
    note: str = ""

    @property
    def active(self) -> bool:
        return self.revoked_month is None

    @property
    def is_allow(self) -> bool:
        return self.effect == "allow"

    @property
    def granted_via(self) -> str:
        """SPEC §5.2 `granted_via` vocabulary, as the normaliser is expected to record it."""
        if self.kind == "aws_managed":
            return f"managed_policy:{self.name}"
        if self.kind == "aws_group":
            return f"group:{self.name}"
        if self.kind == "aws_inline":
            return "direct"
        return f"role:{self.name}"

    def is_admin_at_least_project(self) -> bool:
        return "admin" in self.verbs and self.scope_level in ("project", "org", "global")

    def non_read(self) -> bool:
        return any(v != "read" for v in self.verbs)

    def event_refs(self, principal_ref: str) -> list[dict[str, Any]]:
        """One `grants_added` / `grants_removed` entry per native scope string.

        Keys `principal_ref`, `cloud`, `scope_ref`, `granted_via` follow SPEC §5.2 so `drift/diff.py`
        can join a canonical grant row back to the event that caused it.
        """
        scopes = self.native_scopes or (self.scope_ref,)
        service = "" if self.cloud == "gcp" else (self.services[0] if self.services else "")
        return [
            {
                "grant_ref": self.grant_ref,
                "principal_ref": principal_ref,
                "cloud": self.cloud,
                "granted_via": self.granted_via,
                "scope_ref": scope,
                "service": service,
                "name": self.name,
            }
            for scope in scopes
        ]


@dataclass
class Credential:
    credential_ref: str  # aws:key:<AKIA…> | gcp:sa_key:<hex>
    identity_id: str
    cloud: str
    kind: str  # key | sa_key
    key_id: str
    created: date
    last_rotated: date
    last_used: date | None
    active: bool
    policy: str  # auto | manual
    project_ref: str | None = None
    rotated_by_remediation: bool = False


@dataclass
class Resource:
    ref: str
    cloud: str
    service: str
    category: str
    region: str
    sensitivity: str  # low | high
    project_id: str
    project_ref: str
    created_month: int
    name: str
    kind: str  # bucket | table | function | rg | storage_account | key_vault | sql | project | dataset | gcs_bucket
    created_on: date


@dataclass
class ExceptionEntry:
    identity_id: str
    exception_type: str
    approved_by: str
    approved_on: date
    review_date: date | None
    expires_on: date | None
    justification: str


@dataclass
class Event:
    event_id: str
    month: int
    kind: str
    identity_id: str | None
    cloud: str | None
    grants_added: list[dict[str, Any]]
    grants_removed: list[dict[str, Any]]
    trigger: str
    note: str
    extra: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        base: dict[str, Any] = {
            "event_id": self.event_id,
            "month": self.month,
            "kind": self.kind,
            "identity_id": self.identity_id,
            "cloud": self.cloud,
            "grants_added": self.grants_added,
            "grants_removed": self.grants_removed,
            "trigger": self.trigger,
            "note": self.note,
        }
        base.update(self.extra)
        return base


@dataclass
class ActivityRecord:
    last: date | None = None
    ops: dict[int, int] = field(default_factory=dict)  # month → operation count

    def trailing(self, month: int, window: int = 3) -> int:
        return sum(c for m, c in self.ops.items() if month - window < m <= month)


ActivityKey = tuple[str, str, str]  # (identity_id, cloud, service key)


@dataclass(frozen=True)
class RemediationSpec:
    """An applied remediation (SPEC §11.5), replayed at its month on every re-simulation."""

    month: int
    identity_id: str
    action: str
    cloud: str | None
    grant_refs: tuple[dict[str, Any], ...]
    credential_ref: str | None
    note: str

    def __post_init__(self) -> None:
        if self.action not in REMEDIATION_ACTIONS:
            raise ValueError(f"action must be one of {REMEDIATION_ACTIONS}, got {self.action!r}")
        if self.cloud is not None and self.cloud not in ("aws", "azure", "gcp"):
            raise ValueError(f"unknown cloud {self.cloud!r}")
        if self.month < 1:
            raise ValueError("month must be >= 1")
        # accept a plain list from callers / JSON; keep the dataclass hashable
        object.__setattr__(self, "grant_refs", tuple(dict(r) for r in self.grant_refs))

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "remediation",
            "month": self.month,
            "identity_id": self.identity_id,
            "action": self.action,
            "cloud": self.cloud,
            "grant_refs": list(self.grant_refs),
            "credential_ref": self.credential_ref,
            "note": self.note,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RemediationSpec:
        return cls(
            month=int(data["month"]),
            identity_id=str(data["identity_id"]),
            action=str(data["action"]),
            cloud=data.get("cloud"),
            grant_refs=tuple(dict(r) for r in data.get("grant_refs", [])),
            credential_ref=data.get("credential_ref"),
            note=str(data.get("note", "")),
        )


def principal_ref_for(
    ident: Identity, cloud: str, constants: SimConstants, projects: Mapping[str, Project]
) -> str:
    """The native identifier the normaliser records as `principal_ref` (SPEC §5.1, §6)."""
    if cloud == "aws":
        return ident.aws_arn(constants.aws_account_id)
    if cloud == "azure":
        return ident.azure_object_id
    project_ref = projects[ident.project_id].project_ref if ident.project_id else None
    return ident.gcp_member(project_ref)


@dataclass
class MonthSnapshot:
    """State at the END of `month` (SPEC §4.7)."""

    month: int
    identities: dict[str, Identity]
    grants: list[Grant]  # active at month end
    credentials: list[Credential]
    resources: list[Resource]
    projects: dict[str, Project]
    activity: dict[ActivityKey, ActivityRecord]

    def grants_for(self, identity_id: str) -> list[Grant]:
        return [g for g in self.grants if g.identity_id == identity_id]

    def last_activity(self, identity_id: str) -> date | None:
        dates = [rec.last for (iid, _, _), rec in self.activity.items() if iid == identity_id and rec.last]
        return max(dates) if dates else None

    def credentials_for(self, identity_id: str) -> list[Credential]:
        return [c for c in self.credentials if c.identity_id == identity_id]

    @property
    def as_of(self) -> date:
        return month_end(self.month)


@dataclass
class EstateState:
    seed: int
    months: int
    identities_target: int
    constants: SimConstants
    snapshots: list[MonthSnapshot]
    events: list[Event]
    exceptions: list[ExceptionEntry]
    remediations: list[RemediationSpec]
    all_grants: list[Grant]  # every grant ever made, with revocation months (half-life input)
    projects: dict[str, Project]
    identities: dict[str, Identity]

    @property
    def final(self) -> MonthSnapshot:
        return self.snapshots[-1]

    def snapshot(self, month: int) -> MonthSnapshot:
        return self.snapshots[month - 1]


def snapshot_of(
    month: int,
    identities: dict[str, Identity],
    grants: list[Grant],
    credentials: list[Credential],
    resources: list[Resource],
    projects: dict[str, Project],
    activity: dict[ActivityKey, ActivityRecord],
) -> MonthSnapshot:
    return MonthSnapshot(
        month=month,
        identities=copy.deepcopy(identities),
        grants=[copy.copy(g) for g in grants if g.active],
        credentials=copy.deepcopy(credentials),
        resources=copy.deepcopy(resources),
        projects=copy.deepcopy(projects),
        activity=copy.deepcopy(activity),
    )
