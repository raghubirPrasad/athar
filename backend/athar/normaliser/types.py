"""Intermediate rows shared by the parsers, the linker and the pipeline (SPEC §5, §6). Pure data.

Parsers turn native files into *raw* rows keyed by `principal_ref`; the linker assigns
identities; the pipeline then mints the canonical `athar.domain` rows. Nothing here touches
a database or the clock.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from athar.domain import ExceptionRow, IdentityRow, ProjectRow, ResourceRow
from athar.normaliser.ids import local_part, normalise_email

Pair = tuple[str, str]
UNKNOWN_PAIR: Pair = ("unknown", "unknown")

SERVICE_EMPLOYMENT = "service"
SERVICE_NAME_PREFIXES: tuple[str, ...] = ("svc-", "sa-", "svc_", "sa_")


# ---------------------------------------------------------------------------
# HR feed (SPEC §4.6) — the linker's reference data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HrEmployee:
    employee_id: str
    email: str | None  # lower-cased, None when absent or not an address
    display_name: str
    department: str
    title: str
    employment_type: str  # staff | contractor | service
    status: str  # active | departed | on_leave
    start_date: date | None
    end_date: date | None
    contract_end: date | None
    manager_id: str | None
    row_number: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def is_service(self) -> bool:
        return self.employment_type == SERVICE_EMPLOYMENT

    @property
    def local_part(self) -> str | None:
        return local_part(self.email) if self.email else None


def _sa_name_keys(name: str) -> set[str]:
    """Every spelling under which an HR service row may name a cloud service account."""
    n = name.strip().lower()
    keys = {n}
    for prefix in SERVICE_NAME_PREFIXES:
        keys.add(f"{prefix}{n}")
        if n.startswith(prefix):
            keys.add(n[len(prefix) :])
    return keys


@dataclass
class HrBundle:
    """Employees, project registry and exception register, with the indexes the linker needs."""

    employees: list[HrEmployee] = field(default_factory=list)
    projects: list[ProjectRow] = field(default_factory=list)
    exceptions: list[ExceptionRow] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Index the feed, dropping any key that names more than one employee.

        An ambiguous identifier must not silently merge two identities: `setdefault` used to hand
        every principal to whichever row came first, so two service accounts sharing an address —
        which happens when two projects share a name — became one identity with a cloud footprint
        neither of them has. A dropped key simply falls through to the next linking rule in SPEC §6,
        and an unlinked principal becomes finding R10, which is the honest answer.
        """
        self.by_email: dict[str, HrEmployee] = {}
        self.by_local_part: dict[str, HrEmployee] = {}
        self.by_id: dict[str, HrEmployee] = {}
        self.service_by_name: dict[str, HrEmployee] = {}
        self.ambiguous: set[str] = set()

        def index(table: dict[str, HrEmployee], key: str, emp: HrEmployee) -> None:
            seen = table.get(key)
            if seen is None:
                table[key] = emp
            elif seen.employee_id != emp.employee_id:
                self.ambiguous.add(key)
                del table[key]

        for emp in self.employees:
            self.by_id[emp.employee_id] = emp
            if emp.email:
                index(self.by_email, emp.email, emp)
                lp = emp.local_part
                if lp:
                    index(self.by_local_part, lp, emp)
            if emp.is_service:
                for key in _sa_name_keys(emp.display_name) | (
                    _sa_name_keys(emp.local_part) if emp.local_part else set()
                ):
                    index(self.service_by_name, key, emp)
        self.project_by_key: dict[str, ProjectRow] = {}
        for prj in self.projects:
            for key in (prj.project_id, prj.project_ref, prj.name):
                if key:
                    self.project_by_key.setdefault(key.strip().lower(), prj)

    def employee_for_email(self, email: str | None) -> HrEmployee | None:
        cleaned = normalise_email(email)
        return self.by_email.get(cleaned) if cleaned else None

    def employee_for_local_part(self, name: str | None) -> HrEmployee | None:
        return self.by_local_part.get(name.strip().lower()) if name else None

    def service_employee_named(self, name: str | None) -> HrEmployee | None:
        if not name:
            return None
        for key in sorted(_sa_name_keys(name)):
            hit = self.service_by_name.get(key)
            if hit is not None:
                return hit
        return None

    def project_for(self, hint: str | None) -> ProjectRow | None:
        return self.project_by_key.get(hint.strip().lower()) if hint else None

    @classmethod
    def from_identities(
        cls,
        identities: Iterable[IdentityRow],
        projects: Iterable[ProjectRow] = (),
        exceptions: Iterable[ExceptionRow] = (),
    ) -> HrBundle:
        """Rebuild the linker's reference data from stored identity rows (the HR email rides in
        `tags["email"]`), so uploads (SPEC §13 POST /ingest/upload) can be linked without the CSV.

        Every stored identity is carried, including the `svc:` rows. The HR feed names service
        accounts by exactly that id, so dropping them made an upload re-mint each one under a
        second id shape — `svc:<project>:<display name>` beside the canonical
        `svc:<project>:<account>` — splitting one account across two CPM rows, with the findings on
        one and the grants on the other. `unlinked:` rows are still dropped: they exist only because
        nothing owned the principal, so offering them back as an owner would make R10 self-healing.
        """
        employees = [
            HrEmployee(
                employee_id=row.identity_id,
                email=normalise_email(str(row.tags.get("email") or ""))
                if isinstance(row.tags, dict)
                else None,
                display_name=row.display_name,
                department=row.department,
                title=str(row.tags.get("title", "")) if isinstance(row.tags, dict) else "",
                employment_type=row.employment_type,
                status=row.employment_status,
                start_date=None,
                end_date=None,
                contract_end=None,
                manager_id=None,
            )
            for row in identities
            if not row.identity_id.startswith("unlinked:")
        ]
        return cls(employees=employees, projects=list(projects), exceptions=list(exceptions))


# ---------------------------------------------------------------------------
# Raw provider rows (before identities are assigned)
# ---------------------------------------------------------------------------


@dataclass
class RawPrincipal:
    principal_ref: str
    cloud: str
    principal_type: str  # user | role | group | service_principal | service_account
    name: str  # UserName / displayName / service-account name
    email: str | None  # UPN / member email when the provider carries one (lower-cased)
    tags: dict[str, str] = field(default_factory=dict)  # lower-cased keys; evidence only, never exceptions
    project_hint: str | None = None  # AWS tag `project`, Azure RG tag, GCP project id
    raw: dict[str, Any] = field(default_factory=dict)
    is_service: bool = False
    enabled: bool = True  # Entra accountEnabled / AWS login+keys; False => grants inactive
    mfa: bool | None = None  # provider observation; None = provider reports nothing
    source_file: str = ""
    source_pointer: str = ""


@dataclass(frozen=True)
class RawGrant:
    principal_ref: str
    cloud: str
    pairs: tuple[Pair, ...]  # sorted (service_category, verb)
    scope_ref: str
    scope_level: str
    region: str | None
    effect: str  # allow | deny
    granted_via: str
    raw_snippet: dict[str, Any]
    source_file: str
    source_pointer: str
    unmapped: tuple[str, ...] = ()  # raw actions / roles the mapping does not know


@dataclass(frozen=True)
class RawActivity:
    principal_ref: str
    cloud: str
    service_category: str
    last_activity_at: date | None
    operation_count: int = 0


@dataclass(frozen=True)
class RawCredential:
    principal_ref: str
    credential_ref: str
    cloud: str
    kind: str  # key | password | sa_key
    created_at: date | None
    last_rotated_at: date | None
    last_used_at: date | None
    active: bool


#: Key under which the pipeline records, on the `verb: unknown` grant row's `raw_snippet`, the raw
#: actions that actually failed to map (SPEC §5.3). A statement may mix mapped and unmapped actions —
#: `s3:GetObject` next to `ce:Frobnicate` — and only this list names the one that produced `unknown`,
#: so R0 reports the action a mapping entry would fix rather than the statement's first action.
#: Read by `athar.detection.common.unmapped_actions`; the two are pinned together by
#: `tests/unit/test_normaliser_pipeline.py` and `tests/unit/test_rules_r0.py`.
UNMAPPED_ACTIONS_KEY = "unmapped_actions"


@dataclass(frozen=True)
class UnmappedAction:
    """A mapping miss (SPEC §5.3 → finding R0), reported alongside the `unknown` grant rows."""

    cloud: str
    principal_ref: str
    raw: str  # action, permission or role as written by the provider
    source_file: str
    source_pointer: str

    def as_dict(self) -> dict[str, str]:
        return {
            "cloud": self.cloud,
            "principal_ref": self.principal_ref,
            "raw": self.raw,
            "source_file": self.source_file,
            "source_pointer": self.source_pointer,
        }


@dataclass
class ProviderParse:
    """Everything one provider's files say, before identity linking."""

    cloud: str
    principals: list[RawPrincipal] = field(default_factory=list)
    grants: list[RawGrant] = field(default_factory=list)
    activity: list[RawActivity] = field(default_factory=list)
    credentials: list[RawCredential] = field(default_factory=list)
    resources: list[ResourceRow] = field(default_factory=list)
    entra_users: dict[str, dict[str, Any]] = field(default_factory=dict)  # Azure objectId → Graph record
    unmapped: list[UnmappedAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
