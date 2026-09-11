"""Normaliser pipeline: native files → canonical rows (SPEC §4.6 → §5, §6). Pure file→rows.

  normalise_month(estate_dir, month)            one snapshot month on disk → NormalisedMonth
  normalise_provider(provider, month, files, hr) one provider's uploaded files → ProviderRows
  to_estate_view(nm)                             NormalisedMonth → in-memory EstateView

Nothing here touches a database, the clock or the network; `upsert.upsert_month` persists.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from athar.clock import EPOCH, month_of
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
from athar.hashing import sha256_hex
from athar.log import get_logger
from athar.normaliser import ids
from athar.normaliser.linker import link_principals, synthetic_identities
from athar.normaliser.mappings import UNKNOWN
from athar.normaliser.parsers import aws as aws_p
from athar.normaliser.parsers import azure as az_p
from athar.normaliser.parsers import gcp as gcp_p
from athar.normaliser.parsers.aws import merge_activity
from athar.normaliser.parsers.common import dominant_category, max_date
from athar.normaliser.parsers.hr import parse_hr
from athar.normaliser.schemas import PROVIDERS, UploadValidationError, ValidatedFile, validate_upload
from athar.normaliser.types import (
    UNMAPPED_ACTIONS_KEY,
    HrBundle,
    HrEmployee,
    ProviderParse,
    RawPrincipal,
    UnmappedAction,
)

log = get_logger(__name__)

CLOUD_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp")
NO_LIMIT = 1 << 31  # files read from the estate directory are trusted generator output


class NormaliserError(Exception):
    """A month directory is missing or unreadable (never raised for odd *content*)."""


@dataclass
class ProviderRows:
    """Canonical rows for one provider and month (SPEC §13 POST /ingest/upload)."""

    cloud: str
    month: int
    identities: list[IdentityRow] = field(default_factory=list)  # synthetic svc:/unlinked: only
    principals: list[PrincipalRow] = field(default_factory=list)
    grants: list[GrantRow] = field(default_factory=list)
    activity: list[ActivityRow] = field(default_factory=list)
    credentials: list[CredentialRow] = field(default_factory=list)
    resources: list[ResourceRow] = field(default_factory=list)
    unmapped: list[UnmappedAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)


@dataclass
class NormalisedMonth:
    month: int
    clouds: tuple[str, ...] = ()  # providers this ingest carries; upsert reconciles only these
    identities: list[IdentityRow] = field(default_factory=list)
    principals: list[PrincipalRow] = field(default_factory=list)
    grants: list[GrantRow] = field(default_factory=list)
    activity: list[ActivityRow] = field(default_factory=list)
    credentials: list[CredentialRow] = field(default_factory=list)
    resources: list[ResourceRow] = field(default_factory=list)
    projects: list[ProjectRow] = field(default_factory=list)
    exceptions: list[ExceptionRow] = field(default_factory=list)
    events: list[EventRow] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)
    unmapped: list[UnmappedAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity rows from HR (SPEC §5.1 identities)
# ---------------------------------------------------------------------------


def _month_or_none(d: Any) -> int | None:
    if d is None:
        return None
    m = month_of(d)
    return m if m >= 1 else None


def identity_from_hr(
    emp: HrEmployee,
    month: int,
    *,
    mfa_observations: Iterable[bool] = (),
    project: ProjectRow | None = None,
) -> IdentityRow:
    """HR row → IdentityRow.

    MFA rule: `mfa_enforced` is True when every provider that reports an MFA state for one of the
    identity's principals reports it enforced (AWS credential report `mfa_active`, an Entra export
    MFA hint). A provider that reports nothing is not evidence of absence, so a human with no
    observation at all is assumed enforced; service identities never are (R9 is humans only).
    Months: `hire_month` is None before the simulated epoch; `departure_month` is clamped to 1 so a
    pre-epoch departure still counts as departed; `contract_end_month` is clamped to 0 (expired).
    """
    obs = list(mfa_observations)
    is_service = emp.is_service
    mfa = all(obs) if obs else not is_service
    departed = emp.status == "departed"
    departure = _month_or_none(emp.end_date) if departed else None
    if departed and departure is None and emp.end_date is not None:
        departure = 1
    contract_end = None
    if emp.contract_end is not None:
        contract_end = max(0, month_of(emp.contract_end)) if emp.contract_end >= EPOCH else 0
    tags: dict[str, Any] = {
        "email": emp.email or "",
        "title": emp.title,
        "manager_id": emp.manager_id or "",
        **emp.extra,
    }
    if project is not None:
        tags["project"] = project.project_id
        tags["project_ref"] = project.project_ref
    return IdentityRow(
        identity_id=emp.employee_id,
        display_name=emp.display_name,
        identity_type="service" if is_service else "human",
        department=emp.department,
        employment_type=emp.employment_type,
        employment_status=emp.status,
        hire_month=_month_or_none(emp.start_date),
        departure_month=departure,
        external=emp.employment_type == "contractor" or emp.department == "Contractors",
        mfa_enforced=mfa,
        tags=tags,
        contract_end_month=contract_end,
        first_seen_month=month,
        last_seen_month=month,
    )


# ---------------------------------------------------------------------------
# Assembly: raw provider rows + HR → canonical rows
# ---------------------------------------------------------------------------


@dataclass
class _Assembled:
    identities: list[IdentityRow]
    principals: list[PrincipalRow]
    grants: list[GrantRow]
    activity: list[ActivityRow]
    credentials: list[CredentialRow]
    resources: list[ResourceRow]
    unmapped: list[UnmappedAction]
    warnings: list[str]


def _derived_resources(cloud: str, grants: list[GrantRow], month: int) -> list[ResourceRow]:
    """Without an inventory, resource-level scope refs become resources (region None, low)."""
    out: dict[str, ResourceRow] = {}
    for g in sorted(grants, key=lambda x: x.grant_id):
        if g.cloud != cloud or g.scope_level != "resource":
            continue
        ref = g.scope_ref.rstrip("*").rstrip("/") or g.scope_ref
        if not ref or ref in out:
            continue
        if cloud == "aws":
            category = aws_p.category_of_ref_service(cloud, aws_p.arn_service(ref), UNKNOWN)
            project = aws_p.arn_account(ref)
        elif cloud == "azure":
            category = az_p.category_of_azure_ref(ref)
            project = az_p.subscription_of(ref)
        else:
            category = gcp_p.category_of_gcp_ref(ref)
            project = gcp_p.project_of_ref(ref)
        if category == UNKNOWN:
            category = dominant_category(((g.service_category, g.verb),))
        out[ref] = ResourceRow(
            resource_ref=ref,
            cloud=cloud,
            service_category=category,
            region=None,
            project_ref=project,
            sensitivity="low",
            snapshot_month=month,
        )
    return [out[k] for k in sorted(out)]


def assemble(
    month: int, parses: list[ProviderParse], hr: HrBundle, *, emit_hr_identities: bool = True
) -> _Assembled:
    """Link principals, then mint canonical rows. Deterministic: every list is sorted."""
    raw_principals: list[RawPrincipal] = [p for parse in parses for p in parse.principals]
    entra: dict[str, dict[str, Any]] = {}
    for parse in parses:
        entra.update(parse.entra_users)
    linked = link_principals(raw_principals, hr, entra)
    identity_of = {p.principal_ref: p.identity_id or "" for p in linked}
    raw_by_ref = {p.principal_ref: p for p in raw_principals}

    # identities: HR rows (with MFA observations and service-account projects) + synthetic ones
    mfa_obs: dict[str, list[bool]] = {}
    project_of_identity: dict[str, ProjectRow] = {}
    for row in linked:
        raw = raw_by_ref[row.principal_ref]
        if raw.mfa is not None and row.identity_id:
            mfa_obs.setdefault(row.identity_id, []).append(raw.mfa)
        prj = hr.project_for(raw.project_hint)
        if prj is not None and row.identity_id and row.identity_id not in project_of_identity:
            project_of_identity[row.identity_id] = prj
    identities: list[IdentityRow] = []
    if emit_hr_identities:
        identities.extend(
            identity_from_hr(
                emp,
                month,
                mfa_observations=mfa_obs.get(emp.employee_id, ()),
                project=project_of_identity.get(emp.employee_id) if emp.is_service else None,
            )
            for emp in hr.employees
        )
    identities.extend(synthetic_identities(raw_principals, linked, hr, month))
    identities.sort(key=lambda r: r.identity_id)

    # grants
    grants: dict[str, GrantRow] = {}
    for parse in parses:
        for rg in sorted(
            parse.grants, key=lambda g: (g.principal_ref, g.source_file, g.source_pointer, g.scope_ref)
        ):
            identity_id = identity_of.get(rg.principal_ref)
            if not identity_id:
                continue
            active = raw_by_ref[rg.principal_ref].enabled
            for category, verb in rg.pairs:
                gid = ids.grant_id(
                    rg.principal_ref, rg.cloud, category, verb, rg.scope_ref, rg.granted_via, month
                )
                if gid in grants:
                    continue  # same natural key from another statement: first (sorted) source wins
                snippet = dict(rg.raw_snippet)
                if verb == UNKNOWN and rg.unmapped:
                    # Only this row is the mapping miss; the statement's other actions mapped fine.
                    snippet[UNMAPPED_ACTIONS_KEY] = sorted(set(rg.unmapped))
                grants[gid] = GrantRow(
                    grant_id=gid,
                    identity_id=identity_id,
                    principal_ref=rg.principal_ref,
                    cloud=rg.cloud,
                    service_category=category,
                    verb=verb,
                    scope_level=rg.scope_level,
                    scope_ref=rg.scope_ref,
                    region=rg.region,
                    effect=rg.effect,
                    granted_via=rg.granted_via,
                    snapshot_month=month,
                    raw_snippet=snippet,
                    source_file=rg.source_file,
                    source_pointer=rg.source_pointer,
                    active=active,
                )
    grant_rows = [grants[k] for k in sorted(grants)]

    # activity per (identity, cloud, category)
    merged: dict[tuple[str, str, str], ActivityRow] = {}
    for parse in parses:
        for act in merge_activity(parse.activity):
            identity_id = identity_of.get(act.principal_ref)
            if not identity_id:
                continue
            key = (identity_id, act.cloud, act.service_category)
            prev = merged.get(key)
            merged[key] = ActivityRow(
                identity_id=identity_id,
                cloud=act.cloud,
                service_category=act.service_category,
                snapshot_month=month,
                last_activity_at=max_date(prev.last_activity_at, act.last_activity_at)
                if prev
                else act.last_activity_at,
                operation_count=(prev.operation_count if prev else 0) + act.operation_count,
            )
    activity_rows = [merged[k] for k in sorted(merged)]

    # credentials
    creds: dict[str, CredentialRow] = {}
    for parse in parses:
        for rc in parse.credentials:
            identity_id = identity_of.get(rc.principal_ref)
            if not identity_id or rc.credential_ref in creds:
                continue
            creds[rc.credential_ref] = CredentialRow(
                credential_ref=rc.credential_ref,
                identity_id=identity_id,
                cloud=rc.cloud,
                kind=rc.kind,
                created_at=rc.created_at,
                last_rotated_at=rc.last_rotated_at,
                last_used_at=rc.last_used_at,
                active=rc.active,
                snapshot_month=month,
            )
    credential_rows = [creds[k] for k in sorted(creds)]

    # resources: inventory when present, else derived from resource-level scopes
    resources: dict[str, ResourceRow] = {}
    for parse in parses:
        rows = parse.resources or _derived_resources(parse.cloud, grant_rows, month)
        for res in rows:
            resources.setdefault(res.resource_ref, res)
    resource_rows = [resources[k] for k in sorted(resources)]

    unmapped = sorted(
        (u for parse in parses for u in parse.unmapped),
        key=lambda u: (u.cloud, u.principal_ref, u.raw, u.source_pointer),
    )
    warnings = [w for parse in parses for w in parse.warnings]
    return _Assembled(
        identities, linked, grant_rows, activity_rows, credential_rows, resource_rows, unmapped, warnings
    )


# ---------------------------------------------------------------------------
# Decoding files
# ---------------------------------------------------------------------------


def _parse_provider(cloud: str, files: dict[str, ValidatedFile], month: int) -> ProviderParse:
    content = {name: vf.content for name, vf in files.items()}
    if cloud == "aws":
        parse = aws_p.parse_aws(content, month)
    elif cloud == "azure":
        parse = az_p.parse_azure(content, month)
    else:
        parse = gcp_p.parse_gcp(content, month)
    for vf in files.values():
        parse.warnings.extend(vf.warnings)
    return parse


def _decode_bytes(provider: str, files: dict[str, bytes]) -> dict[str, ValidatedFile]:
    out: dict[str, ValidatedFile] = {}
    for name in sorted(files):
        vf = validate_upload(provider, name, files[name], NO_LIMIT)
        out[vf.filename] = vf
    return out


def _read_dir_files(provider_dir: Path) -> dict[str, bytes]:
    if not provider_dir.is_dir():
        return {}
    out: dict[str, bytes] = {}
    for path in sorted(provider_dir.rglob("*")):
        if path.is_file():
            out[path.relative_to(provider_dir).as_posix()] = path.read_bytes()
    return out


def _decode_dir(provider: str, provider_dir: Path, warnings: list[str]) -> dict[str, ValidatedFile]:
    out: dict[str, ValidatedFile] = {}
    for name, data in _read_dir_files(provider_dir).items():
        try:
            vf = validate_upload(provider, name, data, NO_LIMIT)
        except UploadValidationError as exc:
            if exc.code == "upload.unknown_file":
                continue  # filler the writers emit that ATHAR does not read
            warnings.append(f"{provider}/{name}: {exc.code}: {exc.detail}")
            log.warning("skipping file", extra={"provider": provider, "file": name, "code": exc.code})
            continue
        out[vf.filename] = vf
    return out


def _hr_bundle(hr_dir: Path, warnings: list[str]) -> HrBundle:
    files = _decode_dir("hr", hr_dir, warnings)
    return parse_hr({name: str(vf.content) for name, vf in files.items()}, warnings)


def file_hashes(month_dir: Path) -> dict[str, str]:
    """sha256 of every file under the month directory, keyed by posix path relative to it."""
    out: dict[str, str] = {}
    for path in sorted(month_dir.rglob("*")):
        if path.is_file():
            out[path.relative_to(month_dir).as_posix()] = sha256_hex(path.read_bytes())
    return out


# ---------------------------------------------------------------------------
# Events (SPEC §4.2 events.jsonl)
# ---------------------------------------------------------------------------

_EVENT_KEYS: frozenset[str] = frozenset(
    {
        "event_id",
        "month",
        "kind",
        "identity_id",
        "cloud",
        "grants_added",
        "grants_removed",
        "added",
        "removed",
        "trigger",
        "note",
    }
)


def read_events(path: Path, up_to_month: int, warnings: list[str] | None = None) -> list[EventRow]:
    """events.jsonl → EventRows for months ≤ `up_to_month`, `grant_delta={"added": [...], "removed": [...]}`
    plus any extra keys the generator wrote (e.g. `credential_ref`). Malformed lines are skipped."""
    if not path.is_file():
        return []
    out: dict[str, EventRow] = {}
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            if warnings is not None:
                warnings.append(f"events.jsonl line {index + 1}: malformed JSON skipped")
            continue
        if not isinstance(obj, dict):
            continue
        try:
            month = int(obj.get("month", 0))
        except (TypeError, ValueError):
            continue
        if month < 1 or month > up_to_month:
            continue
        event_id = str(obj.get("event_id") or ids.event_id(month, index))
        delta: dict[str, Any] = {
            "added": list(obj.get("grants_added") or obj.get("added") or []),
            "removed": list(obj.get("grants_removed") or obj.get("removed") or []),
        }
        delta.update({k: v for k, v in obj.items() if k not in _EVENT_KEYS})
        out[event_id] = EventRow(
            event_id=event_id,
            month=month,
            kind=str(obj.get("kind") or "unknown"),
            identity_id=str(obj["identity_id"]) if obj.get("identity_id") else None,
            cloud=str(obj["cloud"]) if obj.get("cloud") else None,
            grant_delta=delta,
            trigger=str(obj.get("trigger") or "unknown"),
            note=str(obj.get("note") or ""),
        )
    return sorted(out.values(), key=lambda e: (e.month, e.event_id))


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def normalise_month(estate_dir: Path, month: int, thresholds: Thresholds | None = None) -> NormalisedMonth:
    """Read `<estate_dir>/month-NN/{aws,azure,gcp,hr}` (+ `events.jsonl`) into canonical rows.

    `thresholds` is accepted for interface symmetry with the scan; normalisation itself is
    threshold-free (SPEC §7: thresholds re-score in memory without a new ingest).
    """
    estate_dir = Path(estate_dir)
    month_dir = estate_dir / f"month-{month:02d}"
    if not month_dir.is_dir():
        raise NormaliserError(f"no snapshot directory {month_dir}")
    warnings: list[str] = []
    hr = _hr_bundle(month_dir / "hr", warnings)
    clouds = tuple(cloud for cloud in CLOUD_PROVIDERS if (month_dir / cloud).is_dir())
    parses = [
        _parse_provider(cloud, _decode_dir(cloud, month_dir / cloud, warnings), month) for cloud in clouds
    ]
    rows = assemble(month, parses, hr)
    events = read_events(estate_dir / "events.jsonl", month, warnings)
    warnings.extend(rows.warnings)
    log.info(
        "normalised month",
        extra={
            "month": month,
            "identities": len(rows.identities),
            "principals": len(rows.principals),
            "grants": len(rows.grants),
            "unmapped": len(rows.unmapped),
        },
    )
    return NormalisedMonth(
        month=month,
        clouds=clouds,
        identities=rows.identities,
        principals=rows.principals,
        grants=rows.grants,
        activity=rows.activity,
        credentials=rows.credentials,
        resources=rows.resources,
        projects=sorted(hr.projects, key=lambda p: p.project_id),
        exceptions=sorted(hr.exceptions, key=lambda e: e.exception_id),
        events=events,
        file_hashes=file_hashes(month_dir),
        unmapped=rows.unmapped,
        warnings=warnings,
    )


def normalise_provider(
    provider: str, month: int, files: dict[str, bytes], hr: HrBundle | None
) -> ProviderRows:
    """One provider's uploaded files (name → bytes) → canonical rows, linked against `hr`.

    Raises `UploadValidationError` for a file that fails SPEC §15.2 validation. With `hr=None`
    every principal is unlinked (finding R10) — the register is the only way to own a principal.
    """
    cloud = (provider or "").strip().lower()
    if cloud not in CLOUD_PROVIDERS:
        raise UploadValidationError("upload.unknown_provider", f"unknown provider {provider!r}", "provider")
    decoded = _decode_bytes(cloud, files)
    parse = _parse_provider(cloud, decoded, month)
    rows = assemble(month, [parse], hr or HrBundle(), emit_hr_identities=False)
    return ProviderRows(
        cloud=cloud,
        month=month,
        identities=rows.identities,
        principals=rows.principals,
        grants=rows.grants,
        activity=rows.activity,
        credentials=rows.credentials,
        resources=rows.resources,
        unmapped=rows.unmapped,
        warnings=rows.warnings,
        file_hashes={f"{cloud}/{name}": vf.sha256 for name, vf in decoded.items()},
    )


def to_estate_view(nm: NormalisedMonth) -> EstateView:
    """In-memory EstateView for the eval harness and tests (mirrors services.estate_view)."""
    return EstateView(
        month=nm.month,
        identities={r.identity_id: r for r in nm.identities},
        principals={p.principal_ref: p for p in nm.principals},
        grants=list(nm.grants),
        activity=list(nm.activity),
        credentials=list(nm.credentials),
        resources={r.resource_ref: r for r in nm.resources},
        projects={p.project_id: p for p in nm.projects},
        exceptions=list(nm.exceptions),
        events=list(nm.events),
    )


@dataclass
class HrRows:
    """Canonical rows from an uploaded HR feed (SPEC §4.6 hr/*.csv) for one month."""

    month: int
    bundle: HrBundle
    identities: list[IdentityRow] = field(default_factory=list)
    projects: list[ProjectRow] = field(default_factory=list)
    exceptions: list[ExceptionRow] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)


def normalise_hr(month: int, files: dict[str, bytes]) -> HrRows:
    """Uploaded `employees.csv` / `projects.csv` / `exceptions.csv` (name → bytes) → HR rows.

    Raises `UploadValidationError` for a file that fails SPEC §15.2 validation. The returned
    `bundle` is what `normalise_provider` links cloud uploads against; MFA is assumed enforced
    for humans until a provider observation says otherwise (see `identity_from_hr`).
    """
    decoded = _decode_bytes("hr", files)
    warnings: list[str] = []
    bundle = parse_hr({name: str(vf.content) for name, vf in decoded.items()}, warnings)
    for vf in decoded.values():
        warnings.extend(vf.warnings)
    return HrRows(
        month=month,
        bundle=bundle,
        identities=sorted(
            (identity_from_hr(emp, month) for emp in bundle.employees), key=lambda r: r.identity_id
        ),
        projects=sorted(bundle.projects, key=lambda p: p.project_id),
        exceptions=sorted(bundle.exceptions, key=lambda e: e.exception_id),
        warnings=warnings,
        file_hashes={f"hr/{name}": vf.sha256 for name, vf in decoded.items()},
    )


def hr_rows_to_month(rows: HrRows) -> NormalisedMonth:
    """Wrap HrRows as a NormalisedMonth (no clouds → no per-month reconciliation) for `upsert_month`."""
    return NormalisedMonth(
        month=rows.month,
        clouds=(),
        identities=list(rows.identities),
        projects=list(rows.projects),
        exceptions=list(rows.exceptions),
        file_hashes=dict(rows.file_hashes),
        warnings=list(rows.warnings),
    )


def provider_rows_to_month(rows: ProviderRows, hr: HrBundle | None = None) -> NormalisedMonth:
    """Wrap ProviderRows as a NormalisedMonth so `upsert_month` can persist an upload."""
    bundle = hr or HrBundle()
    return NormalisedMonth(
        month=rows.month,
        clouds=(rows.cloud,),
        identities=list(rows.identities),
        principals=list(rows.principals),
        grants=list(rows.grants),
        activity=list(rows.activity),
        credentials=list(rows.credentials),
        resources=list(rows.resources),
        projects=list(bundle.projects),
        exceptions=list(bundle.exceptions),
        events=[],
        file_hashes=dict(rows.file_hashes),
        unmapped=list(rows.unmapped),
        warnings=list(rows.warnings),
    )


__all__ = [
    "PROVIDERS",
    "HrBundle",
    "HrRows",
    "NormalisedMonth",
    "NormaliserError",
    "ProviderRows",
    "UnmappedAction",
    "assemble",
    "file_hashes",
    "hr_rows_to_month",
    "identity_from_hr",
    "normalise_hr",
    "normalise_month",
    "normalise_provider",
    "provider_rows_to_month",
    "read_events",
    "to_estate_view",
]
