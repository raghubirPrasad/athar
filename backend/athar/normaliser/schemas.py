"""Upload validation (SPEC §15.2) and file decoding for the normaliser. Pure.

`validate_upload(provider, filename, data, max_bytes)` is the only gate between an untrusted
upload (SPEC §13 POST /ingest/upload) and the parsers. It raises `UploadValidationError` — and
nothing else — with a stable `code`:

  upload.too_large · upload.empty · upload.unknown_provider · upload.wrong_provider ·
  upload.unknown_file · upload.not_utf8 · upload.malformed_json · upload.too_deep ·
  upload.wrong_shape · upload.missing_field · upload.invalid_field · upload.invalid

Unknown / extra fields are allowed everywhere (writers MAY emit realistic filler, SPEC §4.6).
Duplicate principals are tolerated (last wins) and reported in `warnings`; NaN / absent dates
become None downstream; a CSV cell starting with `= + - @` is accepted and flagged (exports do
the escaping, SPEC §15.2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from athar.hashing import sha256_hex
from athar.normaliser.parsers import aws as aws_p
from athar.normaliser.parsers import azure as az_p
from athar.normaliser.parsers import gcp as gcp_p
from athar.normaliser.parsers.common import read_csv_rows
from athar.normaliser.parsers.hr import EMPLOYEE_COLUMNS, EXCEPTION_COLUMNS, PROJECT_COLUMNS

MAX_JSON_DEPTH = 32
PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "hr")
_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@")


class UploadValidationError(Exception):
    """Stable machine-readable rejection of an upload (rendered as RFC 7807 by the API lane)."""

    def __init__(self, code: str, detail: str, field: str | None = None) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.field = field


@dataclass
class ValidatedFile:
    provider: str
    filename: str  # canonical relative name, e.g. `authorization-details.json`, `nda-x/iam-policy.json`
    kind: str  # json | csv
    content: Any  # decoded: dict / list for JSON, list[dict[str, str]] for CSV, str for HR CSVs
    sha256: str
    size: int
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# pydantic v2 schemas — only the SPEC §4.6 required fields; everything else is allowed
# ---------------------------------------------------------------------------


class _Loose(BaseModel):
    model_config = ConfigDict(extra="allow")


class AwsStatement(_Loose):
    Effect: str


class AwsPolicyDocument(_Loose):
    Statement: list[AwsStatement] | AwsStatement


class AwsInlinePolicy(_Loose):
    PolicyName: str
    PolicyDocument: AwsPolicyDocument


class AwsAttachedPolicy(_Loose):
    PolicyName: str | None = None
    PolicyArn: str | None = None


class AwsUserDetail(_Loose):
    UserName: str
    Arn: str
    UserPolicyList: list[AwsInlinePolicy] = []
    GroupList: list[str] = []
    AttachedManagedPolicies: list[AwsAttachedPolicy] = []


class AwsGroupDetail(_Loose):
    GroupName: str
    Arn: str
    GroupPolicyList: list[AwsInlinePolicy] = []
    AttachedManagedPolicies: list[AwsAttachedPolicy] = []


class AwsRoleDetail(_Loose):
    RoleName: str
    Arn: str
    RolePolicyList: list[AwsInlinePolicy] = []
    AttachedManagedPolicies: list[AwsAttachedPolicy] = []


class AwsPolicy(_Loose):
    PolicyName: str
    Arn: str


class AwsAuthorizationDetails(_Loose):
    UserDetailList: list[AwsUserDetail] = []
    GroupDetailList: list[AwsGroupDetail] = []
    RoleDetailList: list[AwsRoleDetail] = []
    Policies: list[AwsPolicy] = []


class AwsServiceLastAccessedEntry(_Loose):
    Arn: str
    ServicesLastAccessed: list[dict[str, Any]] = []


class AzureRoleAssignment(_Loose):
    principalId: str  # noqa: N815 — provider field name
    scope: str
    roleDefinitionId: str | None = None  # noqa: N815
    roleDefinitionName: str | None = None  # noqa: N815


class AzureEntraUser(_Loose):
    id: str
    userPrincipalName: str  # noqa: N815


class AzureRoleDefinition(_Loose):
    name: str | None = None
    id: str | None = None
    roleName: str | None = None  # noqa: N815


class AzureResourceGroup(_Loose):
    name: str
    location: str


class AzureActivityEntry(_Loose):
    principalId: str  # noqa: N815
    resourceProvider: str  # noqa: N815


class GcpBinding(_Loose):
    role: str
    members: list[str] = []


class GcpIamPolicy(_Loose):
    bindings: list[GcpBinding] = []


class GcpProject(_Loose):
    projectId: str  # noqa: N815


class GcpKey(_Loose):
    name: str


class GcpActivityEntry(_Loose):
    member: str
    role: str | None = None


class Inventory(_Loose):
    sensitivity: str | None = None
    region: str | None = None


# file name → (kind, schema, is_list)
_FILES: dict[str, dict[str, tuple[str, type[BaseModel] | None, bool]]] = {
    "aws": {
        aws_p.AUTH_DETAILS: ("json", AwsAuthorizationDetails, False),
        aws_p.CREDENTIAL_REPORT: ("csv", None, False),
        aws_p.SERVICE_LAST_ACCESSED: ("json", AwsServiceLastAccessedEntry, True),
        aws_p.RESOURCES: ("json", Inventory, True),
    },
    "azure": {
        az_p.ROLE_ASSIGNMENTS: ("json", AzureRoleAssignment, True),
        az_p.ROLE_DEFINITIONS: ("json", AzureRoleDefinition, True),
        az_p.ENTRA_USERS: ("json", AzureEntraUser, True),
        az_p.RESOURCE_GROUPS: ("json", AzureResourceGroup, True),
        az_p.ACTIVITY_SUMMARY: ("json", AzureActivityEntry, True),
        az_p.RESOURCES: ("json", Inventory, True),
    },
    "gcp": {
        gcp_p.PROJECTS: ("json", GcpProject, True),
        gcp_p.SA_KEYS: ("json", GcpKey, True),
        gcp_p.ACTIVITY: ("json", GcpActivityEntry, True),
        gcp_p.RESOURCES: ("json", Inventory, True),
        gcp_p.IAM_POLICY: ("json", GcpIamPolicy, False),
        gcp_p.CUSTOM_ROLES: ("json", None, True),
    },
    "hr": {
        "employees.csv": ("csv", None, False),
        "projects.csv": ("csv", None, False),
        "exceptions.csv": ("csv", None, False),
    },
}
_CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    aws_p.CREDENTIAL_REPORT: ("user", "arn"),
    "employees.csv": ("employee_id", "email", "display_name", "department", "employment_type", "status"),
    "projects.csv": ("project_id", "name", "status", "cloud"),
    "exceptions.csv": ("identity_id", "exception_type", "approved_by"),
}
_ALL_CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "employees.csv": EMPLOYEE_COLUMNS,
    "projects.csv": PROJECT_COLUMNS,
    "exceptions.csv": EXCEPTION_COLUMNS,
}


def canonical_filename(provider: str, filename: str) -> str:
    """`some/dir/authorization-details.json` → `authorization-details.json`; GCP policies keep the
    project directory (`<project>/iam-policy.json`, `<project>/roles.json`)."""
    parts = [p for p in filename.replace("\\", "/").split("/") if p and p not in (".", "..")]
    if not parts:
        return ""
    base = parts[-1]
    if provider == "gcp" and base in (gcp_p.IAM_POLICY, gcp_p.CUSTOM_ROLES) and len(parts) >= 2:
        return f"{parts[-2]}/{base}"
    return base


def _owner_of(base: str) -> str | None:
    for prov, files in _FILES.items():
        if base in files:
            return prov
    return None


def json_depth(obj: Any) -> int:
    """Nesting depth of a decoded JSON value, iteratively (no recursion limit)."""
    depth = 0
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, d = stack.pop()
        depth = max(depth, d)
        if isinstance(node, dict):
            stack.extend((v, d + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, d + 1) for v in node)
    return depth


def _decode_json(text: str, filename: str) -> Any:
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise UploadValidationError(
            "upload.too_deep", f"{filename}: JSON nesting exceeds {MAX_JSON_DEPTH}"
        ) from exc
    except ValueError as exc:
        raise UploadValidationError(
            "upload.malformed_json", f"{filename}: {exc.__class__.__name__}: {exc}"
        ) from exc


def _first_error(exc: ValidationError) -> tuple[str, str, str]:
    """(code, field path, message) for the first pydantic error."""
    errors = exc.errors()
    if not errors:
        return "upload.invalid_field", "", "invalid"
    first = errors[0]
    path = "/".join(str(p) for p in first.get("loc", ()))
    kind = str(first.get("type", ""))
    code = "upload.missing_field" if kind == "missing" else "upload.invalid_field"
    return code, path, str(first.get("msg", "invalid"))


def _validate_json(provider: str, name: str, obj: Any, warnings: list[str]) -> Any:
    _kind, schema, is_list = _FILES[provider][name]
    if schema is None:
        return obj
    if is_list:
        if isinstance(obj, dict) and isinstance(obj.get("value"), list):
            obj = obj["value"]  # Graph / ARM paged shape
        if not isinstance(obj, list):
            raise UploadValidationError("upload.wrong_shape", f"{name}: expected a JSON array", name)
        for i, item in enumerate(obj):
            if not isinstance(item, dict):
                raise UploadValidationError("upload.wrong_shape", f"{name}[{i}]: expected an object", f"/{i}")
            try:
                schema.model_validate(item)
            except ValidationError as exc:
                code, path, msg = _first_error(exc)
                raise UploadValidationError(code, f"{name}[{i}]: {path}: {msg}", f"/{i}/{path}") from exc
        _report_duplicates(name, obj, warnings)
        return obj
    if not isinstance(obj, dict):
        raise UploadValidationError("upload.wrong_shape", f"{name}: expected a JSON object", name)
    try:
        schema.model_validate(obj)
    except ValidationError as exc:
        code, path, msg = _first_error(exc)
        raise UploadValidationError(code, f"{name}: {path}: {msg}", f"/{path}") from exc
    if name == aws_p.AUTH_DETAILS:
        _report_duplicates(name, obj.get("UserDetailList") or [], warnings, key="Arn")
    return obj


_DUP_KEYS: dict[str, str] = {
    az_p.ROLE_ASSIGNMENTS: "id",
    az_p.ENTRA_USERS: "id",
    gcp_p.PROJECTS: "projectId",
    gcp_p.SA_KEYS: "name",
}


def _report_duplicates(name: str, items: list[Any], warnings: list[str], key: str | None = None) -> None:
    key = key or _DUP_KEYS.get(name)
    if key is None:
        return
    seen: set[str] = set()
    for item in items:
        value = str(item.get(key, "")) if isinstance(item, dict) else ""
        if value and value in seen:
            warnings.append(f"{name}: duplicate {key} {value} (last wins)")
        seen.add(value)


def _validate_csv(name: str, text: str, warnings: list[str]) -> list[dict[str, str]]:
    header, rows = read_csv_rows(text)
    if not header:
        raise UploadValidationError("upload.empty", f"{name}: no header row", name)
    required = _CSV_COLUMNS.get(name, ())
    missing = [c for c in required if c not in header]
    if missing:
        raise UploadValidationError(
            "upload.missing_field", f"{name}: missing column(s) {', '.join(missing)}", missing[0]
        )
    expected = _ALL_CSV_COLUMNS.get(name)
    if expected:
        absent = [c for c in expected if c not in header]
        if absent:
            warnings.append(f"{name}: optional column(s) absent: {', '.join(absent)}")
    for n, row in enumerate(rows, start=1):
        for col, value in row.items():
            if value.startswith(_FORMULA_PREFIXES) and not _looks_numeric(value):
                warnings.append(
                    f"{name}: row {n} column {col} starts with a formula character; stored verbatim"
                )
    key = "user" if name == aws_p.CREDENTIAL_REPORT else ("employee_id" if name == "employees.csv" else None)
    if key:
        seen: set[str] = set()
        for row in rows:
            v = row.get(key, "")
            if v and v in seen:
                warnings.append(f"{name}: duplicate {key} {v} (last wins)")
            seen.add(v)
    return rows


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def validate_upload(provider: str, filename: str, data: bytes, max_bytes: int) -> ValidatedFile:
    """Validate one uploaded file. Raises `UploadValidationError` and nothing else."""
    try:
        return _validate(provider, filename, data, max_bytes)
    except UploadValidationError:
        raise
    except Exception as exc:  # pragma: no cover — belt and braces: never leak another exception type
        raise UploadValidationError("upload.invalid", f"{filename}: {exc.__class__.__name__}") from exc


def _validate(provider: str, filename: str, data: bytes, max_bytes: int) -> ValidatedFile:
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        raise UploadValidationError("upload.unknown_provider", f"unknown provider {provider!r}", "provider")
    if not isinstance(data, (bytes, bytearray)):
        raise UploadValidationError("upload.invalid", f"{filename}: body is not bytes")
    size = len(data)
    if size > max_bytes:
        raise UploadValidationError(
            "upload.too_large", f"{filename}: {size} bytes exceeds the {max_bytes} byte limit"
        )
    name = canonical_filename(provider, filename or "")
    base = name.rsplit("/", 1)[-1]
    if base not in _FILES[provider]:
        owner = _owner_of(base)
        if owner and owner != provider:
            raise UploadValidationError(
                "upload.wrong_provider", f"{base} belongs to provider {owner!r}, not {provider!r}", "provider"
            )
        raise UploadValidationError(
            "upload.unknown_file", f"{base!r} is not a {provider} export file", "file"
        )
    if size == 0 or not bytes(data).strip():
        raise UploadValidationError("upload.empty", f"{filename}: empty file")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UploadValidationError(
            "upload.not_utf8", f"{filename}: not valid UTF-8 (byte {exc.start})"
        ) from exc
    warnings: list[str] = []
    kind = _FILES[provider][base][0]
    if kind == "csv":
        rows = _validate_csv(base, text, warnings)
        content: Any = text if provider == "hr" else rows
    else:
        obj = _decode_json(text, base)
        depth = json_depth(obj)
        if depth > MAX_JSON_DEPTH:
            raise UploadValidationError(
                "upload.too_deep", f"{base}: JSON nesting depth {depth} exceeds {MAX_JSON_DEPTH}"
            )
        content = _validate_json(provider, base, obj, warnings)
    return ValidatedFile(
        provider=provider,
        filename=name,
        kind=kind,
        content=content,
        sha256=sha256_hex(bytes(data)),
        size=size,
        warnings=warnings,
    )


def known_files(provider: str) -> tuple[str, ...]:
    return tuple(_FILES.get(provider, {}))
