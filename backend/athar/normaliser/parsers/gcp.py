"""GCP parser (SPEC §4.6 GCP shapes → §5 rows). Pure.

Inputs:
  projects.json               `[{projectId, name, labels: {region, department, owner, …}}]`
  <project>/iam-policy.json   `gcloud projects get-iam-policy --format=json`
  <project>/roles.json        optional custom roles `[{name, includedPermissions}]`
  service-account-keys.json   `gcloud iam service-accounts keys list` (USER_MANAGED keys only)
  activity.json               IAM Recommender-style `[{project, member, role, lastAuthenticatedTime, …}]`
  resources.json              ATHAR-side inventory `[{ref, service, region, sensitivity, project}]`

`principal_ref` is the binding member as written (`user:…`, `serviceAccount:…`, `group:…`);
scope is `projects/<projectId>` (scope_level project); `granted_via` is `role:<role>`.
"""

from __future__ import annotations

import re
from typing import Any

from athar.normaliser.expand import expand_action
from athar.normaliser.ids import credential_ref, json_pointer, normalise_email
from athar.normaliser.mappings import UNKNOWN, role_pairs, scope_level
from athar.normaliser.parsers.aws import parse_inventory
from athar.normaliser.parsers.common import (
    as_list,
    expand_many,
    lower_tags,
    parse_bool,
    parse_date,
    parse_int,
    sorted_pairs,
    text,
    text_or_none,
)
from athar.normaliser.types import (
    UNKNOWN_PAIR,
    Pair,
    ProviderParse,
    RawActivity,
    RawCredential,
    RawGrant,
    RawPrincipal,
    UnmappedAction,
)

CLOUD = "gcp"
PROJECTS = "projects.json"
SA_KEYS = "service-account-keys.json"
ACTIVITY = "activity.json"
RESOURCES = "resources.json"
IAM_POLICY = "iam-policy.json"
CUSTOM_ROLES = "roles.json"
IDENTITY_CATEGORY = "identity"

_SA_DOMAIN = re.compile(r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com$", re.IGNORECASE)
_KEY_NAME = re.compile(r"serviceAccounts/([^/]+)/keys/([^/]+)$")

_MEMBER_TYPES: dict[str, str] = {
    "user": "user",
    "serviceaccount": "service_account",
    "group": "group",
    "domain": "group",
    "deleted": "user",
}


def member_parts(member: str) -> tuple[str, str]:
    """`serviceAccount:x@p.iam.gserviceaccount.com` → (`service_account`, `x@p…`)."""
    prefix, sep, rest = member.partition(":")
    if not sep:
        return ("group", member)
    if prefix.lower() == "deleted":
        inner_prefix, _, inner_rest = rest.partition(":")
        return (_MEMBER_TYPES.get(inner_prefix.lower(), "user"), inner_rest.split("?", 1)[0])
    return (_MEMBER_TYPES.get(prefix.lower(), "group"), rest)


def sa_project(email: str) -> str | None:
    m = _SA_DOMAIN.search(email or "")
    return m.group(1).lower() if m else None


def project_of_ref(ref: str) -> str | None:
    m = re.search(r"(?:^|/)projects/([^/]+)", ref or "")
    return m.group(1) if m else None


def _role_pairs(role: str, custom: dict[str, list[str]]) -> tuple[tuple[Pair, ...], list[str]]:
    known = role_pairs(CLOUD, role)
    if known:
        return sorted_pairs(set(known)), []
    perms = custom.get(role.lower())
    if perms is not None:
        pairs, unmapped = expand_many(CLOUD, perms)
        pairs.discard(UNKNOWN_PAIR)
        if pairs:
            return sorted_pairs(pairs), unmapped
    got = expand_action(CLOUD, role)
    if got == [UNKNOWN_PAIR]:
        return (UNKNOWN_PAIR,), [role]
    return sorted_pairs(set(got)), [role] if all(v == UNKNOWN for _, v in got) else []


def _custom_roles(files: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, content in files.items():
        if not name.endswith(CUSTOM_ROLES):
            continue
        for rec in as_list(content.get("roles")) if isinstance(content, dict) else as_list(content):
            if isinstance(rec, dict) and text(rec.get("name")):
                out[text(rec.get("name")).lower()] = [
                    text(p) for p in as_list(rec.get("includedPermissions")) if text(p)
                ]
    return out


def _policy_files(files: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """(project id, file name, policy) for every `<project>/iam-policy.json`."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    for name in sorted(files):
        if not name.endswith(IAM_POLICY):
            continue
        content = files[name]
        if not isinstance(content, dict):
            continue
        project = name[: -len(IAM_POLICY)].strip("/") or text(content.get("project")) or "unknown-project"
        out.append((project.rsplit("/", 1)[-1], name, content))
    return out


def parse_gcp(files: dict[str, Any], month: int, source_prefix: str = "gcp/") -> ProviderParse:
    parse = ProviderParse(cloud=CLOUD)
    inventory = files.get(RESOURCES)
    if isinstance(inventory, list):
        parse.resources = parse_inventory(CLOUD, inventory, month, ("ref", "id", "resource_ref", "name"))
        parse.resources = [
            r if r.project_ref else _with_project(r, project_of_ref(r.resource_ref)) for r in parse.resources
        ]

    projects: dict[str, dict[str, Any]] = {}
    for rec in as_list(files.get(PROJECTS)):
        if isinstance(rec, dict) and text(rec.get("projectId")):
            projects[text(rec.get("projectId")).lower()] = rec

    def project_labels(project: str) -> dict[str, str]:
        rec = projects.get(project.lower())
        return lower_tags(rec.get("labels")) if rec else {}

    def project_region(project: str) -> str | None:
        rec = projects.get(project.lower())
        if not rec:
            return None
        return text_or_none(project_labels(project).get("region")) or text_or_none(rec.get("region"))

    custom = _custom_roles(files)
    principals: dict[str, RawPrincipal] = {}

    for project, name, policy in _policy_files(files):
        source = f"{source_prefix}{name}"
        scope = f"projects/{project}"
        region = project_region(project)
        labels = project_labels(project)
        for b_idx, binding in enumerate(as_list(policy.get("bindings"))):
            if not isinstance(binding, dict):
                continue
            role = text(binding.get("role"))
            pairs, unmapped = _role_pairs(role, custom) if role else ((UNKNOWN_PAIR,), ["<missing role>"])
            for m_idx, member in enumerate(as_list(binding.get("members"))):
                member_text = text(member)
                if not member_text:
                    continue
                ptype, ident = member_parts(member_text)
                pointer = json_pointer("bindings", b_idx, "members", m_idx)
                principal = principals.get(member_text)
                if principal is None:
                    email = normalise_email(ident) if "@" in ident else None
                    home = sa_project(ident) if ptype == "service_account" else None
                    principal = RawPrincipal(
                        principal_ref=member_text,
                        cloud=CLOUD,
                        principal_type=ptype,
                        name=ident.split("@", 1)[0] if "@" in ident else ident,
                        email=email,
                        tags={},
                        project_hint=home or (project if ptype == "service_account" else None),
                        raw={"member": member_text, "project": home or project, "projects": []},
                        is_service=ptype == "service_account",
                        source_file=source,
                        source_pointer=pointer,
                    )
                    principals[member_text] = principal
                if ptype == "service_account" and labels.get("owner") and "owner" not in principal.tags:
                    principal.tags["owner"] = labels["owner"]
                seen_projects = principal.raw.setdefault("projects", [])
                if isinstance(seen_projects, list) and project not in seen_projects:
                    seen_projects.append(project)
                for miss in unmapped:
                    parse.unmapped.append(UnmappedAction(CLOUD, member_text, miss, source, pointer))
                snippet: dict[str, Any] = {
                    "raw_action": role,
                    "project": project,
                    "role": role,
                    "member": member_text,
                    "binding": binding,
                }
                parse.grants.append(
                    RawGrant(
                        principal_ref=member_text,
                        cloud=CLOUD,
                        pairs=pairs,
                        scope_ref=scope,
                        scope_level=scope_level(CLOUD, scope),
                        region=region,
                        effect="allow",
                        granted_via=f"role:{role}",
                        raw_snippet=snippet,
                        source_file=source,
                        source_pointer=pointer,
                        unmapped=tuple(unmapped),
                    )
                )

    keys = files.get(SA_KEYS)
    key_list = as_list(keys.get("keys")) if isinstance(keys, dict) else as_list(keys)
    for rec in key_list:
        if not isinstance(rec, dict):
            continue
        key_type = text(rec.get("keyType")).upper()
        if key_type == "SYSTEM_MANAGED":
            continue  # Google-rotated; not a credential the customer manages (SPEC §5.3 credential age)
        name = text(rec.get("name"))
        m = _KEY_NAME.search(name)
        email = m.group(1) if m else text(rec.get("serviceAccount") or rec.get("email"))
        key_id = m.group(2) if m else text(rec.get("keyId") or rec.get("id"))
        if not email or not key_id:
            continue
        member = f"serviceAccount:{email}"
        if member not in principals:
            principals[member] = RawPrincipal(
                principal_ref=member,
                cloud=CLOUD,
                principal_type="service_account",
                name=email.split("@", 1)[0],
                email=normalise_email(email),
                project_hint=sa_project(email),
                raw={"member": member, "project": sa_project(email)},
                is_service=True,
                source_file=f"{source_prefix}{SA_KEYS}",
            )
        created = parse_date(rec.get("validAfterTime"))
        disabled = parse_bool(rec.get("disabled")) or False
        parse.credentials.append(
            RawCredential(
                principal_ref=member,
                credential_ref=credential_ref(CLOUD, "sa_key", key_id),
                cloud=CLOUD,
                kind="sa_key",
                created_at=created,
                last_rotated_at=created,
                last_used_at=parse_date(rec.get("lastUsedTime") or rec.get("lastAuthenticatedTime")),
                active=not disabled,
            )
        )

    activity = files.get(ACTIVITY)
    for rec in as_list(activity.get("insights")) if isinstance(activity, dict) else as_list(activity):
        if not isinstance(rec, dict):
            continue
        member = text(rec.get("member"))
        when = parse_date(rec.get("lastAuthenticatedTime") or rec.get("lastAuthenticated"))
        if not member or when is None:
            continue
        role = text(rec.get("role"))
        pairs, _ = _role_pairs(role, custom) if role else ((UNKNOWN_PAIR,), [])
        categories = sorted({c for c, _ in pairs}) or [UNKNOWN]
        count = parse_int(rec.get("usedPermissionsCount")) or 1
        for category in categories:
            parse.activity.append(RawActivity(member, CLOUD, category, when, count))

    parse.principals = [principals[k] for k in sorted(principals)]
    return parse


def _with_project(row: Any, project: str | None) -> Any:
    from dataclasses import replace

    return replace(row, project_ref=project) if project else row


def category_of_gcp_ref(ref: str) -> str:
    """`//storage.googleapis.com/…` → storage; `projects/p/datasets/x` → data (by path kind)."""
    m = re.match(r"^//([a-z]+)\.googleapis\.com/", ref or "")
    if m:
        service = {"bigquery": "bigquery", "sqladmin": "cloudsql", "cloudkms": "cloudkms"}.get(
            m.group(1), m.group(1)
        )
        got = expand_action(CLOUD, f"{service}.x.get")
        return got[0][0] if got and got[0][0] != UNKNOWN else UNKNOWN
    kinds = {
        "datasets": "data",
        "buckets": "storage",
        "instances": "compute",
        "topics": "data",
        "keyRings": "security",
    }
    for part in (ref or "").split("/"):
        if part in kinds:
            return kinds[part]
    return UNKNOWN
