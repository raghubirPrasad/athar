"""Azure parser (SPEC §4.6 Azure shapes → §5 rows). Pure.

Inputs:
  role-assignments.json      `az role assignment list --all`
  role-definitions.json      `az role definition list` (built-in and custom; used when a role is
                             not in mappings/azure.yaml: actions minus notActions, plus dataActions)
  entra-users.json           Graph `/users?$select=id,userPrincipalName,displayName,accountEnabled,
                             department,signInActivity` (plus any MFA hint the export carries)
  resource-groups.json       `[{name, location, tags}]` — region and `project` tag for RG scopes
  activity-log-summary.json  `[{principalId, resourceProvider, lastOperationTime, operationCount}]`
  resources.json             ATHAR-side inventory `[{ref, service, region, sensitivity, project}]`

`principal_ref` is the Entra objectId (`principalId`); `granted_via` is `role:<roleDefinitionName>`.
"""

from __future__ import annotations

import re
from typing import Any

from athar.normaliser.expand import expand_actions, subtract
from athar.normaliser.ids import json_pointer, normalise_email
from athar.normaliser.mappings import UNKNOWN, role_pairs, scope_level
from athar.normaliser.parsers.aws import parse_inventory
from athar.normaliser.parsers.common import (
    as_list,
    category_of_ref_service,
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
    RawGrant,
    RawPrincipal,
    UnmappedAction,
)

CLOUD = "azure"
ROLE_ASSIGNMENTS = "role-assignments.json"
ROLE_DEFINITIONS = "role-definitions.json"
ENTRA_USERS = "entra-users.json"
RESOURCE_GROUPS = "resource-groups.json"
ACTIVITY_SUMMARY = "activity-log-summary.json"
RESOURCES = "resources.json"
IDENTITY_CATEGORY = "identity"

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RG = re.compile(r"^/subscriptions/([^/]+)/resourceGroups/([^/]+)", re.IGNORECASE)
_SUB = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)

# Keys under which an Entra export may carry an MFA observation (none is standard on /users).
_MFA_KEYS: tuple[str, ...] = (
    "mfaEnforced",
    "mfaEnabled",
    "mfaRegistered",
    "isMfaRegistered",
    "isMfaCapable",
    "strongAuthenticationEnabled",
)

_PRINCIPAL_TYPES: dict[str, str] = {
    "user": "user",
    "serviceprincipal": "service_principal",
    "group": "group",
    "managedidentity": "service_principal",
    "foreigngroup": "group",
}


def guid_of(role_definition_id: str) -> str:
    """The role-definition GUID of `/subscriptions/<sub>/providers/…/roleDefinitions/<guid>`.

    The *last* GUID in the string: the first one is the subscription id, which every role
    definition in a subscription shares."""
    found = _GUID.findall(role_definition_id or "")
    return found[-1].lower() if found else text(role_definition_id).lower()


def subscription_of(scope: str) -> str | None:
    m = _SUB.match(scope or "")
    return f"/subscriptions/{m.group(1)}" if m else None


def resource_group_of(scope: str) -> str | None:
    m = _RG.match(scope or "")
    return m.group(2) if m else None


def provider_of(ref: str) -> str | None:
    """`.../providers/Microsoft.Storage/storageAccounts/x` → `Microsoft.Storage`."""
    m = re.search(r"/providers/([^/]+)/", ref or "", re.IGNORECASE)
    return m.group(1) if m else None


def _definition_pairs(definition: dict[str, Any]) -> tuple[tuple[Pair, ...], list[str]]:
    raw_props = definition.get("properties")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else definition
    pairs: set[Pair] = set()
    unmapped: list[str] = []
    for perm in as_list(props.get("permissions")):
        if not isinstance(perm, dict):
            continue
        actions = [text(a) for a in as_list(perm.get("actions")) if text(a)]
        got, missing = expand_many(CLOUD, actions)
        unmapped.extend(missing)
        not_actions = [text(a) for a in as_list(perm.get("notActions")) if text(a)]
        if not_actions:
            got = subtract(got, expand_actions(CLOUD, not_actions))
        data_actions = [text(a) for a in as_list(perm.get("dataActions")) if text(a)]
        got_data, missing_data = expand_many(CLOUD, data_actions)
        unmapped.extend(missing_data)
        not_data = [text(a) for a in as_list(perm.get("notDataActions")) if text(a)]
        if not_data:
            got_data = subtract(got_data, expand_actions(CLOUD, not_data))
        pairs |= got | got_data
    pairs.discard(UNKNOWN_PAIR)
    return sorted_pairs(pairs), unmapped


class _Definitions:
    def __init__(self, records: list[Any]) -> None:
        self.by_guid: dict[str, dict[str, Any]] = {}
        self.by_name: dict[str, dict[str, Any]] = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            raw_props = rec.get("properties")
            props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}
            for key in (rec.get("id"), rec.get("name")):
                if text(key):
                    self.by_guid[guid_of(text(key))] = rec
            role_name = text(rec.get("roleName")) or text(props.get("roleName"))
            if role_name:
                self.by_name[role_name.lower()] = rec

    def lookup(self, role_definition_id: str, role_name: str) -> dict[str, Any] | None:
        return self.by_guid.get(guid_of(role_definition_id)) or self.by_name.get(role_name.lower())


def _resource_groups(records: list[Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in records:
        if isinstance(rec, dict) and text(rec.get("name")):
            out[text(rec.get("name")).lower()] = rec
    return out


def _mfa_hint(user: dict[str, Any]) -> bool | None:
    for key in _MFA_KEYS:
        if key in user:
            return parse_bool(user.get(key))
    methods = user.get("authenticationMethods")
    if isinstance(methods, list):
        return len(methods) > 1
    return None


def parse_azure(files: dict[str, Any], month: int, source_prefix: str = "azure/") -> ProviderParse:
    parse = ProviderParse(cloud=CLOUD)
    inventory = files.get(RESOURCES)
    if isinstance(inventory, list):
        parse.resources = parse_inventory(CLOUD, inventory, month, ("ref", "id", "resource_ref", "arn"))
        parse.resources = [
            r
            if r.project_ref and r.project_ref.lower().startswith("/subscriptions/")
            else _with_subscription(r, subscription_of(r.resource_ref))
            for r in parse.resources
        ]
    definitions = _Definitions(as_list(files.get(ROLE_DEFINITIONS)))
    groups = _resource_groups(as_list(files.get(RESOURCE_GROUPS)))
    inventory_by_ref = {r.resource_ref.lower(): r for r in parse.resources}

    principals: dict[str, RawPrincipal] = {}

    users = files.get(ENTRA_USERS)
    users_list = as_list(users.get("value")) if isinstance(users, dict) else as_list(users)
    source_users = f"{source_prefix}{ENTRA_USERS}"
    for idx, user in enumerate(users_list):
        if not isinstance(user, dict) or not text(user.get("id")):
            continue
        oid = text(user.get("id")).lower()
        parse.entra_users[oid] = user
        upn = normalise_email(text(user.get("userPrincipalName"))) or normalise_email(text(user.get("mail")))
        enabled = parse_bool(user.get("accountEnabled"))
        if oid in principals:
            parse.warnings.append(f"duplicate principal {oid} (entra-users entry {idx} replaces earlier)")
        # `email` is what the *assignment* names the principal (SPEC §6 rule 1); the directory UPN
        # stays in `entra_users` so the linker resolves it as rule 2 (`entra_directory`).
        principals[oid] = RawPrincipal(
            principal_ref=oid,
            cloud=CLOUD,
            principal_type="user",
            name=text(user.get("displayName")) or (upn or oid),
            email=None,
            tags={"department": text(user.get("department"))} if text(user.get("department")) else {},
            raw={
                k: user[k]
                for k in ("id", "userPrincipalName", "displayName", "accountEnabled", "department")
                if k in user
            },
            is_service=False,
            enabled=enabled if enabled is not None else True,
            mfa=_mfa_hint(user),
            source_file=source_users,
            source_pointer=json_pointer(idx),
        )
        sign_in = user.get("signInActivity")
        if isinstance(sign_in, dict):
            when = parse_date(sign_in.get("lastSignInDateTime")) or parse_date(
                sign_in.get("lastNonInteractiveSignInDateTime")
            )
            if when:
                parse.activity.append(RawActivity(oid, CLOUD, IDENTITY_CATEGORY, when, 1))

    assignments = files.get(ROLE_ASSIGNMENTS)
    assignment_list = (
        as_list(assignments.get("value")) if isinstance(assignments, dict) else as_list(assignments)
    )
    source_assign = f"{source_prefix}{ROLE_ASSIGNMENTS}"
    for idx, rec in enumerate(assignment_list):
        if not isinstance(rec, dict):
            continue
        raw_props = rec.get("properties")
        props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}
        oid = text(rec.get("principalId") or props.get("principalId")).lower()
        if not oid:
            continue
        ptype_raw = text(rec.get("principalType") or props.get("principalType")).lower()
        ptype = _PRINCIPAL_TYPES.get(ptype_raw, "user" if not ptype_raw else "service_principal")
        pname = text(rec.get("principalName") or props.get("principalName"))
        scope = text(rec.get("scope") or props.get("scope")) or "/"
        role_def_id = text(rec.get("roleDefinitionId") or props.get("roleDefinitionId"))
        role_name = text(rec.get("roleDefinitionName") or props.get("roleDefinitionName"))
        rg_name = resource_group_of(scope)
        rg = groups.get(rg_name.lower()) if rg_name else None
        rg_tags = lower_tags(rg.get("tags")) if rg else {}
        pointer = json_pointer(idx)

        principal = principals.get(oid)
        if principal is None:
            principal = RawPrincipal(
                principal_ref=oid,
                cloud=CLOUD,
                principal_type=ptype,
                name=pname or oid,
                email=normalise_email(pname) if ptype == "user" else None,
                tags={},
                raw={"principalId": oid, "principalType": ptype_raw or ptype, "principalName": pname},
                is_service=ptype != "user",
                source_file=source_assign,
                source_pointer=pointer,
            )
            principals[oid] = principal
        elif ptype != "user" and principal.principal_type == "user" and not parse.entra_users.get(oid):
            principal.principal_type = ptype
        if ptype == "user" and principal.email is None:
            principal.email = normalise_email(pname)
        if ptype != "user" and principal.project_hint is None:
            principal.project_hint = text_or_none(rg_tags.get("project"))
            if rg_tags.get("owner") and "owner" not in principal.tags:
                principal.tags["owner"] = rg_tags["owner"]
        sub = subscription_of(scope)
        if sub and "subscription" not in principal.raw:
            principal.raw["subscription"] = sub

        pairs_known = role_pairs(CLOUD, guid_of(role_def_id)) if role_def_id else None
        pairs_known = pairs_known or role_pairs(CLOUD, role_name)
        unmapped: list[str] = []
        if pairs_known:
            pairs = sorted_pairs(set(pairs_known))
        else:
            definition = definitions.lookup(role_def_id, role_name)
            pairs, unmapped = _definition_pairs(definition) if definition else ((), [])
            if not pairs:
                pairs = (UNKNOWN_PAIR,)
                unmapped = [role_name or role_def_id]
        for miss in unmapped:
            parse.unmapped.append(UnmappedAction(CLOUD, oid, miss, source_assign, pointer))
        region = text_or_none(rg.get("location")) if rg else None
        if region is None:
            hit = inventory_by_ref.get(scope.lower())
            region = hit.region if hit else None
        snippet = {"raw_action": role_name or role_def_id, **rec}
        parse.grants.append(
            RawGrant(
                principal_ref=oid,
                cloud=CLOUD,
                pairs=pairs,
                scope_ref=scope,
                scope_level=scope_level(CLOUD, scope),
                region=region,
                effect="allow",
                granted_via=f"role:{role_name or guid_of(role_def_id)}",
                raw_snippet=snippet,
                source_file=source_assign,
                source_pointer=pointer,
                unmapped=tuple(unmapped),
            )
        )

    summary = files.get(ACTIVITY_SUMMARY)
    for rec in as_list(summary.get("value")) if isinstance(summary, dict) else as_list(summary):
        if not isinstance(rec, dict):
            continue
        oid = text(rec.get("principalId")).lower()
        when = parse_date(rec.get("lastOperationTime"))
        if not oid or when is None:
            continue
        category = category_of_ref_service(CLOUD, text_or_none(rec.get("resourceProvider")), UNKNOWN)
        parse.activity.append(RawActivity(oid, CLOUD, category, when, parse_int(rec.get("operationCount"))))

    parse.principals = [principals[k] for k in sorted(principals)]
    return parse


def _with_subscription(row: Any, subscription: str | None) -> Any:
    from dataclasses import replace

    return replace(row, project_ref=subscription or row.project_ref) if subscription else row


def category_of_azure_ref(ref: str) -> str:
    return category_of_ref_service(CLOUD, provider_of(ref), "compute" if resource_group_of(ref) else UNKNOWN)
