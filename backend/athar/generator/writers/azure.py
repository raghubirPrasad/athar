"""Azure native exports (SPEC §4.6). Pure.

  azure/role-assignments.json     `az role assignment list --all`
  azure/role-definitions.json     `az role definition list` (the built-ins in use plus NDA's custom roles)
  azure/entra-users.json          Graph `/users?$select=id,userPrincipalName,displayName,accountEnabled,
                                  department,signInActivity`
  azure/resource-groups.json      `az group list` — the region and `project` tag behind every RG scope
  azure/activity-log-summary.json per-principal, per-resource-provider aggregation of the Activity Log
  azure/resources.json            ATHAR-side inventory (see `writers/inventory.py`)

Built-in role definition GUIDs are Microsoft's published values (SPEC §4.6 marks them `(verify)`);
custom role GUIDs come from the seeded RNG (`SimConstants.azure_custom_role_guids`).

# SPEC? ATHAR's Azure inputs carry no service-principal export, and the directory is the only file
# that can own a principal (SPEC §6 rule 2). NDA therefore registers its automation identities in
# Entra ID, so `entra-users.json` carries them alongside the humans while the assignments keep
# their true `principalType: ServicePrincipal`. Without this a subscription-scope assignment held
# by a service principal would have no owner at all (finding R10), which is not what the estate
# means to say.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import date
from typing import Any

from athar.generator import catalogue as cat
from athar.generator.state import EstateState, Grant, Identity, MonthSnapshot
from athar.generator.writers import business_ts, dumps, opt_ts
from athar.generator.writers import inventory as inv

CLOUD = "azure"
ASSIGNMENT_TYPE = "Microsoft.Authorization/roleAssignments"
DEFINITION_TYPE = "Microsoft.Authorization/roleDefinitions"
RESOURCE_GROUP_TYPE = "Microsoft.Resources/resourceGroups"
ACTIVITY_WINDOW_MONTHS = 3  # the Activity Log's retention window, ~90 days

_SUBSCRIPTION = re.compile(r"^/subscriptions/([^/]+)")


def role_guid(state: EstateState, role_name: str) -> str:
    definition = cat.AZURE_ROLE_DEFINITIONS.get(role_name)
    if definition is None:
        return ""
    return definition.guid or state.constants.azure_custom_role_guids.get(role_name, "")


def definition_scope(scope: str) -> str:
    """Role definitions are addressed under the assignment's subscription; a management-group
    assignment names the tenant-level definition instead."""
    match = _SUBSCRIPTION.match(scope)
    return f"/subscriptions/{match.group(1)}" if match else ""


def definition_id(state: EstateState, role_name: str, scope: str) -> str:
    return f"{definition_scope(scope)}/providers/{DEFINITION_TYPE}/{role_guid(state, role_name)}"


def _principal_type(ident: Identity) -> str:
    return "User" if ident.is_human else "ServicePrincipal"


def _principal_name(ident: Identity) -> str:
    return ident.email if ident.is_human else ident.display_name


def _azure_identities(snapshot: MonthSnapshot) -> list[Identity]:
    return [
        snapshot.identities[i]
        for i in sorted(snapshot.identities)
        if snapshot.identities[i].present_in(CLOUD)
    ]


def _azure_grants(snapshot: MonthSnapshot) -> list[Grant]:
    return sorted(
        (
            g
            for g in snapshot.grants
            if g.cloud == CLOUD
            and g.identity_id in snapshot.identities
            and snapshot.identities[g.identity_id].present_in(CLOUD)
        ),
        key=lambda g: (g.identity_id, g.scope_ref, g.name, g.grant_ref),
    )


def role_assignments(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for grant in _azure_grants(snapshot):
        ident = snapshot.identities[grant.identity_id]
        created = business_ts(grant.granted_on, grant.grant_ref)
        out.append(
            {
                "id": f"{grant.scope_ref}/providers/{ASSIGNMENT_TYPE}/{grant.native_id}",
                "name": grant.native_id,
                "principalId": ident.azure_object_id,
                "principalType": _principal_type(ident),
                "principalName": _principal_name(ident),
                "roleDefinitionId": definition_id(state, grant.name, grant.scope_ref),
                "roleDefinitionName": grant.name,
                "scope": grant.scope_ref,
                "type": ASSIGNMENT_TYPE,
                "createdOn": created,
                "updatedOn": created,
            }
        )
    return sorted(out, key=lambda a: str(a["id"]))


def role_definitions(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    """Every role definition an assignment references this month, plus NDA's custom roles."""
    used = {g.name for g in _azure_grants(snapshot)}
    used |= {name for name, d in cat.AZURE_ROLE_DEFINITIONS.items() if d.custom}
    subscription = state.constants.azure_subscription_scope
    out: list[dict[str, Any]] = []
    for name in sorted(used):
        definition = cat.AZURE_ROLE_DEFINITIONS.get(name)
        if definition is None:
            continue
        guid = role_guid(state, name)
        out.append(
            {
                "id": f"{subscription}/providers/{DEFINITION_TYPE}/{guid}",
                "name": guid,
                "type": DEFINITION_TYPE,
                "roleName": definition.name,
                "roleType": "CustomRole" if definition.custom else "BuiltInRole",
                "description": definition.description,
                "permissions": [
                    {
                        "actions": list(definition.actions),
                        "notActions": list(definition.not_actions),
                        "dataActions": list(definition.data_actions),
                        "notDataActions": [],
                    }
                ],
                "assignableScopes": [subscription] if definition.custom else ["/"],
            }
        )
    return out


def _last_sign_in(snapshot: MonthSnapshot) -> dict[str, date]:
    out: dict[str, date] = {}
    for (identity_id, cloud, _service), record in snapshot.activity.items():
        if cloud != CLOUD or record.last is None:
            continue
        if record.last > out.get(identity_id, date.min):
            out[identity_id] = record.last
    return out


def entra_users(snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    signed_in = _last_sign_in(snapshot)
    out: list[dict[str, Any]] = []
    for ident in _azure_identities(snapshot):
        seen = signed_in.get(ident.identity_id)
        stamp = opt_ts(seen, f"{ident.identity_id}:signin")
        interactive = stamp if ident.is_human else None
        non_interactive = None if ident.is_human else stamp
        out.append(
            {
                "id": ident.azure_object_id,
                "userPrincipalName": ident.email,
                "displayName": ident.display_name,
                "accountEnabled": CLOUD not in ident.disabled_clouds,
                "department": ident.department,
                "signInActivity": {
                    "lastSignInDateTime": interactive,
                    "lastNonInteractiveSignInDateTime": non_interactive,
                },
            }
        )
    return sorted(out, key=lambda u: str(u["id"]))


def resource_groups(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    """Every resource group, with the `project` tag the linker reads (SPEC §6 rule 4) and the
    `location` that gives an RG-scoped assignment its region (SPEC §4.6)."""
    primary = state.constants.azure_subscription_id
    out: list[dict[str, Any]] = []
    for res in sorted(
        (r for r in snapshot.resources if r.cloud == CLOUD and r.kind == "rg"), key=lambda r: r.ref
    ):
        project = snapshot.projects.get(res.project_id)
        tags = {
            "project": res.project_ref,
            "department": project.department if project else "",
            "environment": "prod" if res.ref.startswith(f"/subscriptions/{primary}/") else "sandbox",
        }
        if project is not None and project.owner_id and project.owner_id in snapshot.identities:
            tags["owner"] = snapshot.identities[project.owner_id].email
        out.append(
            {
                "id": res.ref,
                "name": res.name,
                "type": RESOURCE_GROUP_TYPE,
                "location": res.region,
                "managedBy": None,
                "properties": {"provisioningState": "Succeeded"},
                "tags": {k: v for k, v in sorted(tags.items()) if v},
            }
        )
    return out


def activity_log_summary(snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    """`[{principalId, resourceProvider, lastOperationTime, operationCount}]` — the aggregation a
    real deployment builds from the Activity Log; the count is the trailing 90-day window."""
    month = snapshot.month
    out: list[dict[str, Any]] = []
    by_principal: dict[str, dict[str, Any]] = defaultdict(dict)
    for (identity_id, cloud, provider), record in snapshot.activity.items():
        ident = snapshot.identities.get(identity_id)
        if cloud != CLOUD or record.last is None or ident is None or not ident.present_in(CLOUD):
            continue
        by_principal[ident.azure_object_id][provider] = {
            "principalId": ident.azure_object_id,
            "resourceProvider": provider,
            "lastOperationTime": business_ts(record.last, f"{identity_id}:{provider}"),
            "operationCount": record.trailing(month, ACTIVITY_WINDOW_MONTHS),
        }
    for principal_id in sorted(by_principal):
        for provider in sorted(by_principal[principal_id]):
            out.append(by_principal[principal_id][provider])
    return out


def azure_files(state: EstateState, snapshot: MonthSnapshot) -> dict[str, str]:
    return {
        "azure/role-assignments.json": dumps(role_assignments(state, snapshot)),
        "azure/role-definitions.json": dumps(role_definitions(state, snapshot)),
        "azure/entra-users.json": dumps(entra_users(snapshot)),
        "azure/resource-groups.json": dumps(resource_groups(state, snapshot)),
        "azure/activity-log-summary.json": dumps(activity_log_summary(snapshot)),
        "azure/resources.json": dumps(inv.azure_resources(state, snapshot)),
    }
