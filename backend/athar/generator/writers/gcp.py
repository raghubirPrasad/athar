"""GCP native exports (SPEC §4.6). Pure.

  gcp/projects.json                 `gcloud projects list` (the `region` label carries the region)
  gcp/<projectId>/iam-policy.json   `gcloud projects get-iam-policy <projectId> --format=json`
  gcp/service-account-keys.json     `gcloud iam service-accounts keys list`
  gcp/activity.json                 IAM Recommender / Policy Analyzer style last-authenticated activity
  gcp/resources.json                ATHAR-side inventory (see `writers/inventory.py`)

A binding member is `user:<email>` for a person and
`serviceAccount:<name>@<projectId>.iam.gserviceaccount.com` for an automation identity — the
string ATHAR keeps as `principal_ref` (SPEC §5.1). Google-managed (`SYSTEM_MANAGED`) keys are
emitted for realism and are not customer credentials; only `USER_MANAGED` keys age (R6).
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from athar.clock import month_start
from athar.generator import catalogue as cat
from athar.generator.state import (
    ActivityRecord,
    Credential,
    EstateState,
    Grant,
    Identity,
    MonthSnapshot,
    Project,
)
from athar.generator.writers import business_ts, dumps, etag, opt_ts
from athar.generator.writers import inventory as inv
from athar.hashing import sha256_hex

CLOUD = "gcp"
IAM_POLICY_VERSION = 1
KEY_ALGORITHM = "KEY_ALG_RSA_2048"
NEVER_EXPIRES = "9999-12-31T23:59:59Z"
SYSTEM_KEY_LIFETIME_DAYS = 14
ACTIVITY_WINDOW_MONTHS = 3

_LABEL_UNSAFE = re.compile(r"[^a-z0-9_-]+")


def label(value: str) -> str:
    """GCP label values are lower-case `[a-z0-9_-]` (so no address ever becomes a label)."""
    return _LABEL_UNSAFE.sub("-", value.strip().lower()).strip("-")[:63]


def role_name(grant: Grant, org_id: str) -> str:
    """`organizations/{org}/roles/…` templates carry the organisation id of this estate."""
    return grant.name.replace("{org}", org_id)


def _gcp_projects(snapshot: MonthSnapshot) -> list[Project]:
    return sorted((p for p in snapshot.projects.values() if p.cloud == CLOUD), key=lambda p: p.project_ref)


def _member(snapshot: MonthSnapshot, ident: Identity) -> str:
    project = snapshot.projects.get(ident.project_id or "")
    return ident.gcp_member(project.project_ref if project else None)


def _gcp_grants(snapshot: MonthSnapshot) -> list[Grant]:
    return [
        g
        for g in snapshot.grants
        if g.cloud == CLOUD
        and g.identity_id in snapshot.identities
        and snapshot.identities[g.identity_id].present_in(CLOUD)
    ]


def projects(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for project in _gcp_projects(snapshot):
        out.append(
            {
                "projectId": project.project_ref,
                "name": project.name,
                "projectNumber": project.gcp_number,
                "lifecycleState": "ACTIVE",
                "parent": {"type": "folder", "id": state.constants.gcp_folder_id},
                "createTime": business_ts(project.created_on, project.project_id),
                "labels": {
                    "region": label(project.region),
                    "department": label(project.department),
                    "project-id": label(project.project_id),
                },
            }
        )
    return out


def iam_policies(state: EstateState, snapshot: MonthSnapshot) -> dict[str, dict[str, Any]]:
    """`projectId → policy document`. Every GCP project has a policy, even with no bindings left."""
    members: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    org = state.constants.gcp_org_id
    for grant in _gcp_grants(snapshot):
        project_ref = grant.scope_ref.removeprefix("projects/")
        members[project_ref][role_name(grant, org)].add(
            _member(snapshot, snapshot.identities[grant.identity_id])
        )
    out: dict[str, dict[str, Any]] = {}
    for project in _gcp_projects(snapshot):
        bindings = members.get(project.project_ref, {})
        out[project.project_ref] = {
            "bindings": [{"role": role, "members": sorted(bindings[role])} for role in sorted(bindings)],
            "etag": etag(state.seed, snapshot.month, project.project_ref),
            "version": IAM_POLICY_VERSION,
        }
    return out


def _service_accounts(snapshot: MonthSnapshot) -> list[Identity]:
    return [
        snapshot.identities[i]
        for i in sorted(snapshot.identities)
        if not snapshot.identities[i].is_human and snapshot.identities[i].present_in(CLOUD)
    ]


def _key_name(project_ref: str, email: str, key_id: str) -> str:
    return f"projects/{project_ref}/serviceAccounts/{email}/keys/{key_id}"


def service_account_keys(snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    accounts = {i.identity_id: i for i in _service_accounts(snapshot)}
    credentials: dict[str, list[Credential]] = defaultdict(list)
    for cred in snapshot.credentials:
        if cred.cloud == CLOUD and cred.identity_id in accounts:
            credentials[cred.identity_id].append(cred)
    out: list[dict[str, Any]] = []
    for identity_id, ident in sorted(accounts.items()):
        project = snapshot.projects.get(ident.project_id or "")
        project_ref = project.project_ref if project else ""
        email = _member(snapshot, ident).split(":", 1)[1]
        for cred in sorted(credentials.get(identity_id, []), key=lambda c: (c.created, c.key_id)):
            out.append(
                {
                    "name": _key_name(cred.project_ref or project_ref, email, cred.key_id),
                    "validAfterTime": business_ts(cred.created, cred.key_id),
                    "validBeforeTime": NEVER_EXPIRES,
                    "keyAlgorithm": KEY_ALGORITHM,
                    "keyOrigin": "GOOGLE_PROVIDED",
                    "keyType": "USER_MANAGED",
                    "disabled": not cred.active,
                }
            )
        # Google's own signing key: rotated by Google, never a customer credential (the parser
        # skips SYSTEM_MANAGED). Emitted because a real `keys list` always shows one.
        system_id = sha256_hex(f"{email}|system|{snapshot.month}".encode())[:40]
        valid_after = month_start(snapshot.month)
        out.append(
            {
                "name": _key_name(project_ref, email, system_id),
                "validAfterTime": business_ts(valid_after, system_id),
                "validBeforeTime": business_ts(
                    valid_after + timedelta(days=SYSTEM_KEY_LIFETIME_DAYS), f"{system_id}:end"
                ),
                "keyAlgorithm": KEY_ALGORITHM,
                "keyOrigin": "GOOGLE_PROVIDED",
                "keyType": "SYSTEM_MANAGED",
            }
        )
    return sorted(out, key=lambda k: str(k["name"]))


def _used_permissions(record: ActivityRecord | None, month: int, total: int) -> int:
    """Distinct permissions the member exercised in the observation window, the way IAM Recommender
    reports it: a handful out of thousands. One per active month in the window, never more than the
    role holds; a binding that never authenticated used nothing."""
    if record is None or record.last is None:
        return 0
    active_months = sum(
        1 for m, count in record.ops.items() if month - ACTIVITY_WINDOW_MONTHS < m <= month and count
    )
    return max(1, min(total, active_months + 1))


def activity(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    """One row per binding: when that member last authenticated in that project, and how much of
    the role it actually used (SPEC §4.6, IAM Recommender shape)."""
    org = state.constants.gcp_org_id
    month = snapshot.month
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for grant in _gcp_grants(snapshot):
        ident = snapshot.identities[grant.identity_id]
        project_ref = grant.scope_ref.removeprefix("projects/")
        member = _member(snapshot, ident)
        role = role_name(grant, org)
        record = snapshot.activity.get((grant.identity_id, CLOUD, project_ref))
        last = record.last if record else None
        total = cat.GCP_ROLE_INFO.get(grant.name, ("", 1))[1]
        used = _used_permissions(record, month, total)
        rows[(project_ref, member, role)] = {
            "project": project_ref,
            "member": member,
            "role": role,
            "lastAuthenticatedTime": opt_ts(last, f"{grant.identity_id}:{project_ref}"),
            "usedPermissionsCount": used,
            "totalPermissionsCount": total,
        }
    return [rows[key] for key in sorted(rows)]


def gcp_files(state: EstateState, snapshot: MonthSnapshot) -> dict[str, str]:
    files = {
        "gcp/projects.json": dumps(projects(state, snapshot)),
        "gcp/service-account-keys.json": dumps(service_account_keys(snapshot)),
        "gcp/activity.json": dumps(activity(state, snapshot)),
        "gcp/resources.json": dumps(inv.gcp_resources(state, snapshot)),
    }
    for project_ref, policy in iam_policies(state, snapshot).items():
        files[f"gcp/{project_ref}/iam-policy.json"] = dumps(policy)
    return files
