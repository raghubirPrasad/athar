"""Inverse templates: provider-native before/after JSON for a remediation (SPEC §11.5). Pure.

`policy_diff(action, identity, grants, drop, credentials)` renders, from the grants' retained
`raw_snippet`s, the copy-pasteable change an operator would apply:

  detach AWS managed policy · remove AWS inline statement · remove AWS user from group ·
  delete Azure role assignment · remove GCP binding member ·
  deactivate AWS access key / GCP SA key · disable Entra user / AWS console login / GCP SA

`before` / `after` are keyed by cloud; `operations` list `{op, target, detail, cli}` sorted so the
output is deterministic. The diff never decides anything: the rule engine chose `action`, and
`drop` ⊆ the identity's grants was validated upstream (SPEC §11.4).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from athar.domain import CredentialRow, GrantRow, IdentityRow

REVOKING_ACTIONS: frozenset[str] = frozenset(
    {"revoke_grant", "downgrade_to_least_privilege", "remove_cloud_access"}
)
DISABLING_ACTIONS: frozenset[str] = frozenset({"disable_identity", "remove_cloud_access"})
CREDENTIAL_ACTIONS: frozenset[str] = frozenset(
    {"rotate_or_disable_credential", "disable_identity", "remove_cloud_access"}
)


@dataclass
class PolicyDiff:
    cloud: str  # aws | azure | gcp | multi | none
    before: dict[str, Any] = field(default_factory=dict)  # {cloud: native JSON}
    after: dict[str, Any] = field(default_factory=dict)
    operations: list[dict[str, Any]] = field(default_factory=list)  # [{op, cloud, target, detail, cli}]
    summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "before": self.before,
            "after": self.after,
            "operations": self.operations,
            "summary": self.summary,
        }


def _op(op: str, cloud: str, target: str, detail: dict[str, Any], cli: str) -> dict[str, Any]:
    return {"op": op, "cloud": cloud, "target": target, "detail": detail, "cli": cli}


def _aws_user_name(g: GrantRow) -> str:
    snip = g.raw_snippet
    return str(snip.get("UserName") or snip.get("RoleName") or g.principal_ref.rsplit("/", 1)[-1])


def _aws_is_role(g: GrantRow) -> bool:
    return ":role/" in g.principal_ref or "RoleName" in g.raw_snippet


# ---------------------------------------------------------------------------
# Grant removals
# ---------------------------------------------------------------------------


def _aws_grant_ops(
    drop: list[GrantRow], before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    by_principal: dict[str, list[GrantRow]] = {}
    for g in drop:
        by_principal.setdefault(g.principal_ref, []).append(g)
    for principal_ref in sorted(by_principal):
        rows = by_principal[principal_ref]
        name = _aws_user_name(rows[0])
        kind = "Role" if _aws_is_role(rows[0]) else "User"
        holder_before: dict[str, Any] = {f"{kind}Name": name, "Arn": principal_ref}
        holder_after: dict[str, Any] = {f"{kind}Name": name, "Arn": principal_ref}
        managed = sorted(
            {
                (str(g.raw_snippet.get("PolicyName", "")), str(g.raw_snippet.get("PolicyArn", "")))
                for g in rows
                if g.granted_via.startswith("managed_policy:")
            }
        )
        if managed:
            holder_before["AttachedManagedPolicies"] = [{"PolicyName": n, "PolicyArn": a} for n, a in managed]
            holder_after["AttachedManagedPolicies"] = []
            for n, a in managed:
                verb = "detach-role-policy" if kind == "Role" else "detach-user-policy"
                flag = "--role-name" if kind == "Role" else "--user-name"
                ops.append(
                    _op(
                        "detach_managed_policy",
                        "aws",
                        principal_ref,
                        {"PolicyName": n, "PolicyArn": a},
                        f"aws iam {verb} {flag} {name} --policy-arn {a}",
                    )
                )
        inline: dict[str, list[dict[str, Any]]] = {}
        for g in rows:
            if g.granted_via == "direct" and isinstance(g.raw_snippet.get("Statement"), dict):
                stmt = g.raw_snippet["Statement"]
                bucket = inline.setdefault(str(g.raw_snippet.get("PolicyName", "inline")), [])
                if stmt not in bucket:
                    bucket.append(stmt)
        if inline:
            holder_before["UserPolicyList" if kind == "User" else "RolePolicyList"] = [
                {"PolicyName": pn, "PolicyDocument": {"Version": "2012-10-17", "Statement": stmts}}
                for pn, stmts in sorted(inline.items())
            ]
            holder_after["UserPolicyList" if kind == "User" else "RolePolicyList"] = [
                {"PolicyName": pn, "PolicyDocument": {"Version": "2012-10-17", "Statement": []}}
                for pn in sorted(inline)
            ]
            for pn, stmts in sorted(inline.items()):
                verb = "delete-role-policy" if kind == "Role" else "delete-user-policy"
                flag = "--role-name" if kind == "Role" else "--user-name"
                ops.append(
                    _op(
                        "remove_inline_statement",
                        "aws",
                        principal_ref,
                        {"PolicyName": pn, "Statements": stmts},
                        f"aws iam {verb} {flag} {name} --policy-name {pn}",
                    )
                )
        groups = sorted({g.granted_via.split(":", 1)[1] for g in rows if g.granted_via.startswith("group:")})
        if groups:
            holder_before["GroupList"] = groups
            holder_after["GroupList"] = []
            for grp in groups:
                ops.append(
                    _op(
                        "remove_user_from_group",
                        "aws",
                        principal_ref,
                        {"GroupName": grp},
                        f"aws iam remove-user-from-group --user-name {name} --group-name {grp}",
                    )
                )
        trusts = sorted({str(g.raw_snippet.get("RoleArn")) for g in rows if g.raw_snippet.get("RoleArn")})
        for role_arn in trusts:
            ops.append(
                _op(
                    "remove_trust_principal",
                    "aws",
                    role_arn,
                    {"Principal": principal_ref},
                    f"aws iam update-assume-role-policy --role-name {role_arn.rsplit('/', 1)[-1]} --policy-document file://trust.json",
                )
            )
        before.setdefault("aws", {}).setdefault("principals", []).append(holder_before)
        after.setdefault("aws", {}).setdefault("principals", []).append(holder_after)
    return ops


def _azure_grant_ops(
    drop: list[GrantRow], before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    seen: set[str] = set()
    assignments: list[dict[str, Any]] = []
    for g in sorted(drop, key=lambda x: (x.scope_ref, x.granted_via, x.grant_id)):
        snip = {k: v for k, v in g.raw_snippet.items() if k != "raw_action"}
        assignment_id = str(
            snip.get("id")
            or f"{g.scope_ref}/providers/Microsoft.Authorization/roleAssignments/{g.principal_ref}"
        )
        if assignment_id in seen:
            continue
        seen.add(assignment_id)
        assignments.append(
            snip or {"id": assignment_id, "principalId": g.principal_ref, "scope": g.scope_ref}
        )
        ops.append(
            _op(
                "delete_role_assignment",
                "azure",
                assignment_id,
                {
                    "principalId": g.principal_ref,
                    "role": g.granted_via.split(":", 1)[-1],
                    "scope": g.scope_ref,
                },
                f"az role assignment delete --ids {assignment_id}",
            )
        )
    if assignments:
        before.setdefault("azure", {})["roleAssignments"] = assignments
        after.setdefault("azure", {})["roleAssignments"] = []
    return ops


def _gcp_grant_ops(
    drop: list[GrantRow], before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    bindings_before: dict[tuple[str, str], dict[str, Any]] = {}
    bindings_after: dict[tuple[str, str], dict[str, Any]] = {}
    for g in sorted(drop, key=lambda x: (x.scope_ref, x.granted_via, x.grant_id)):
        project = str(g.raw_snippet.get("project") or g.scope_ref.split("/", 1)[-1])
        role = str(g.raw_snippet.get("role") or g.granted_via.split(":", 1)[-1])
        raw_binding = g.raw_snippet.get("binding")
        binding: dict[str, Any] = (
            raw_binding if isinstance(raw_binding, dict) else {"role": role, "members": [g.principal_ref]}
        )
        members = [str(mem) for mem in (binding.get("members") or [])]
        key = (project, role)
        if key not in bindings_before:
            bindings_before[key] = {"project": project, "role": role, "members": members}
            bindings_after[key] = {
                "project": project,
                "role": role,
                "members": [mem for mem in members if mem != g.principal_ref],
            }
            ops.append(
                _op(
                    "remove_binding_member",
                    "gcp",
                    f"projects/{project}",
                    {"role": role, "member": g.principal_ref},
                    f"gcloud projects remove-iam-policy-binding {project} --member={g.principal_ref} --role={role}",
                )
            )
    if bindings_before:
        before.setdefault("gcp", {})["bindings"] = [bindings_before[k] for k in sorted(bindings_before)]
        after.setdefault("gcp", {})["bindings"] = [bindings_after[k] for k in sorted(bindings_after)]
    return ops


# ---------------------------------------------------------------------------
# Credentials and identity disablement
# ---------------------------------------------------------------------------


def _credential_ops(
    creds: Iterable[CredentialRow], before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    for c in sorted(creds, key=lambda x: x.credential_ref):
        if not c.active:
            continue
        native = c.credential_ref.split(":", 2)[-1]
        if c.cloud == "aws" and c.kind == "key":
            before.setdefault("aws", {}).setdefault("AccessKeys", []).append(
                {"AccessKeyId": native, "Status": "Active"}
            )
            after.setdefault("aws", {}).setdefault("AccessKeys", []).append(
                {"AccessKeyId": native, "Status": "Inactive"}
            )
            ops.append(
                _op(
                    "deactivate_access_key",
                    "aws",
                    c.credential_ref,
                    {"AccessKeyId": native},
                    f"aws iam update-access-key --access-key-id {native} --status Inactive",
                )
            )
        elif c.cloud == "aws" and c.kind == "password":
            before.setdefault("aws", {}).setdefault("LoginProfiles", []).append(
                {"UserName": native, "PasswordEnabled": True}
            )
            after.setdefault("aws", {}).setdefault("LoginProfiles", []).append(
                {"UserName": native, "PasswordEnabled": False}
            )
            ops.append(
                _op(
                    "disable_console_login",
                    "aws",
                    c.credential_ref,
                    {"UserName": native},
                    f"aws iam delete-login-profile --user-name {native}",
                )
            )
        elif c.cloud == "gcp" and c.kind == "sa_key":
            before.setdefault("gcp", {}).setdefault("serviceAccountKeys", []).append(
                {"keyId": native, "disabled": False}
            )
            after.setdefault("gcp", {}).setdefault("serviceAccountKeys", []).append(
                {"keyId": native, "disabled": True}
            )
            ops.append(
                _op(
                    "disable_service_account_key",
                    "gcp",
                    c.credential_ref,
                    {"keyId": native},
                    f"gcloud iam service-accounts keys disable {native}",
                )
            )
    return ops


def _disable_ops(
    identity: IdentityRow,
    grants: list[GrantRow],
    before: dict[str, Any],
    after: dict[str, Any],
    clouds: set[str],
) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    principals = sorted({(g.cloud, g.principal_ref) for g in grants if g.cloud in clouds})
    for cloud, ref in principals:
        if cloud == "azure":
            before.setdefault("azure", {}).setdefault("users", []).append({"id": ref, "accountEnabled": True})
            after.setdefault("azure", {}).setdefault("users", []).append({"id": ref, "accountEnabled": False})
            ops.append(
                _op(
                    "disable_entra_user",
                    "azure",
                    ref,
                    {"principalId": ref},
                    f"az ad user update --id {ref} --account-enabled false",
                )
            )
        elif cloud == "aws":
            name = ref.rsplit("/", 1)[-1]
            before.setdefault("aws", {}).setdefault("LoginProfiles", []).append(
                {"UserName": name, "PasswordEnabled": True}
            )
            after.setdefault("aws", {}).setdefault("LoginProfiles", []).append(
                {"UserName": name, "PasswordEnabled": False}
            )
            ops.append(
                _op(
                    "disable_console_login",
                    "aws",
                    ref,
                    {"UserName": name},
                    f"aws iam delete-login-profile --user-name {name}",
                )
            )
        elif cloud == "gcp" and ref.startswith("serviceAccount:"):
            email = ref.split(":", 1)[1]
            before.setdefault("gcp", {}).setdefault("serviceAccounts", []).append(
                {"email": email, "disabled": False}
            )
            after.setdefault("gcp", {}).setdefault("serviceAccounts", []).append(
                {"email": email, "disabled": True}
            )
            ops.append(
                _op(
                    "disable_service_account",
                    "gcp",
                    ref,
                    {"email": email},
                    f"gcloud iam service-accounts disable {email}",
                )
            )
    return ops


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def policy_diff(
    action: str,
    identity: IdentityRow,
    grants: Sequence[GrantRow],
    drop: Sequence[GrantRow],
    credentials: Sequence[CredentialRow] = (),
) -> PolicyDiff:
    """Provider-native before/after for `action` on `identity`. Deterministic; pure."""
    grant_ids = {g.grant_id for g in grants}
    dropped = [g for g in drop if g.grant_id in grant_ids or not grants]
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    ops: list[dict[str, Any]] = []
    clouds_touched = {g.cloud for g in dropped} if action != "disable_identity" else {g.cloud for g in grants}

    if action in REVOKING_ACTIONS:
        ops += _aws_grant_ops([g for g in dropped if g.cloud == "aws"], before, after)
        ops += _azure_grant_ops([g for g in dropped if g.cloud == "azure"], before, after)
        ops += _gcp_grant_ops([g for g in dropped if g.cloud == "gcp"], before, after)
    if action in CREDENTIAL_ACTIONS:
        scope_creds = [
            c for c in credentials if action == "rotate_or_disable_credential" or c.cloud in clouds_touched
        ]
        if action == "disable_identity":
            # Disabling the identity already removes the AWS console login through the principal
            # (`_disable_ops`); emitting it again from the password credential would duplicate both
            # the operation and the LoginProfiles before/after rows.
            has_aws_principal = any(g.cloud == "aws" for g in grants)
            scope_creds = [
                c
                for c in scope_creds
                if not (has_aws_principal and c.cloud == "aws" and c.kind == "password")
            ]
        ops += _credential_ops(scope_creds, before, after)
    if action in DISABLING_ACTIONS:
        ops += _disable_ops(
            identity, list(grants), before, after, clouds_touched or {g.cloud for g in grants}
        )

    ops.sort(key=lambda o: (o["cloud"], o["op"], o["target"]))
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for o in ops:
        key = (o["cloud"], o["op"], o["target"])
        if key not in seen:
            seen.add(key)
            unique.append(o)
    clouds = sorted({o["cloud"] for o in unique})
    cloud = clouds[0] if len(clouds) == 1 else ("multi" if clouds else "none")
    counts: dict[str, int] = {}
    for o in unique:
        counts[o["op"]] = counts.get(o["op"], 0) + 1
    described = ", ".join(f"{n}× {op.replace('_', ' ')}" for op, n in sorted(counts.items()))
    summary = (
        f"{action} for {identity.identity_id}: {described}"
        if unique
        else f"{action} for {identity.identity_id}: no provider change required"
    )
    return PolicyDiff(cloud=cloud, before=before, after=after, operations=unique, summary=summary)
