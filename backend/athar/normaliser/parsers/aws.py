"""AWS parser (SPEC §4.6 AWS shapes → §5 rows). Pure.

Inputs (already decoded, see `schemas.load_file`):
  authorization-details.json   `aws iam get-account-authorization-details`
  credential-report.csv        `aws iam get-credential-report`
  service-last-accessed.json   `aws iam get-service-last-accessed-details`, one entry per principal
  resources.json               ATHAR-side inventory `[{arn, service, region, sensitivity, project}]`

Grants: inline statements (`direct`), attached managed policies (`managed_policy:<name>`),
group policies (`group:<name>`), role policies on the role principal, and trust-policy edges
(`sts:AssumeRole`, SPEC §5.3) as `impersonate` grants on the trusted principal. Deny statements
become `effect=deny` rows. Managed policies resolve through mappings/aws.yaml first, then the
customer-managed documents in `Policies`, else `unknown` (finding R0).
"""

from __future__ import annotations

from typing import Any

from athar.domain import ResourceRow
from athar.normaliser.expand import expand_actions, subtract
from athar.normaliser.ids import credential_ref, json_pointer, normalise_email
from athar.normaliser.mappings import UNKNOWN, full_wildcard, role_default_scope, role_pairs, scope_level
from athar.normaliser.parsers.common import (
    as_list,
    category_of_ref_service,
    expand_many,
    lower_tags,
    max_date,
    parse_bool,
    parse_date,
    parse_int,
    sorted_pairs,
    text,
    text_or_none,
)
from athar.normaliser.types import (
    SERVICE_NAME_PREFIXES,
    UNKNOWN_PAIR,
    Pair,
    ProviderParse,
    RawActivity,
    RawCredential,
    RawGrant,
    RawPrincipal,
    UnmappedAction,
)

CLOUD = "aws"
AUTH_DETAILS = "authorization-details.json"
CREDENTIAL_REPORT = "credential-report.csv"
SERVICE_LAST_ACCESSED = "service-last-accessed.json"
RESOURCES = "resources.json"
IDENTITY_CATEGORY = "identity"


def arn_parts(arn: str) -> list[str]:
    """`arn:partition:service:region:account:resource` → six parts (padded)."""
    parts = arn.split(":", 5)
    return parts + [""] * (6 - len(parts))


def arn_region(arn: str) -> str | None:
    if not arn.startswith("arn:"):
        return None
    region = arn_parts(arn)[3]
    return region or None


def arn_account(arn: str) -> str | None:
    if not arn.startswith("arn:"):
        return None
    account = arn_parts(arn)[4]
    return account if account.isdigit() and len(account) == 12 else None


def arn_service(arn: str) -> str | None:
    if not arn.startswith("arn:"):
        return None
    return arn_parts(arn)[2] or None


class _Inventory:
    """Region / project lookup for resource ARNs from the ATHAR-side inventory."""

    def __init__(self, rows: list[ResourceRow]) -> None:
        self.rows = rows
        self._by_ref = {r.resource_ref: r for r in rows}

    def region_for(self, scope_ref: str) -> str | None:
        stem = scope_ref.rstrip("*").rstrip("/")
        hit = self._by_ref.get(scope_ref) or self._by_ref.get(stem)
        if hit is not None:
            return hit.region
        if not stem:
            return None
        for ref, row in self._by_ref.items():
            if ref.startswith(stem) or stem.startswith(ref):
                return row.region
        return None


class _AwsContext:
    def __init__(self, month: int, source_prefix: str) -> None:
        self.month = month
        self.source_prefix = source_prefix
        self.parse = ProviderParse(cloud=CLOUD)
        self.account_id: str | None = None
        self.inventory = _Inventory([])
        self.groups: dict[str, tuple[int, dict[str, Any]]] = {}
        self.policies_by_arn: dict[str, tuple[int, dict[str, Any]]] = {}
        self.policies_by_name: dict[str, tuple[int, dict[str, Any]]] = {}
        self.principal_refs: set[str] = set()

    def src(self, name: str) -> str:
        return f"{self.source_prefix}{name}"


# ---------------------------------------------------------------------------
# Statements and policies
# ---------------------------------------------------------------------------


def _statement_pairs(stmt: dict[str, Any]) -> tuple[tuple[Pair, ...], list[str]]:
    actions = [text(a) for a in as_list(stmt.get("Action")) if text(a)]
    not_actions = [text(a) for a in as_list(stmt.get("NotAction")) if text(a)]
    pairs, unmapped = expand_many(CLOUD, actions)
    if not_actions:
        pairs |= subtract(set(full_wildcard()), expand_actions(CLOUD, not_actions))
    if not pairs:
        pairs = {UNKNOWN_PAIR}
    return sorted_pairs(pairs), unmapped


def _statement_grants(
    ctx: _AwsContext,
    principal_ref: str,
    stmt: dict[str, Any],
    *,
    granted_via: str,
    policy_name: str,
    pointer: str,
    source: str,
    holder: dict[str, str],
) -> list[RawGrant]:
    if not isinstance(stmt, dict):
        return []
    pairs, unmapped = _statement_pairs(stmt)
    effect = "deny" if text(stmt.get("Effect")).lower() == "deny" else "allow"
    resources = [text(r) for r in as_list(stmt.get("Resource")) if text(r)]
    if not resources:
        resources = ["*"]  # NotResource / missing Resource: read as unrestricted (SPEC? simpler reading)
    snippet: dict[str, Any] = {
        "raw_action": as_list(stmt.get("Action")) or as_list(stmt.get("NotAction")),
        "PolicyName": policy_name,
        "Statement": stmt,
        **holder,
    }
    out: list[RawGrant] = []
    for res in resources:
        out.append(
            RawGrant(
                principal_ref=principal_ref,
                cloud=CLOUD,
                pairs=pairs,
                scope_ref=res,
                scope_level=scope_level(CLOUD, res),
                region=arn_region(res) or ctx.inventory.region_for(res),
                effect=effect,
                granted_via=granted_via,
                raw_snippet=snippet,
                source_file=source,
                source_pointer=pointer,
                unmapped=tuple(unmapped),
            )
        )
    for action in unmapped:
        ctx.parse.unmapped.append(UnmappedAction(CLOUD, principal_ref, action, source, pointer))
    return out


def _policy_document_grants(
    ctx: _AwsContext,
    principal_ref: str,
    document: Any,
    *,
    granted_via: str,
    policy_name: str,
    pointer: str,
    source: str,
    holder: dict[str, str],
) -> list[RawGrant]:
    if not isinstance(document, dict):
        return []
    out: list[RawGrant] = []
    for i, stmt in enumerate(as_list(document.get("Statement"))):
        out.extend(
            _statement_grants(
                ctx,
                principal_ref,
                stmt,
                granted_via=granted_via,
                policy_name=policy_name,
                pointer=f"{pointer}/Statement/{i}",
                source=source,
                holder=holder,
            )
        )
    return out


def _default_document(policy: dict[str, Any]) -> Any:
    versions = as_list(policy.get("PolicyVersionList"))
    for v in versions:
        if isinstance(v, dict) and parse_bool(v.get("IsDefaultVersion")):
            return v.get("Document")
    for v in versions:
        if isinstance(v, dict) and v.get("Document") is not None:
            return v.get("Document")
    return policy.get("Document")


def _managed_policy_grants(
    ctx: _AwsContext,
    principal_ref: str,
    attached: dict[str, Any],
    *,
    granted_via: str,
    pointer: str,
    source: str,
    holder: dict[str, str],
) -> list[RawGrant]:
    name = text(attached.get("PolicyName"))
    arn = text(attached.get("PolicyArn"))
    label = name or arn
    pairs = role_pairs(CLOUD, arn) or role_pairs(CLOUD, name)
    if pairs:
        scope = role_default_scope(CLOUD, arn) or role_default_scope(CLOUD, name) or "global"
        snippet = {"raw_action": label, "PolicyName": name, "PolicyArn": arn, **holder}
        return [
            RawGrant(
                principal_ref=principal_ref,
                cloud=CLOUD,
                pairs=sorted_pairs(set(pairs)),
                scope_ref="*",
                scope_level=scope,
                region=None,
                effect="allow",
                granted_via=granted_via,
                raw_snippet=snippet,
                source_file=source,
                source_pointer=pointer,
            )
        ]
    found = ctx.policies_by_arn.get(arn) or ctx.policies_by_name.get(name)
    if found is not None:
        idx, policy = found
        doc_pointer = json_pointer("Policies", idx)
        grants = _policy_document_grants(
            ctx,
            principal_ref,
            _default_document(policy),
            granted_via=granted_via,
            policy_name=label,
            pointer=doc_pointer,
            source=source,
            holder={**holder, "PolicyArn": arn},
        )
        if grants:
            return grants
    ctx.parse.unmapped.append(UnmappedAction(CLOUD, principal_ref, label, source, pointer))
    return [
        RawGrant(
            principal_ref=principal_ref,
            cloud=CLOUD,
            pairs=(UNKNOWN_PAIR,),
            scope_ref="*",
            scope_level="global",
            region=None,
            effect="allow",
            granted_via=granted_via,
            raw_snippet={"raw_action": label, "PolicyName": name, "PolicyArn": arn, **holder},
            source_file=source,
            source_pointer=pointer,
            unmapped=(label,),
        )
    ]


def _group_grants(
    ctx: _AwsContext, principal_ref: str, group_name: str, holder: dict[str, str], source: str
) -> list[RawGrant]:
    found = ctx.groups.get(group_name)
    if found is None:
        return []
    idx, group = found
    via = f"group:{group_name}"
    holder = {**holder, "GroupName": group_name}
    out: list[RawGrant] = []
    for i, pol in enumerate(as_list(group.get("GroupPolicyList"))):
        if not isinstance(pol, dict):
            continue
        out.extend(
            _policy_document_grants(
                ctx,
                principal_ref,
                pol.get("PolicyDocument"),
                granted_via=via,
                policy_name=text(pol.get("PolicyName")),
                pointer=json_pointer("GroupDetailList", idx, "GroupPolicyList", i, "PolicyDocument"),
                source=source,
                holder=holder,
            )
        )
    for i, att in enumerate(as_list(group.get("AttachedManagedPolicies"))):
        if isinstance(att, dict):
            out.extend(
                _managed_policy_grants(
                    ctx,
                    principal_ref,
                    att,
                    granted_via=via,
                    pointer=json_pointer("GroupDetailList", idx, "AttachedManagedPolicies", i),
                    source=source,
                    holder=holder,
                )
            )
    return out


# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------


def _looks_like_service(name: str, tags: dict[str, str]) -> bool:
    kind = tags.get("type") or tags.get("kind") or tags.get("identity_type") or ""
    if kind.lower() in ("service", "service_account", "service-account", "sa"):
        return True
    return name.lower().startswith(SERVICE_NAME_PREFIXES)


def _principal_raw(record: dict[str, Any], account: str | None) -> dict[str, Any]:
    keep = ("UserName", "UserId", "RoleName", "RoleId", "Arn", "CreateDate", "Path", "GroupList", "Tags")
    raw = {k: record[k] for k in keep if k in record}
    if account:
        raw["account"] = account
    return raw


def _parse_users(ctx: _AwsContext, details: dict[str, Any], source: str) -> None:
    seen: dict[str, int] = {}
    for idx, user in enumerate(as_list(details.get("UserDetailList"))):
        if not isinstance(user, dict):
            continue
        arn = text(user.get("Arn"))
        if not arn:
            continue
        if arn in seen:
            ctx.parse.warnings.append(f"duplicate principal {arn} (entry {idx} replaces {seen[arn]})")
            ctx.parse.principals = [p for p in ctx.parse.principals if p.principal_ref != arn]
            ctx.parse.grants = [g for g in ctx.parse.grants if g.principal_ref != arn]
        seen[arn] = idx
        name = text(user.get("UserName")) or arn.rsplit("/", 1)[-1]
        tags = lower_tags(user.get("Tags"))
        ctx.account_id = ctx.account_id or arn_account(arn)
        ctx.parse.principals.append(
            RawPrincipal(
                principal_ref=arn,
                cloud=CLOUD,
                principal_type="user",
                name=name,
                email=normalise_email(tags.get("email")),
                tags=tags,
                project_hint=text_or_none(tags.get("project")),
                raw=_principal_raw(user, arn_account(arn)),
                is_service=_looks_like_service(name, tags),
                source_file=source,
                source_pointer=json_pointer("UserDetailList", idx),
            )
        )
        ctx.principal_refs.add(arn)
        holder = {"UserName": name}
        for i, pol in enumerate(as_list(user.get("UserPolicyList"))):
            if isinstance(pol, dict):
                ctx.parse.grants.extend(
                    _policy_document_grants(
                        ctx,
                        arn,
                        pol.get("PolicyDocument"),
                        granted_via="direct",
                        policy_name=text(pol.get("PolicyName")),
                        pointer=json_pointer("UserDetailList", idx, "UserPolicyList", i, "PolicyDocument"),
                        source=source,
                        holder=holder,
                    )
                )
        for i, att in enumerate(as_list(user.get("AttachedManagedPolicies"))):
            if isinstance(att, dict):
                ctx.parse.grants.extend(
                    _managed_policy_grants(
                        ctx,
                        arn,
                        att,
                        granted_via=f"managed_policy:{text(att.get('PolicyName')) or text(att.get('PolicyArn'))}",
                        pointer=json_pointer("UserDetailList", idx, "AttachedManagedPolicies", i),
                        source=source,
                        holder=holder,
                    )
                )
        for group in as_list(user.get("GroupList")):
            ctx.parse.grants.extend(_group_grants(ctx, arn, text(group), holder, source))


def _trust_principals(document: Any) -> list[str]:
    """ARNs of AWS principals allowed to assume the role (service principals and `*` are skipped)."""
    out: list[str] = []
    if not isinstance(document, dict):
        return out
    for stmt in as_list(document.get("Statement")):
        if not isinstance(stmt, dict) or text(stmt.get("Effect")).lower() != "allow":
            continue
        actions = {text(a).lower() for a in as_list(stmt.get("Action"))}
        if not any(a in ("sts:assumerole", "sts:*", "*") for a in actions):
            continue
        principal = stmt.get("Principal")
        if isinstance(principal, dict):
            for value in as_list(principal.get("AWS")):
                if text(value).startswith("arn:"):
                    out.append(text(value))
    return out


def _parse_roles(ctx: _AwsContext, details: dict[str, Any], source: str) -> None:
    trust_edges: list[tuple[str, str, str, Any]] = []
    for idx, role in enumerate(as_list(details.get("RoleDetailList"))):
        if not isinstance(role, dict):
            continue
        arn = text(role.get("Arn"))
        if not arn:
            continue
        name = text(role.get("RoleName")) or arn.rsplit("/", 1)[-1]
        tags = lower_tags(role.get("Tags"))
        ctx.account_id = ctx.account_id or arn_account(arn)
        ctx.parse.principals.append(
            RawPrincipal(
                principal_ref=arn,
                cloud=CLOUD,
                principal_type="role",
                name=name,
                email=normalise_email(tags.get("email")),
                tags=tags,
                project_hint=text_or_none(tags.get("project")),
                raw=_principal_raw(role, arn_account(arn)),
                is_service=True,
                source_file=source,
                source_pointer=json_pointer("RoleDetailList", idx),
            )
        )
        ctx.principal_refs.add(arn)
        holder = {"RoleName": name}
        for i, pol in enumerate(as_list(role.get("RolePolicyList"))):
            if isinstance(pol, dict):
                ctx.parse.grants.extend(
                    _policy_document_grants(
                        ctx,
                        arn,
                        pol.get("PolicyDocument"),
                        granted_via="direct",
                        policy_name=text(pol.get("PolicyName")),
                        pointer=json_pointer("RoleDetailList", idx, "RolePolicyList", i, "PolicyDocument"),
                        source=source,
                        holder=holder,
                    )
                )
        for i, att in enumerate(as_list(role.get("AttachedManagedPolicies"))):
            if isinstance(att, dict):
                ctx.parse.grants.extend(
                    _managed_policy_grants(
                        ctx,
                        arn,
                        att,
                        granted_via=f"managed_policy:{text(att.get('PolicyName')) or text(att.get('PolicyArn'))}",
                        pointer=json_pointer("RoleDetailList", idx, "AttachedManagedPolicies", i),
                        source=source,
                        holder=holder,
                    )
                )
        last_used = role.get("RoleLastUsed")
        if isinstance(last_used, dict):
            when = parse_date(last_used.get("LastUsedDate"))
            if when:
                ctx.parse.activity.append(RawActivity(arn, CLOUD, IDENTITY_CATEGORY, when, 1))
        trust_doc = role.get("AssumeRolePolicyDocument")
        for trusted in _trust_principals(trust_doc):
            trust_edges.append(
                (trusted, arn, json_pointer("RoleDetailList", idx, "AssumeRolePolicyDocument"), trust_doc)
            )
    for trusted, role_arn, pointer, trust_doc in trust_edges:
        if trusted not in ctx.principal_refs:
            continue  # trust from another account / an unknown ARN: no principal row to hang it on
        ctx.parse.grants.append(
            RawGrant(
                principal_ref=trusted,
                cloud=CLOUD,
                pairs=((IDENTITY_CATEGORY, "impersonate"),),
                scope_ref=role_arn,
                scope_level="resource",
                region=None,
                effect="allow",
                granted_via="direct",
                raw_snippet={
                    "raw_action": "sts:AssumeRole",
                    "RoleArn": role_arn,
                    "AssumeRolePolicyDocument": trust_doc,
                },
                source_file=source,
                source_pointer=pointer,
            )
        )


# ---------------------------------------------------------------------------
# Credential report, service last accessed, inventory
# ---------------------------------------------------------------------------


def _user_arn_for(ctx: _AwsContext, user: str, arn: str) -> str:
    if arn:
        return arn
    account = ctx.account_id or "000000000000"
    return f"arn:aws:iam::{account}:user/{user}"


def _key_id(row: dict[str, str], slot: int, user: str) -> str:
    for col in (f"access_key_{slot}_id", f"access_key_{slot}_key_id", f"access_key_{slot}_access_key_id"):
        if text_or_none(row.get(col)):
            return text(row.get(col))
    return f"{user}/key-{slot}"  # the standard report carries no key id: positional, stable


def _parse_credential_report(ctx: _AwsContext, rows: list[dict[str, str]], source: str) -> None:
    known = {p.principal_ref: p for p in ctx.parse.principals}
    for n, row in enumerate(rows, start=1):
        user = text(row.get("user"))
        if not user or user == "<root_account>":
            continue
        arn = _user_arn_for(ctx, user, text(row.get("arn")))
        pointer = f"row:{n}"
        principal = known.get(arn)
        if principal is None:
            principal = RawPrincipal(
                principal_ref=arn,
                cloud=CLOUD,
                principal_type="user",
                name=user,
                email=None,
                raw={"UserName": user, "Arn": arn, "account": arn_account(arn)},
                is_service=_looks_like_service(user, {}),
                source_file=source,
                source_pointer=pointer,
            )
            ctx.parse.principals.append(principal)
            ctx.principal_refs.add(arn)
            known[arn] = principal
        principal.mfa = parse_bool(row.get("mfa_active"))
        password_enabled = parse_bool(row.get("password_enabled"))
        created = parse_date(row.get("user_creation_time"))
        any_active = bool(password_enabled)
        if password_enabled is not None:
            pw_used = parse_date(row.get("password_last_used"))
            ctx.parse.credentials.append(
                RawCredential(
                    principal_ref=arn,
                    credential_ref=credential_ref(CLOUD, "password", user),
                    cloud=CLOUD,
                    kind="password",
                    created_at=created,
                    last_rotated_at=parse_date(row.get("password_last_changed")) or created,
                    last_used_at=pw_used,
                    active=bool(password_enabled),
                )
            )
            if pw_used:
                ctx.parse.activity.append(RawActivity(arn, CLOUD, IDENTITY_CATEGORY, pw_used, 1))
        for slot in (1, 2):
            rotated = parse_date(row.get(f"access_key_{slot}_last_rotated"))
            active = parse_bool(row.get(f"access_key_{slot}_active"))
            if rotated is None and not active:
                continue
            used = parse_date(row.get(f"access_key_{slot}_last_used_date"))
            any_active = any_active or bool(active)
            ctx.parse.credentials.append(
                RawCredential(
                    principal_ref=arn,
                    credential_ref=credential_ref(CLOUD, "key", _key_id(row, slot, user)),
                    cloud=CLOUD,
                    kind="key",
                    created_at=rotated or created,
                    last_rotated_at=rotated,
                    last_used_at=used,
                    active=bool(active),
                )
            )
            if used:
                service = text_or_none(row.get(f"access_key_{slot}_last_used_service"))
                category = category_of_ref_service(CLOUD, service, IDENTITY_CATEGORY)
                ctx.parse.activity.append(RawActivity(arn, CLOUD, category, used, 1))
        # A user with no console password and no active key cannot authenticate: its grants are
        # present but not exercisable (this is what `disable_identity` on AWS produces, SPEC §11.5).
        if password_enabled is not None and not any_active:
            principal.enabled = False


def _parse_service_last_accessed(ctx: _AwsContext, entries: list[Any]) -> None:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        arn = text(entry.get("Arn"))
        if not arn:
            continue
        for svc in as_list(entry.get("ServicesLastAccessed")):
            if not isinstance(svc, dict):
                continue
            when = parse_date(svc.get("LastAuthenticated"))
            if when is None:
                continue
            namespace = text_or_none(svc.get("ServiceNamespace"))
            category = category_of_ref_service(CLOUD, namespace, UNKNOWN)
            count = parse_int(svc.get("TotalAuthenticatedEntities")) or 1
            ctx.parse.activity.append(RawActivity(arn, CLOUD, category, when, count))


def parse_inventory(cloud: str, rows: list[Any], month: int, ref_keys: tuple[str, ...]) -> list[ResourceRow]:
    """ATHAR-side inventory `[{arn|ref, service, region, sensitivity, project}]` → ResourceRows."""
    out: dict[str, ResourceRow] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ref = next((text(row[k]) for k in ref_keys if text(row.get(k))), "")
        if not ref:
            continue
        service = text_or_none(row.get("service")) or text_or_none(row.get("category"))
        category = category_of_ref_service(cloud, service, UNKNOWN)
        if category == UNKNOWN and cloud == CLOUD:
            category = category_of_ref_service(cloud, arn_service(ref), UNKNOWN)
        sensitivity = "high" if text(row.get("sensitivity")).lower() == "high" else "low"
        project = (
            text_or_none(row.get("project"))
            or text_or_none(row.get("project_ref"))
            or text_or_none(row.get("project_id"))
        )
        if cloud == CLOUD:
            project = arn_account(ref) or project
        out[ref] = ResourceRow(
            resource_ref=ref,
            cloud=cloud,
            service_category=category,
            region=text_or_none(row.get("region")) or text_or_none(row.get("location")),
            project_ref=project,
            sensitivity=sensitivity,
            snapshot_month=month,
        )
    return [out[k] for k in sorted(out)]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_aws(files: dict[str, Any], month: int, source_prefix: str = "aws/") -> ProviderParse:
    """`files` maps the SPEC §4.6 file names to their decoded content (dict / list / CSV rows)."""
    ctx = _AwsContext(month, source_prefix)
    inventory = files.get(RESOURCES)
    if isinstance(inventory, list):
        ctx.parse.resources = parse_inventory(CLOUD, inventory, month, ("arn", "ref", "resource_ref", "id"))
        ctx.inventory = _Inventory(ctx.parse.resources)
        for res in ctx.parse.resources:
            ctx.account_id = ctx.account_id or arn_account(res.resource_ref)
    details = files.get(AUTH_DETAILS)
    if isinstance(details, dict):
        source = ctx.src(AUTH_DETAILS)
        for idx, group in enumerate(as_list(details.get("GroupDetailList"))):
            if isinstance(group, dict) and text(group.get("GroupName")):
                ctx.groups[text(group.get("GroupName"))] = (idx, group)
        for idx, pol in enumerate(as_list(details.get("Policies"))):
            if isinstance(pol, dict):
                if text(pol.get("Arn")):
                    ctx.policies_by_arn[text(pol.get("Arn"))] = (idx, pol)
                if text(pol.get("PolicyName")):
                    ctx.policies_by_name[text(pol.get("PolicyName"))] = (idx, pol)
        _parse_users(ctx, details, source)
        _parse_roles(ctx, details, source)
    report = files.get(CREDENTIAL_REPORT)
    if isinstance(report, list):
        _parse_credential_report(ctx, [r for r in report if isinstance(r, dict)], ctx.src(CREDENTIAL_REPORT))
    accessed = files.get(SERVICE_LAST_ACCESSED)
    if isinstance(accessed, list):
        _parse_service_last_accessed(ctx, accessed)
    elif isinstance(accessed, dict):
        _parse_service_last_accessed(ctx, as_list(accessed.get("Entries") or accessed.get("entries")))
    return ctx.parse


def merge_activity(rows: list[RawActivity]) -> list[RawActivity]:
    """One row per (principal, category): latest date, summed counts. Sorted."""
    merged: dict[tuple[str, str, str], RawActivity] = {}
    for row in rows:
        key = (row.principal_ref, row.cloud, row.service_category)
        prev = merged.get(key)
        if prev is None:
            merged[key] = row
        else:
            merged[key] = RawActivity(
                row.principal_ref,
                row.cloud,
                row.service_category,
                max_date(prev.last_activity_at, row.last_activity_at),
                prev.operation_count + row.operation_count,
            )
    return [merged[k] for k in sorted(merged)]
