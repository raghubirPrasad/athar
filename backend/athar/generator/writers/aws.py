"""AWS native exports (SPEC §4.6). Pure.

  aws/authorization-details.json  `aws iam get-account-authorization-details`
  aws/credential-report.csv       `aws iam get-credential-report`
  aws/service-last-accessed.json  `aws iam get-service-last-accessed-details`, one entry per principal
  aws/resources.json              ATHAR-side inventory (see `writers/inventory.py`)

An identity present in AWS is an IAM **user** (`arn:aws:iam::<account>:user/<name>`, the HR email
local part, SPEC §6 rule 3). Its simulated grants become inline user policies (`UserPolicyList`),
attached managed policies (`AttachedManagedPolicies`) and department group membership
(`GroupList` → `GroupDetailList`). Two IAM **roles** carry no owner tag and no HR record on
purpose: they are the estate's unowned principals (finding R10, SPEC §6 rule 6).

# SPEC? §4.6 does not say what an export shows after access is revoked. The simpler reading is
# taken here: only principals the identity still holds are exported, so an offboarding that DID
# revoke access deletes the IAM user, while the interesting case — the offboarding ticket that was
# never closed — leaves the user, its policies and its credential-report row in place.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta
from typing import Any

from athar.clock import EPOCH, month_end
from athar.generator import catalogue as cat
from athar.generator.names import DEPARTMENT_SLUG
from athar.generator.simulator import AWS_FILLER_ROLES
from athar.generator.state import Credential, EstateState, Grant, Identity, MonthSnapshot
from athar.generator.writers import (
    NO_INFORMATION,
    NOT_AVAILABLE,
    NOT_SUPPORTED,
    business_ts,
    csv_text,
    dumps,
    opt_ts,
)
from athar.generator.writers import inventory as inv

CLOUD = "aws"
POLICY_VERSION = "2012-10-17"
HOME_REGION = cat.HOME_REGION[CLOUD]

# Job-function managed policies live under a different ARN path than the rest.
_JOB_FUNCTION: frozenset[str] = frozenset({"Billing", "ViewOnlyAccess", "DatabaseAdministrator"})

# Static objects that pre-date the simulation window (SPEC §4.5: no `datetime.now()`).
_ROOT_CREATED = EPOCH - timedelta(days=1460)
_GROUP_CREATED = EPOCH - timedelta(days=730)
_AWS_POLICY_CREATED = EPOCH - timedelta(days=2200)
_CUSTOMER_POLICY_CREATED = EPOCH - timedelta(days=400)
_ROLE_CREATED = EPOCH - timedelta(days=520)

CREDENTIAL_REPORT_COLUMNS: tuple[str, ...] = (
    "user",
    "arn",
    "user_creation_time",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_1_last_used_region",
    "access_key_1_last_used_service",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
)

# The two unowned IAM roles (SPEC §6 rule 6 → R10). Deliberately modest permissions: they must be
# unowned, not over-privileged, and `RoleLastUsed` keeps them out of the dormancy rule.
_FILLER_ROLE_SPECS: dict[str, dict[str, Any]] = {
    "nda-lambda-exec": {
        "service": "lambda.amazonaws.com",
        "description": "Execution role assumed by the citizen-service Lambda functions.",
        "inline": [
            (
                "nda-lambda-exec-logs",
                [
                    {
                        "Sid": "WriteFunctionLogs",
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:{region}:{account}:log-group:/aws/lambda/*",
                    }
                ],
            )
        ],
        "managed": (),
        "tags": {"managed_by": "terraform", "purpose": "lambda-execution"},
        "services": ("lambda", "cloudtrail"),
    },
    "nda-ci-deploy": {
        "service": "codebuild.amazonaws.com",
        "description": "Build role assumed by the delivery pipeline to read release artefacts.",
        "inline": [],
        "managed": ("AmazonS3ReadOnlyAccess",),
        "tags": {"managed_by": "terraform", "purpose": "ci-pipeline"},
        "services": ("s3",),
    },
}


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


def managed_policy_arn(name: str, account: str) -> str:
    """`arn:aws:iam::aws:policy/<name>` for an AWS managed policy, the account's own ARN for a
    customer-managed one (SPEC §4.6)."""
    if name in cat.AWS_CUSTOMER_MANAGED:
        return f"arn:aws:iam::{account}:policy/{name}"
    if name in _JOB_FUNCTION:
        return f"arn:aws:iam::aws:policy/job-function/{name}"
    return f"arn:aws:iam::aws:policy/{name}"


def group_arn(name: str, account: str) -> str:
    return f"arn:aws:iam::{account}:group/{name}"


def role_arn(name: str, account: str) -> str:
    return f"arn:aws:iam::{account}:role/{name}"


def _sid(name: str, index: int, total: int) -> str:
    base = "".join(part.capitalize() for part in name.replace("_", "-").split("-") if part)
    return base if total == 1 else f"{base}{index + 1}"


def _one_or_many(values: list[str]) -> Any:
    return values[0] if len(values) == 1 else values


# ---------------------------------------------------------------------------
# Grants → policy documents
# ---------------------------------------------------------------------------


def _statement(grant: Grant, index: int, total: int) -> dict[str, Any]:
    actions = list(grant.actions) or ["*"]
    resources = list(grant.native_scopes) or [grant.scope_ref]
    return {
        "Sid": _sid(grant.name, index, total),
        "Effect": "Allow",
        "Action": _one_or_many(actions),
        "Resource": _one_or_many(resources),
    }


def inline_policies(grants: list[Grant]) -> list[dict[str, Any]]:
    """One `UserPolicyList` entry per inline policy name (a user cannot hold two of the same name);
    a policy granted at several scopes carries one statement per scope."""
    by_name: dict[str, list[Grant]] = defaultdict(list)
    for grant in grants:
        if grant.kind == "aws_inline":
            by_name[grant.name].append(grant)
    out: list[dict[str, Any]] = []
    for name in sorted(by_name):
        statements = sorted(by_name[name], key=lambda g: (g.scope_ref, g.grant_ref))
        out.append(
            {
                "PolicyName": name,
                "PolicyDocument": {
                    "Version": POLICY_VERSION,
                    "Statement": [_statement(g, i, len(statements)) for i, g in enumerate(statements)],
                },
            }
        )
    return out


def attached_policies(grants: list[Grant], account: str) -> list[dict[str, Any]]:
    names = sorted({g.name for g in grants if g.kind == "aws_managed"})
    return [{"PolicyName": name, "PolicyArn": managed_policy_arn(name, account)} for name in names]


def _tags(ident: Identity) -> list[dict[str, str]]:
    tags = dict(ident.tags)
    if not ident.is_human:
        tags.setdefault("type", "service")
    return [{"Key": key, "Value": tags[key]} for key in sorted(tags)]


# ---------------------------------------------------------------------------
# authorization-details.json
# ---------------------------------------------------------------------------


def _aws_identities(snapshot: MonthSnapshot) -> list[Identity]:
    return [
        snapshot.identities[i]
        for i in sorted(snapshot.identities)
        if snapshot.identities[i].present_in(CLOUD)
    ]


def _grants_by_identity(snapshot: MonthSnapshot) -> dict[str, list[Grant]]:
    out: dict[str, list[Grant]] = defaultdict(list)
    for grant in snapshot.grants:
        if grant.cloud == CLOUD:
            out[grant.identity_id].append(grant)
    return out


def _home_bucket(snapshot: MonthSnapshot, department: str) -> str | None:
    """The department's AWS home-project bucket ARN (the group's read statement scopes to it)."""
    projects = [
        p
        for p in snapshot.projects.values()
        if p.cloud == CLOUD and p.kind == "department" and p.department == department
    ]
    if not projects:
        return None
    project = min(projects, key=lambda p: p.project_id)
    buckets = [r for r in snapshot.resources if r.project_id == project.project_id and r.kind == "bucket"]
    return min(buckets, key=lambda r: r.ref).ref if buckets else None


def _group_details(
    snapshot: MonthSnapshot, account: str, names: set[str], ids: dict[str, str], attached: Counter[str]
) -> list[dict[str, Any]]:
    slug_of = {f"grp-{slug}": (dept, slug) for dept, slug in DEPARTMENT_SLUG.items()}
    out: list[dict[str, Any]] = []
    for name in sorted(names):
        department, slug = slug_of.get(name, ("Unassigned", name.removeprefix("grp-")))
        template = cat.aws_group_read_inline(slug)
        bucket = _home_bucket(snapshot, department)
        inline: list[dict[str, Any]] = []
        if bucket:
            inline.append(
                {
                    "PolicyName": template.name,
                    "PolicyDocument": {
                        "Version": POLICY_VERSION,
                        "Statement": [
                            {
                                "Sid": _sid(template.name, 0, 1),
                                "Effect": "Allow",
                                "Action": list(template.actions),
                                "Resource": [bucket, f"{bucket}/*"],
                            }
                        ],
                    },
                }
            )
        attached[cat.AWS_READONLY.name] += 1
        out.append(
            {
                "Path": "/",
                "GroupName": name,
                "GroupId": ids.get(name, ""),
                "Arn": group_arn(name, account),
                "CreateDate": business_ts(_GROUP_CREATED, name),
                "GroupPolicyList": inline,
                "AttachedManagedPolicies": [
                    {
                        "PolicyName": cat.AWS_READONLY.name,
                        "PolicyArn": managed_policy_arn(cat.AWS_READONLY.name, account),
                    }
                ],
            }
        )
    return out


def _role_details(
    state: EstateState, snapshot: MonthSnapshot, attached: Counter[str]
) -> list[dict[str, Any]]:
    account = state.constants.aws_account_id
    last_used = month_end(snapshot.month) - timedelta(days=2)
    out: list[dict[str, Any]] = []
    for name in sorted(AWS_FILLER_ROLES):
        spec = _FILLER_ROLE_SPECS[name]
        inline = [
            {
                "PolicyName": policy_name,
                "PolicyDocument": {
                    "Version": POLICY_VERSION,
                    "Statement": [
                        {
                            **stmt,
                            "Resource": str(stmt["Resource"]).format(region=HOME_REGION, account=account),
                        }
                        for stmt in statements
                    ],
                },
            }
            for policy_name, statements in spec["inline"]
        ]
        for policy_name in spec["managed"]:
            attached[policy_name] += 1
        out.append(
            {
                "Path": "/",
                "RoleName": name,
                "RoleId": state.constants.aws_ids.get(f"role:{name}", ""),
                "Arn": role_arn(name, account),
                "CreateDate": business_ts(_ROLE_CREATED, name),
                "Description": spec["description"],
                "AssumeRolePolicyDocument": {
                    "Version": POLICY_VERSION,
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": spec["service"]},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "InstanceProfileList": [],
                "RolePolicyList": inline,
                "AttachedManagedPolicies": [
                    {"PolicyName": p, "PolicyArn": managed_policy_arn(p, account)}
                    for p in sorted(spec["managed"])
                ],
                "RoleLastUsed": {"LastUsedDate": business_ts(last_used, name), "Region": HOME_REGION},
                "Tags": [{"Key": k, "Value": v} for k, v in sorted(dict(spec["tags"]).items())],
            }
        )
    return out


def _citizen_deny_statements(snapshot: MonthSnapshot) -> list[dict[str, Any]] | None:
    """The guardrail document for this month, scoped to the bucket its own grant names.

    None when nobody holds the guardrail yet, which is every month before
    `cat.CITIZEN_DENY_FROM_MONTH` — the policy is then not attached either, so no document is due.
    """
    refs = sorted(
        {g.scope_ref for g in snapshot.grants if g.name == cat.AWS_CITIZEN_DENY_POLICY and not g.is_allow}
    )
    return cat.citizen_deny_statements(refs[0]) if refs else None


def _policy_details(
    state: EstateState, snapshot: MonthSnapshot, attached: Counter[str]
) -> list[dict[str, Any]]:
    """`Policies`: the document of every policy attached this month, as the real export carries it.

    One customer-managed policy is where R0's mapping miss lives (an action no table knows); the
    other is the citizen-data guardrail, whose document is the only place its `Deny` is stated.
    A policy attached with no document here is silently dropped from the export, and the normaliser
    then reads the attachment as an ordinary allow — which is exactly how the guardrail's `deny`
    rows went missing from the canonical model.
    """
    account = state.constants.aws_account_id
    out: list[dict[str, Any]] = []
    for name in sorted(attached):
        if name == cat.AWS_CITIZEN_DENY_POLICY:
            statements = _citizen_deny_statements(snapshot)
        else:
            statements = cat.AWS_MANAGED_POLICY_DOCUMENTS.get(name)
        if statements is None:
            continue
        customer = name in cat.AWS_CUSTOMER_MANAGED
        created = _CUSTOMER_POLICY_CREATED if customer else _AWS_POLICY_CREATED
        out.append(
            {
                "PolicyName": name,
                "PolicyId": state.constants.aws_ids.get(f"policy:{name}", ""),
                "Arn": managed_policy_arn(name, account),
                "Path": "/",
                "DefaultVersionId": "v1",
                "AttachmentCount": attached[name],
                "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True,
                "CreateDate": business_ts(created, name),
                "UpdateDate": business_ts(created, f"{name}:update"),
                "PolicyVersionList": [
                    {
                        "Document": {"Version": POLICY_VERSION, "Statement": statements},
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "CreateDate": business_ts(created, f"{name}:v1"),
                    }
                ],
            }
        )
    return out


def authorization_details(state: EstateState, snapshot: MonthSnapshot) -> dict[str, Any]:
    account = state.constants.aws_account_id
    grants = _grants_by_identity(snapshot)
    attached: Counter[str] = Counter()
    group_names: set[str] = set()
    users: list[dict[str, Any]] = []
    for ident in _aws_identities(snapshot):
        held = grants.get(ident.identity_id, [])
        groups = sorted({g.name for g in held if g.kind == "aws_group"})
        group_names.update(groups)
        for name in {g.name for g in held if g.kind == "aws_managed"}:
            attached[name] += 1
        users.append(
            {
                "Path": "/" if ident.is_human else "/service/",
                "UserName": ident.username,
                "UserId": ident.aws_user_id,
                "Arn": ident.aws_arn(account),
                "CreateDate": business_ts(ident.start_date, ident.identity_id),
                "UserPolicyList": inline_policies(held),
                "GroupList": groups,
                "AttachedManagedPolicies": attached_policies(held, account),
                "Tags": _tags(ident),
            }
        )
    ids = {k: v for k, v in state.constants.aws_ids.items() if k.startswith("grp-")}
    group_details = _group_details(snapshot, account, group_names, ids, attached)
    role_details = _role_details(state, snapshot, attached)
    return {
        "UserDetailList": users,
        "GroupDetailList": group_details,
        "RoleDetailList": role_details,
        "Policies": _policy_details(state, snapshot, attached),  # counted after users, groups and roles
    }


# ---------------------------------------------------------------------------
# credential-report.csv
# ---------------------------------------------------------------------------


def _aws_keys(snapshot: MonthSnapshot, identity_id: str) -> list[Credential]:
    """The user's access keys in slot order. The report carries no key id, so the slot is
    positional and stable: oldest first (this is the order `rotate_or_disable_credential`
    addresses with `aws:key:<user>/key-<slot>`)."""
    keys = [c for c in snapshot.credentials if c.identity_id == identity_id and c.cloud == CLOUD]
    return sorted(keys, key=lambda c: (c.created, c.key_id))[:2]


def _last_activity(snapshot: MonthSnapshot) -> dict[str, tuple[date, str]]:
    """identity → (last AWS activity, the service namespace it was on), one pass over the month."""
    out: dict[str, tuple[date, str]] = {}
    for identity_id, cloud, service in sorted(snapshot.activity):
        record = snapshot.activity[(identity_id, cloud, service)]
        if cloud != CLOUD or record.last is None:
            continue
        seen = out.get(identity_id)
        if seen is None or record.last > seen[0]:
            out[identity_id] = (record.last, service)
    return out


def credential_report(state: EstateState, snapshot: MonthSnapshot) -> str:
    account = state.constants.aws_account_id
    rows: list[tuple[Any, ...]] = [
        (
            "<root_account>",
            f"arn:aws:iam::{account}:root",
            business_ts(_ROOT_CREATED, "root"),
            NOT_SUPPORTED,
            business_ts(_ROOT_CREATED + timedelta(days=30), "root-login"),
            NOT_SUPPORTED,
            "true",
            "false",
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            "false",
            NOT_AVAILABLE,
            NOT_AVAILABLE,
        )
    ]
    as_of = snapshot.as_of
    activity = _last_activity(snapshot)
    for ident in sorted(_aws_identities(snapshot), key=lambda i: i.username):
        disabled = CLOUD in ident.disabled_clouds
        # A service user never had a console password, and `disable_identity` deletes the login
        # profile: in both cases the report says `not_supported`, not `false`.
        console = ident.is_human and not ident.console_disabled and not disabled
        seen = activity.get(ident.identity_id)
        keys = _aws_keys(snapshot, ident.identity_id)
        cells: list[Any] = [
            ident.username,
            ident.aws_arn(account),
            business_ts(ident.start_date, ident.identity_id),
            "true" if console else "false",
        ]
        if console:
            cells += [
                opt_ts(seen[0] if seen else None, f"{ident.identity_id}:console") or NO_INFORMATION,
                business_ts(ident.password_last_changed(as_of), f"{ident.identity_id}:password"),
            ]
        else:
            cells += [NOT_SUPPORTED, NOT_SUPPORTED]
        cells.append("true" if (ident.is_human and ident.mfa) else "false")
        for slot in (1, 2):
            key = keys[slot - 1] if len(keys) >= slot else None
            if key is None:
                cells += ["false", NOT_AVAILABLE, NOT_AVAILABLE]
                if slot == 1:
                    cells += [NOT_AVAILABLE, NOT_AVAILABLE]
                continue
            cells += [
                "true" if key.active else "false",
                business_ts(key.last_rotated, key.key_id),
                opt_ts(key.last_used, key.credential_ref) or NOT_AVAILABLE,
            ]
            if slot == 1 and key.last_used is not None:
                cells += [HOME_REGION, (seen[1] if seen else None) or NOT_AVAILABLE]
            elif slot == 1:
                cells += [NOT_AVAILABLE, NOT_AVAILABLE]
        rows.append(tuple(cells))
    return csv_text(CREDENTIAL_REPORT_COLUMNS, rows)


# ---------------------------------------------------------------------------
# service-last-accessed.json
# ---------------------------------------------------------------------------


def _service_entry(namespace: str, day: date | None, key: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ServiceName": cat.AWS_SERVICE_NAMES.get(namespace, namespace),
        "ServiceNamespace": namespace,
        "TotalAuthenticatedEntities": 1 if day else 0,
    }
    if day is not None:
        entry["LastAuthenticated"] = business_ts(day, key)
    return entry


def service_last_accessed(state: EstateState, snapshot: MonthSnapshot) -> list[dict[str, Any]]:
    """One entry per principal, listing every service its policies allow — used or not. The
    unused ones are what the least-privilege planner (SPEC §11.5) drops."""
    account = state.constants.aws_account_id
    grants = _grants_by_identity(snapshot)
    used: dict[tuple[str, str], date] = {}
    for (identity_id, cloud, service), record in snapshot.activity.items():
        if cloud == CLOUD and record.last is not None:
            key = (identity_id, service)
            if record.last > used.get(key, date.min):
                used[key] = record.last
    out: list[dict[str, Any]] = []
    for ident in _aws_identities(snapshot):
        namespaces = {s for g in grants.get(ident.identity_id, []) for s in g.services if s}
        namespaces |= {service for (iid, service) in used if iid == ident.identity_id}
        if not namespaces:
            continue
        out.append(
            {
                "Arn": ident.aws_arn(account),
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [
                    _service_entry(
                        namespace,
                        used.get((ident.identity_id, namespace)),
                        f"{ident.identity_id}:{namespace}",
                    )
                    for namespace in sorted(namespaces)
                ],
            }
        )
    role_day = month_end(snapshot.month) - timedelta(days=2)
    for name in sorted(AWS_FILLER_ROLES):
        out.append(
            {
                "Arn": role_arn(name, account),
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [
                    _service_entry(namespace, role_day, f"{name}:{namespace}")
                    for namespace in sorted(_FILLER_ROLE_SPECS[name]["services"])
                ],
            }
        )
    return sorted(out, key=lambda entry: entry["Arn"])


def aws_files(state: EstateState, snapshot: MonthSnapshot) -> dict[str, str]:
    return {
        "aws/authorization-details.json": dumps(authorization_details(state, snapshot)),
        "aws/credential-report.csv": credential_report(state, snapshot),
        "aws/service-last-accessed.json": dumps(service_last_accessed(state, snapshot)),
        "aws/resources.json": dumps(inv.aws_resources(state, snapshot)),
    }
