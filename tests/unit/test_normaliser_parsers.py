"""Provider parsers on small inline documents (SPEC §4.6 shapes → §5 raw rows). Pure."""

from __future__ import annotations

from datetime import date

from athar.normaliser.mappings import full_wildcard
from athar.normaliser.parsers import aws as aws_p
from athar.normaliser.parsers import azure as az_p
from athar.normaliser.parsers import gcp as gcp_p
from athar.normaliser.parsers import hr as hr_p
from athar.normaliser.parsers.common import parse_bool, parse_date, parse_int, read_csv_rows
from athar.normaliser.types import UNKNOWN_PAIR, RawActivity

ACCOUNT = "123456789012"
SUB = "/subscriptions/11111111-1111-4111-8111-111111111111"


def _user(name: str, **extra: object) -> dict:
    base: dict = {
        "UserName": name,
        "UserId": "AIDA" + name.upper()[:10],
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": "2025-09-01T00:00:00Z",
        "UserPolicyList": [],
        "GroupList": [],
        "AttachedManagedPolicies": [],
        "Tags": [],
    }
    base.update(extra)
    return base


def _inline(name: str, *statements: dict) -> dict:
    return {"PolicyName": name, "PolicyDocument": {"Version": "2012-10-17", "Statement": list(statements)}}


# ---------------------------------------------------------------- common


def test_parse_date_accepts_iso_variants_and_rejects_the_rest() -> None:
    assert parse_date("2025-09-24T10:00:00Z") == date(2025, 9, 24)
    assert parse_date("2025-09-24T10:00:00.123+04:00") == date(2025, 9, 24)
    assert parse_date("2025-09-24") == date(2025, 9, 24)
    assert parse_date("2025-09-24 10:00:00") == date(2025, 9, 24)
    for bad in ("N/A", "no_information", "not_supported", "", None, "NaN", float("nan"), "yesterday", 42):
        assert parse_date(bad) is None, bad


def test_parse_bool_and_int_are_lenient() -> None:
    assert parse_bool("true") is True and parse_bool("FALSE") is False and parse_bool(True) is True
    assert parse_bool("not_supported") is None and parse_bool(None) is None
    assert parse_int("17") == 17 and parse_int("3.0") == 3 and parse_int("N/A") == 0 and parse_int(None) == 0


def test_read_csv_rows_skips_comment_bom_and_blank_lines() -> None:
    text = "﻿# SYNTHETIC marker\n\nA,B\n1,2\n\n,\n3\n"
    header, rows = read_csv_rows(text)
    assert header == ["a", "b"]
    assert rows == [{"a": "1", "b": "2"}, {"a": "3", "b": ""}]
    assert read_csv_rows("") == ([], [])
    assert read_csv_rows("# only a comment\n") == ([], [])


# ---------------------------------------------------------------- AWS


def test_arn_helpers() -> None:
    arn = f"arn:aws:dynamodb:me-central-1:{ACCOUNT}:table/x"
    assert aws_p.arn_region(arn) == "me-central-1"
    assert aws_p.arn_account(arn) == ACCOUNT
    assert aws_p.arn_service(arn) == "dynamodb"
    assert aws_p.arn_region("arn:aws:s3:::bucket") is None
    assert aws_p.arn_account("arn:aws:s3:::bucket") is None
    assert aws_p.arn_region("*") is None and aws_p.arn_service("*") is None


def test_not_action_statement_subtracts_from_the_full_wildcard() -> None:
    details = {
        "UserDetailList": [
            _user(
                "dev",
                UserPolicyList=[
                    _inline("no-iam", {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})
                ],
            )
        ]
    }
    parse = aws_p.parse_aws({aws_p.AUTH_DETAILS: details}, 1)
    pairs = set(parse.grants[0].pairs)
    assert pairs
    assert not any(c == "identity" for c, _ in pairs)
    assert ("storage", "read") in pairs
    assert pairs == {p for p in full_wildcard() if p[0] != "identity"}
    assert parse.grants[0].raw_snippet["raw_action"] == ["iam:*"]
    assert not parse.unmapped


def test_duplicate_user_entries_last_wins_with_a_warning() -> None:
    first = _user(
        "dup",
        AttachedManagedPolicies=[
            {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        ],
    )
    second = _user(
        "dup",
        AttachedManagedPolicies=[
            {
                "PolicyName": "AmazonS3ReadOnlyAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            }
        ],
    )
    parse = aws_p.parse_aws({aws_p.AUTH_DETAILS: {"UserDetailList": [first, second]}}, 1)
    assert len(parse.principals) == 1
    assert {g.granted_via for g in parse.grants} == {"managed_policy:AmazonS3ReadOnlyAccess"}
    assert any("duplicate principal" in w for w in parse.warnings)


def test_credential_report_skips_root_and_uses_key_id_column_when_present() -> None:
    rows = [
        {
            "user": "<root_account>",
            "arn": f"arn:aws:iam::{ACCOUNT}:root",
            "mfa_active": "true",
            "password_enabled": "not_supported",
        },
        {
            "user": "keyed",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/keyed",
            "user_creation_time": "2025-01-01T00:00:00Z",
            "password_enabled": "false",
            "mfa_active": "false",
            "access_key_1_active": "true",
            "access_key_1_id": "AKIAEXAMPLEKEY000001",
            "access_key_1_last_rotated": "2025-01-01T00:00:00Z",
            "access_key_1_last_used_date": "N/A",
            "access_key_2_active": "false",
            "access_key_2_last_rotated": "N/A",
        },
    ]
    parse = aws_p.parse_aws(
        {aws_p.AUTH_DETAILS: {"UserDetailList": [_user("keyed")]}, aws_p.CREDENTIAL_REPORT: rows}, 1
    )
    refs = {c.credential_ref: c for c in parse.credentials}
    assert "aws:key:AKIAEXAMPLEKEY000001" in refs
    assert refs["aws:key:AKIAEXAMPLEKEY000001"].last_used_at is None
    assert refs["aws:password:keyed"].active is False
    assert all("root" not in c.credential_ref for c in parse.credentials)
    assert parse.principals[0].mfa is False
    assert parse.principals[0].enabled is True  # an active key can still authenticate


def test_user_without_console_or_active_key_is_disabled() -> None:
    row = {
        "user": "gone",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/gone",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "2024-01-01T00:00:00Z",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
    }
    parse = aws_p.parse_aws(
        {aws_p.AUTH_DETAILS: {"UserDetailList": [_user("gone")]}, aws_p.CREDENTIAL_REPORT: [row]}, 1
    )
    assert parse.principals[0].enabled is False
    assert {c.credential_ref: c.active for c in parse.credentials} == {
        "aws:password:gone": False,
        "aws:key:gone/key-1": False,
    }


def test_credential_report_user_absent_from_authorization_details_gets_a_principal() -> None:
    row = {"user": "orphan", "arn": "", "password_enabled": "true", "mfa_active": "true"}
    parse = aws_p.parse_aws(
        {aws_p.AUTH_DETAILS: {"UserDetailList": [_user("other")]}, aws_p.CREDENTIAL_REPORT: [row]}, 1
    )
    refs = {p.principal_ref for p in parse.principals}
    assert f"arn:aws:iam::{ACCOUNT}:user/orphan" in refs  # account id learned from the other ARN


def test_service_last_accessed_accepts_wrapper_shape_and_unknown_namespaces() -> None:
    entries = {
        "Entries": [
            {
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/x",
                "ServicesLastAccessed": [
                    {
                        "ServiceNamespace": "s3",
                        "LastAuthenticated": "2025-09-01T00:00:00Z",
                        "TotalAuthenticatedEntities": 2,
                    },
                    {"ServiceNamespace": "frobnicator", "LastAuthenticated": "2025-09-02T00:00:00Z"},
                    {"ServiceNamespace": "ec2"},
                ],
            }
        ]
    }
    parse = aws_p.parse_aws({aws_p.SERVICE_LAST_ACCESSED: entries}, 1)
    assert [(a.service_category, a.last_activity_at, a.operation_count) for a in parse.activity] == [
        ("storage", date(2025, 9, 1), 2),
        ("unknown", date(2025, 9, 2), 1),
    ]


def test_unknown_managed_policy_is_unmapped_at_global_scope() -> None:
    user = _user(
        "u",
        AttachedManagedPolicies=[
            {"PolicyName": "VendorThing", "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/VendorThing"}
        ],
    )
    parse = aws_p.parse_aws({aws_p.AUTH_DETAILS: {"UserDetailList": [user]}}, 1)
    g = parse.grants[0]
    assert g.pairs == (UNKNOWN_PAIR,) and g.scope_level == "global" and g.scope_ref == "*"
    assert g.unmapped == ("VendorThing",)
    assert [u.raw for u in parse.unmapped] == ["VendorThing"]
    assert g.source_pointer == "/UserDetailList/0/AttachedManagedPolicies/0"


def test_trust_from_unknown_arn_is_ignored() -> None:
    role = {
        "RoleName": "r",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/r",
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    }
    parse = aws_p.parse_aws({aws_p.AUTH_DETAILS: {"RoleDetailList": [role]}}, 1)
    assert parse.principals[0].principal_type == "role" and parse.principals[0].is_service
    assert not any(("identity", "impersonate") in g.pairs for g in parse.grants)


def test_merge_activity_keeps_latest_date_and_sums_counts() -> None:
    rows = [
        RawActivity("p", "aws", "storage", date(2025, 1, 1), 1),
        RawActivity("p", "aws", "storage", date(2025, 3, 1), 2),
        RawActivity("p", "aws", "storage", None, 4),
        RawActivity("a", "aws", "compute", None, 0),
    ]
    merged = aws_p.merge_activity(rows)
    assert [(r.principal_ref, r.service_category, r.last_activity_at, r.operation_count) for r in merged] == [
        ("a", "compute", None, 0),
        ("p", "storage", date(2025, 3, 1), 7),
    ]


def test_inventory_rows_tolerate_missing_and_odd_fields() -> None:
    rows = [
        {"arn": "arn:aws:s3:::b", "sensitivity": "HIGH"},
        {"service": "s3"},
        "not a dict",
        {
            "arn": "arn:aws:ec2:eu-west-1:123456789012:instance/i-1",
            "service": "ec2",
            "region": "eu-west-1",
            "sensitivity": "medium",
        },
    ]
    res = aws_p.parse_inventory("aws", rows, 3, ("arn",))
    assert [(r.resource_ref, r.service_category, r.region, r.sensitivity, r.project_ref) for r in res] == [
        ("arn:aws:ec2:eu-west-1:123456789012:instance/i-1", "compute", "eu-west-1", "low", ACCOUNT),
        ("arn:aws:s3:::b", "storage", None, "high", None),
    ]
    assert all(r.snapshot_month == 3 for r in res)


# ---------------------------------------------------------------- Azure


def test_guid_of_takes_the_role_guid_not_the_subscription() -> None:
    rid = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/8E3AF657-A8FF-443C-A75C-2FE8C4BCB635"
    assert az_p.guid_of(rid) == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    assert az_p.guid_of("8e3af657-a8ff-443c-a75c-2fe8c4bcb635") == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    assert az_p.guid_of("Owner") == "owner"


def test_scope_helpers() -> None:
    scope = f"{SUB}/resourceGroups/RG-Payments/providers/Microsoft.Sql/servers/s"
    assert az_p.subscription_of(scope) == SUB
    assert az_p.resource_group_of(scope) == "RG-Payments"
    assert az_p.provider_of(scope) == "Microsoft.Sql"
    assert az_p.subscription_of("/") is None and az_p.resource_group_of(SUB) is None


def _assignment(
    oid: str, role_name: str, role_guid: str, scope: str, ptype: str = "User", pname: str = ""
) -> dict:
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{oid[:8]}-ra",
        "principalId": oid,
        "principalType": ptype,
        "principalName": pname,
        "roleDefinitionId": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role_guid}",
        "roleDefinitionName": role_name,
        "scope": scope,
    }


def test_custom_role_from_definitions_honours_not_actions() -> None:
    guid = "dddddddd-0009-4000-8000-000000000009"
    definition = {
        "id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{guid}",
        "name": guid,
        "roleName": "Blob Ops",
        "permissions": [
            {
                "actions": ["Microsoft.Storage/*"],
                "notActions": ["Microsoft.Storage/storageAccounts/delete"],
                "dataActions": [],
                "notDataActions": [],
            }
        ],
    }
    files = {
        az_p.ROLE_ASSIGNMENTS: [
            _assignment(
                "aaaaaaaa-0001-4000-8000-000000000001", "Blob Ops", guid, f"{SUB}/resourceGroups/rg-x"
            )
        ],
        az_p.ROLE_DEFINITIONS: [definition],
    }
    parse = az_p.parse_azure(files, 1)
    assert set(parse.grants[0].pairs) == {("storage", "read"), ("storage", "write"), ("storage", "admin")}
    assert parse.grants[0].granted_via == "role:Blob Ops"
    assert parse.grants[0].scope_level == "resource"
    assert not parse.unmapped


def test_undefined_role_is_unmapped_never_a_crash() -> None:
    files = {
        az_p.ROLE_ASSIGNMENTS: [
            _assignment(
                "aaaaaaaa-0001-4000-8000-000000000001",
                "Vendor Role",
                "dddddddd-0002-4000-8000-000000000002",
                SUB,
            )
        ]
    }
    parse = az_p.parse_azure(files, 1)
    assert parse.grants[0].pairs == (UNKNOWN_PAIR,)
    assert [u.raw for u in parse.unmapped] == ["Vendor Role"]
    assert parse.grants[0].scope_level == "project"


def test_built_in_role_by_guid_without_a_name() -> None:
    files = {
        az_p.ROLE_ASSIGNMENTS: [
            _assignment(
                "aaaaaaaa-0001-4000-8000-000000000001", "", "acdd72a7-3385-48ef-bd42-f606fba81ae7", SUB
            )
        ]
    }
    parse = az_p.parse_azure(files, 1)
    assert set(parse.grants[0].pairs) == {
        (c, "read") for c in ("compute", "storage", "network", "identity", "data", "security", "billing")
    }
    assert parse.grants[0].granted_via == "role:acdd72a7-3385-48ef-bd42-f606fba81ae7"


def test_service_principal_gets_project_and_owner_from_resource_group_tags() -> None:
    scope = f"{SUB}/resourceGroups/rg-pay"
    files = {
        az_p.ROLE_ASSIGNMENTS: [
            _assignment(
                "cccccccc-0001-4000-8000-000000000001",
                "Reader",
                "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                scope,
                "ServicePrincipal",
                "sp-x",
            )
        ],
        az_p.RESOURCE_GROUPS: [
            {
                "name": "rg-pay",
                "location": "uaenorth",
                "tags": {"Project": "prj-pay", "Owner": "a.b@nda.example"},
            }
        ],
    }
    parse = az_p.parse_azure(files, 1)
    p = parse.principals[0]
    assert p.principal_type == "service_principal" and p.is_service
    assert p.project_hint == "prj-pay" and p.tags["owner"] == "a.b@nda.example"
    assert parse.grants[0].region == "uaenorth"


def test_entra_users_carry_directory_upn_and_sign_in_activity() -> None:
    oid = "aaaaaaaa-0001-4000-8000-000000000001"
    files = {
        az_p.ENTRA_USERS: {
            "value": [
                {
                    "id": oid.upper(),
                    "userPrincipalName": "A.B@nda.example",
                    "displayName": "A B",
                    "accountEnabled": False,
                    "signInActivity": {"lastSignInDateTime": "2025-09-01T00:00:00Z"},
                }
            ]
        },
        az_p.ROLE_ASSIGNMENTS: [
            _assignment(oid, "Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7", SUB, "User", "A B")
        ],
    }
    parse = az_p.parse_azure(files, 1)
    p = parse.principals[0]
    assert p.principal_ref == oid
    assert p.email is None  # the assignment named a display name, not a UPN: rule 2 territory
    assert parse.entra_users[oid]["userPrincipalName"] == "A.B@nda.example"
    assert p.enabled is False
    assert parse.activity == [RawActivity(oid, "azure", "identity", date(2025, 9, 1), 1)]


def test_activity_summary_maps_resource_providers_to_categories() -> None:
    oid = "aaaaaaaa-0001-4000-8000-000000000001"
    files = {
        az_p.ACTIVITY_SUMMARY: {
            "value": [
                {
                    "principalId": oid,
                    "resourceProvider": "microsoft.keyvault",
                    "lastOperationTime": "2025-09-03T00:00:00Z",
                    "operationCount": 4,
                },
                {"principalId": oid, "resourceProvider": "Microsoft.Storage", "lastOperationTime": "garbage"},
            ]
        }
    }
    parse = az_p.parse_azure(files, 1)
    assert parse.activity == [RawActivity(oid, "azure", "security", date(2025, 9, 3), 4)]


def test_azure_ref_categories() -> None:
    assert az_p.category_of_azure_ref(f"{SUB}/resourceGroups/rg/providers/Microsoft.Sql/servers/s") == "data"
    assert az_p.category_of_azure_ref(f"{SUB}/resourceGroups/rg") == "compute"
    assert az_p.category_of_azure_ref(SUB) == "unknown"


# ---------------------------------------------------------------- GCP


def test_member_parts() -> None:
    assert gcp_p.member_parts("user:a@nda.example") == ("user", "a@nda.example")
    assert gcp_p.member_parts("serviceAccount:x@p.iam.gserviceaccount.com") == (
        "service_account",
        "x@p.iam.gserviceaccount.com",
    )
    assert gcp_p.member_parts("group:g@nda.example") == ("group", "g@nda.example")
    assert gcp_p.member_parts("domain:nda.example") == ("group", "nda.example")
    assert gcp_p.member_parts("deleted:user:a@nda.example?uid=123") == ("user", "a@nda.example")
    assert gcp_p.member_parts("allUsers") == ("group", "allUsers")
    assert gcp_p.sa_project("x@nda-analytics-prod.iam.gserviceaccount.com") == "nda-analytics-prod"
    assert gcp_p.sa_project("a@nda.example") is None
    assert gcp_p.project_of_ref("//bigquery.googleapis.com/projects/p1/datasets/d") == "p1"


def test_custom_roles_file_resolves_an_unknown_role() -> None:
    files = {
        gcp_p.PROJECTS: [{"projectId": "p1", "labels": {"region": "me-central1"}}],
        "p1/iam-policy.json": {
            "bindings": [{"role": "projects/p1/roles/customOps", "members": ["user:a@nda.example"]}]
        },
        "p1/roles.json": [
            {
                "name": "projects/p1/roles/customOps",
                "includedPermissions": [
                    "storage.objects.get",
                    "compute.instances.setMetadata",
                    "weird.thing.frob",
                ],
            }
        ],
    }
    parse = gcp_p.parse_gcp(files, 1)
    g = parse.grants[0]
    assert set(g.pairs) == {("storage", "read"), ("compute", "admin")}
    assert g.region == "me-central1" and g.scope_ref == "projects/p1" and g.scope_level == "project"
    assert [u.raw for u in parse.unmapped] == ["weird.thing.frob"]
    assert g.source_file == "gcp/p1/iam-policy.json" and g.source_pointer == "/bindings/0/members/0"


def test_unknown_role_is_unmapped_and_project_without_label_has_no_region() -> None:
    files = {
        "p2/iam-policy.json": {
            "bindings": [{"role": "roles/vendor.thing", "members": ["user:a@nda.example"]}]
        }
    }
    parse = gcp_p.parse_gcp(files, 1)
    assert parse.grants[0].pairs == (UNKNOWN_PAIR,)
    assert parse.grants[0].region is None
    assert [u.raw for u in parse.unmapped] == ["roles/vendor.thing"]


def test_service_account_keys_skip_system_managed_and_honour_disabled() -> None:
    sa = "etl@p1.iam.gserviceaccount.com"
    files = {
        gcp_p.SA_KEYS: {
            "keys": [
                {
                    "name": f"projects/p1/serviceAccounts/{sa}/keys/aaaa",
                    "validAfterTime": "2024-01-01T00:00:00Z",
                    "keyType": "USER_MANAGED",
                },
                {
                    "name": f"projects/p1/serviceAccounts/{sa}/keys/bbbb",
                    "validAfterTime": "2025-01-01T00:00:00Z",
                    "keyType": "SYSTEM_MANAGED",
                },
                {
                    "name": f"projects/p1/serviceAccounts/{sa}/keys/cccc",
                    "validAfterTime": "2025-02-01T00:00:00Z",
                    "keyType": "USER_MANAGED",
                    "disabled": True,
                },
            ]
        }
    }
    parse = gcp_p.parse_gcp(files, 1)
    assert [(c.credential_ref, c.active, c.created_at) for c in parse.credentials] == [
        ("gcp:sa_key:aaaa", True, date(2024, 1, 1)),
        ("gcp:sa_key:cccc", False, date(2025, 2, 1)),
    ]
    p = parse.principals[0]
    assert p.principal_ref == f"serviceAccount:{sa}" and p.is_service and p.project_hint == "p1"


def test_activity_per_binding_fans_out_to_the_role_categories() -> None:
    files = {
        gcp_p.ACTIVITY: [
            {
                "project": "p1",
                "member": "user:a@nda.example",
                "role": "roles/bigquery.dataViewer",
                "lastAuthenticatedTime": "2025-09-05T00:00:00Z",
                "usedPermissionsCount": 3,
            },
            {
                "project": "p1",
                "member": "user:a@nda.example",
                "role": "roles/owner",
                "lastAuthenticatedTime": None,
            },
        ]
    }
    parse = gcp_p.parse_gcp(files, 1)
    assert parse.activity == [RawActivity("user:a@nda.example", "gcp", "data", date(2025, 9, 5), 3)]


def test_service_account_owner_label_is_evidence_for_the_linker() -> None:
    files = {
        gcp_p.PROJECTS: [{"projectId": "p1", "labels": {"owner": "a.b@nda.example"}}],
        "p1/iam-policy.json": {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["serviceAccount:sa@p1.iam.gserviceaccount.com", "user:x@nda.example"],
                }
            ]
        },
    }
    parse = gcp_p.parse_gcp(files, 1)
    by_ref = {p.principal_ref: p for p in parse.principals}
    assert by_ref["serviceAccount:sa@p1.iam.gserviceaccount.com"].tags == {"owner": "a.b@nda.example"}
    assert by_ref["user:x@nda.example"].tags == {}


def test_gcp_ref_categories() -> None:
    assert gcp_p.category_of_gcp_ref("//storage.googleapis.com/projects/_/buckets/b") == "storage"
    assert gcp_p.category_of_gcp_ref("//bigquery.googleapis.com/projects/p/datasets/d") == "data"
    assert gcp_p.category_of_gcp_ref("projects/p/topics/t") == "data"
    assert gcp_p.category_of_gcp_ref("projects/p") == "unknown"


# ---------------------------------------------------------------- HR


def test_parse_employees_skips_comment_dedups_and_defaults() -> None:
    text = (
        "# SYNTHETIC\n"
        "employee_id,email,display_name,department,title,employment_type,status,start_date,end_date,contract_end,manager_id,extra_col\n"
        "e1,A.B@nda.example,A B,Finance,Lead,staff,active,2025-09-01,,,m1,hello\n"
        "e1,a.b@nda.example,A B (again),Finance,Lead,,,NaN,,,,\n"
        ",,nobody,,,,,,,,\n"
        "s1,svc-x@nda.example,svc-x,Data Services,ETL,service,active,,,,\n"
    )
    warnings: list[str] = []
    rows = hr_p.parse_employees(text, warnings)
    assert [r.employee_id for r in rows] == ["e1", "s1"]
    e1 = rows[0]
    assert e1.display_name == "A B (again)" and e1.email == "a.b@nda.example"
    assert e1.employment_type == "staff" and e1.status == "active" and e1.start_date is None
    assert e1.row_number == 2 and e1.extra == {}
    assert rows[1].is_service and rows[1].local_part == "svc-x"
    assert any("duplicate employee_id e1" in w for w in warnings)


def test_parse_projects_and_exceptions() -> None:
    projects = hr_p.parse_projects(
        "project_id,name,department,status,retired_month,cloud,project_ref\np1,P One,Finance,Retired,3.0,GCP,ref-1\np2,,,,,,\n"
    )
    assert [(p.project_id, p.status, p.retired_month, p.cloud, p.project_ref, p.name) for p in projects] == [
        ("p1", "retired", 3, "gcp", "ref-1", "P One"),
        ("p2", "active", None, "", "p2", "p2"),
    ]
    text = (
        "identity_id,exception_type,approved_by,approved_on,review_date,expires_on,justification\n"
        "e1,break-glass,ciso@nda.example,2025-09-01,2026-03-01,,why\n"
        "e1,break-glass,ciso@nda.example,2025-09-01,2026-03-01,,why again\n"
        ",dr-failover,x,,,,\n"
    )
    exceptions = hr_p.parse_exceptions(text)
    assert len(exceptions) == 1
    e = exceptions[0]
    assert e.identity_id == "e1" and e.review_date == date(2026, 3, 1) and e.expires_on is None
    assert e.source == "register" and len(e.exception_id) == 32
    assert hr_p.parse_exceptions(text)[0].exception_id == e.exception_id  # deterministic


def test_hr_bundle_indexes() -> None:
    bundle = hr_p.parse_hr(
        {
            "employees.csv": "employee_id,email,display_name,department,employment_type,status\ne1,A@nda.example,A,Finance,staff,active\ns1,,svc-etl,Data Services,service,active\n",
            "projects.csv": "project_id,name,department,status,cloud,project_ref\np1,Analytics,Data Services,active,gcp,nda-analytics-prod\n",
        }
    )
    assert bundle.employee_for_email("a@NDA.example").employee_id == "e1"
    assert bundle.employee_for_local_part("A").employee_id == "e1"
    assert bundle.service_employee_named("etl").employee_id == "s1"
    assert bundle.service_employee_named("SVC-ETL").employee_id == "s1"
    assert bundle.project_for("NDA-Analytics-Prod").project_id == "p1"
    assert bundle.project_for("Analytics").project_id == "p1"
    assert bundle.project_for(None) is None and bundle.employee_for_email(None) is None
