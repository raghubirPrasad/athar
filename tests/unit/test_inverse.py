"""Inverse templates (SPEC §11.5): provider-native before/after JSON from retained raw snippets."""

from __future__ import annotations

import json

import pytest
from athar.normaliser.inverse import PolicyDiff, policy_diff
from tests.factories import credential, grant, identity

ACCOUNT = "123456789012"
OMAR = f"arn:aws:iam::{ACCOUNT}:user/omar.haddad"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/etl-runner"
SUB = "/subscriptions/11111111-1111-4111-8111-111111111111"
OID = "aaaaaaaa-0005-4000-8000-000000000005"
RA_ID = f"{SUB}/providers/Microsoft.Authorization/roleAssignments/bbbbbbbb-0004-4000-8000-000000000004"

IDENTITY = identity("emp-0002", display_name="Omar Haddad")


def _managed(gid: str = "g-managed") -> object:
    return grant(
        gid,
        "emp-0002",
        OMAR,
        service_category="compute",
        verb="admin",
        scope_level="global",
        scope_ref="*",
        granted_via="managed_policy:AdministratorAccess",
        raw_snippet={
            "raw_action": "AdministratorAccess",
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "UserName": "omar.haddad",
        },
        source_pointer="/UserDetailList/1/AttachedManagedPolicies/0",
    )


def _inline(gid: str = "g-inline") -> object:
    stmt = {"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::nda-citizen-data/*"}
    return grant(
        gid,
        "emp-0002",
        OMAR,
        verb="write",
        scope_ref="arn:aws:s3:::nda-citizen-data/*",
        granted_via="direct",
        raw_snippet={
            "raw_action": ["s3:*"],
            "PolicyName": "batch-data-access",
            "Statement": stmt,
            "UserName": "omar.haddad",
        },
    )


def _azure(gid: str = "g-az") -> object:
    snippet = {
        "raw_action": "Owner",
        "id": RA_ID,
        "name": "bbbbbbbb-0004-4000-8000-000000000004",
        "principalId": OID,
        "principalType": "User",
        "roleDefinitionName": "Owner",
        "scope": SUB,
    }
    return grant(
        gid,
        "emp-0002",
        OID,
        cloud="azure",
        verb="admin",
        scope_level="project",
        scope_ref=SUB,
        granted_via="role:Owner",
        raw_snippet=snippet,
        source_file="azure/role-assignments.json",
        source_pointer="/3",
    )


def _gcp(gid: str = "g-gcp", member: str = "user:omar.haddad@nda.example") -> object:
    binding = {"role": "roles/owner", "members": ["user:fatima.saeed@nda.example", member]}
    return grant(
        gid,
        "emp-0002",
        member,
        cloud="gcp",
        verb="admin",
        scope_level="project",
        scope_ref="projects/nda-sandbox",
        granted_via="role:roles/owner",
        raw_snippet={
            "raw_action": "roles/owner",
            "project": "nda-sandbox",
            "role": "roles/owner",
            "member": member,
            "binding": binding,
        },
        source_file="gcp/nda-sandbox/iam-policy.json",
        source_pointer="/bindings/0/members/1",
    )


def _ops(diff: PolicyDiff) -> list[tuple[str, str]]:
    return [(o["op"], o["target"]) for o in diff.operations]


def test_detach_aws_managed_policy() -> None:
    g = _managed()
    diff = policy_diff("revoke_grant", IDENTITY, [g], [g])
    assert diff.cloud == "aws"
    assert _ops(diff) == [("detach_managed_policy", OMAR)]
    op = diff.operations[0]
    assert (
        op["cli"]
        == "aws iam detach-user-policy --user-name omar.haddad --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
    )
    holder_before = diff.before["aws"]["principals"][0]
    holder_after = diff.after["aws"]["principals"][0]
    assert holder_before["UserName"] == "omar.haddad" and holder_before["Arn"] == OMAR
    assert holder_before["AttachedManagedPolicies"] == [
        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    ]
    assert holder_after["AttachedManagedPolicies"] == []
    assert "1× detach managed policy" in diff.summary and "emp-0002" in diff.summary


def test_remove_aws_inline_statement() -> None:
    g = _inline()
    diff = policy_diff("downgrade_to_least_privilege", IDENTITY, [g, _managed()], [g])
    assert _ops(diff) == [("remove_inline_statement", OMAR)]
    assert (
        diff.operations[0]["cli"]
        == "aws iam delete-user-policy --user-name omar.haddad --policy-name batch-data-access"
    )
    before = diff.before["aws"]["principals"][0]["UserPolicyList"][0]
    after = diff.after["aws"]["principals"][0]["UserPolicyList"][0]
    assert before["PolicyName"] == "batch-data-access"
    assert before["PolicyDocument"]["Statement"] == [g.raw_snippet["Statement"]]
    assert after["PolicyDocument"]["Statement"] == []
    assert (
        "AttachedManagedPolicies" not in diff.before["aws"]["principals"][0]
    )  # the kept policy is untouched


def test_remove_aws_user_from_group_and_role_policy() -> None:
    grp = grant(
        "g-grp",
        "emp-0002",
        OMAR,
        granted_via="group:finance-readers",
        raw_snippet={
            "raw_action": "ReadOnlyAccess",
            "PolicyName": "ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "UserName": "omar.haddad",
            "GroupName": "finance-readers",
        },
    )
    role = grant(
        "g-role",
        "svc:prj-legacy:etl-runner",
        ROLE,
        granted_via="managed_policy:AmazonS3FullAccess",
        raw_snippet={
            "raw_action": "AmazonS3FullAccess",
            "PolicyName": "AmazonS3FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "RoleName": "etl-runner",
        },
    )
    diff = policy_diff("revoke_grant", IDENTITY, [grp, role], [grp, role])
    assert _ops(diff) == [("detach_managed_policy", ROLE), ("remove_user_from_group", OMAR)]
    assert (
        diff.operations[0]["cli"]
        == "aws iam detach-role-policy --role-name etl-runner --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess"
    )
    assert (
        diff.operations[1]["cli"]
        == "aws iam remove-user-from-group --user-name omar.haddad --group-name finance-readers"
    )
    holders = {h.get("UserName") or h.get("RoleName"): h for h in diff.before["aws"]["principals"]}
    assert holders["omar.haddad"]["GroupList"] == ["finance-readers"]
    assert holders["etl-runner"]["AttachedManagedPolicies"][0]["PolicyName"] == "AmazonS3FullAccess"


def test_remove_aws_trust_principal() -> None:
    trust = grant(
        "g-trust",
        "svc:prj-legacy:svc-batch",
        f"arn:aws:iam::{ACCOUNT}:user/svc-batch",
        service_category="identity",
        verb="impersonate",
        scope_ref=ROLE,
        granted_via="direct",
        raw_snippet={
            "raw_action": "sts:AssumeRole",
            "RoleArn": ROLE,
            "AssumeRolePolicyDocument": {"Statement": []},
        },
    )
    diff = policy_diff("revoke_grant", IDENTITY, [trust], [trust])
    assert _ops(diff) == [("remove_trust_principal", ROLE)]
    assert "update-assume-role-policy --role-name etl-runner" in diff.operations[0]["cli"]


def test_delete_azure_role_assignment() -> None:
    g = _azure()
    twin = _azure("g-az-2")  # a second verb from the same assignment → one operation
    diff = policy_diff("revoke_grant", IDENTITY, [g, twin], [g, twin])
    assert diff.cloud == "azure"
    assert _ops(diff) == [("delete_role_assignment", RA_ID)]
    assert diff.operations[0]["cli"] == f"az role assignment delete --ids {RA_ID}"
    assert diff.operations[0]["detail"] == {"principalId": OID, "role": "Owner", "scope": SUB}
    assert diff.before["azure"]["roleAssignments"] == [
        {k: v for k, v in g.raw_snippet.items() if k != "raw_action"}
    ]
    assert diff.after["azure"]["roleAssignments"] == []


def test_remove_gcp_binding_member() -> None:
    g = _gcp()
    diff = policy_diff("revoke_grant", IDENTITY, [g], [g])
    assert diff.cloud == "gcp"
    assert _ops(diff) == [("remove_binding_member", "projects/nda-sandbox")]
    assert (
        diff.operations[0]["cli"]
        == "gcloud projects remove-iam-policy-binding nda-sandbox --member=user:omar.haddad@nda.example --role=roles/owner"
    )
    assert diff.before["gcp"]["bindings"] == [
        {
            "project": "nda-sandbox",
            "role": "roles/owner",
            "members": ["user:fatima.saeed@nda.example", "user:omar.haddad@nda.example"],
        }
    ]
    assert diff.after["gcp"]["bindings"] == [
        {"project": "nda-sandbox", "role": "roles/owner", "members": ["user:fatima.saeed@nda.example"]}
    ]


def test_deactivate_aws_key_and_gcp_sa_key() -> None:
    creds = [
        credential("aws:key:AKIAEXAMPLE0001", "emp-0002"),
        credential("gcp:sa_key:abcdef", "emp-0002", cloud="gcp", kind="sa_key"),
        credential("aws:key:AKIAINACTIVE", "emp-0002", active=False),
    ]
    diff = policy_diff("rotate_or_disable_credential", IDENTITY, [_managed()], [], creds)
    assert _ops(diff) == [
        ("deactivate_access_key", "aws:key:AKIAEXAMPLE0001"),
        ("disable_service_account_key", "gcp:sa_key:abcdef"),
    ]
    assert (
        diff.operations[0]["cli"]
        == "aws iam update-access-key --access-key-id AKIAEXAMPLE0001 --status Inactive"
    )
    assert diff.operations[1]["cli"] == "gcloud iam service-accounts keys disable abcdef"
    assert diff.before["aws"]["AccessKeys"] == [{"AccessKeyId": "AKIAEXAMPLE0001", "Status": "Active"}]
    assert diff.after["aws"]["AccessKeys"] == [{"AccessKeyId": "AKIAEXAMPLE0001", "Status": "Inactive"}]
    assert diff.before["gcp"]["serviceAccountKeys"] == [{"keyId": "abcdef", "disabled": False}]
    assert diff.after["gcp"]["serviceAccountKeys"] == [{"keyId": "abcdef", "disabled": True}]
    assert diff.cloud == "multi"
    assert not diff.before.get("aws", {}).get("principals")  # no grant was dropped


def test_disable_identity_across_clouds() -> None:
    sa = _gcp("g-sa", "serviceAccount:etl@nda-analytics-prod.iam.gserviceaccount.com")
    grants = [_managed(), _azure(), _gcp(), sa]
    diff = policy_diff(
        "disable_identity",
        IDENTITY,
        grants,
        [],
        [credential("aws:password:omar.haddad", "emp-0002", kind="password")],
    )
    assert _ops(diff) == [
        ("disable_console_login", OMAR),
        ("disable_entra_user", OID),
        ("disable_service_account", "serviceAccount:etl@nda-analytics-prod.iam.gserviceaccount.com"),
    ]
    assert diff.operations[0]["cli"] == "aws iam delete-login-profile --user-name omar.haddad"
    assert diff.operations[1]["cli"] == f"az ad user update --id {OID} --account-enabled false"
    assert (
        diff.operations[2]["cli"]
        == "gcloud iam service-accounts disable etl@nda-analytics-prod.iam.gserviceaccount.com"
    )
    assert diff.before["azure"]["users"] == [{"id": OID, "accountEnabled": True}]
    assert diff.after["azure"]["users"] == [{"id": OID, "accountEnabled": False}]
    assert diff.before["aws"]["LoginProfiles"] == [{"UserName": "omar.haddad", "PasswordEnabled": True}]
    assert diff.after["aws"]["LoginProfiles"][0]["PasswordEnabled"] is False
    assert "principals" not in diff.before["aws"]  # grants stay; the identity is disabled


def test_remove_cloud_access_drops_grants_credentials_and_login_for_the_touched_cloud() -> None:
    aws_grant = _managed()
    creds = [
        credential("aws:key:AKIA1", "emp-0002"),
        credential("gcp:sa_key:k", "emp-0002", cloud="gcp", kind="sa_key"),
    ]
    diff = policy_diff("remove_cloud_access", IDENTITY, [aws_grant, _azure()], [aws_grant], creds)
    ops = {o["op"] for o in diff.operations}
    assert ops == {"detach_managed_policy", "deactivate_access_key", "disable_console_login"}
    assert diff.cloud == "aws"  # Azure untouched: only the dropped grants' cloud is affected


def test_drop_outside_the_identity_grants_is_ignored() -> None:
    other = grant(
        "g-other",
        "emp-0009",
        f"arn:aws:iam::{ACCOUNT}:user/khalid",
        granted_via="managed_policy:ReadOnlyAccess",
        raw_snippet={"PolicyName": "ReadOnlyAccess", "PolicyArn": "x"},
    )
    diff = policy_diff("revoke_grant", IDENTITY, [_managed()], [other])
    assert diff.operations == [] and diff.cloud == "none"
    assert diff.summary.endswith("no provider change required")


@pytest.mark.parametrize("action", ["no_action_recommended", "tag_as_exception"])
def test_non_changing_actions_produce_no_operations(action: str) -> None:
    diff = policy_diff(action, IDENTITY, [_managed()], [_managed()], [credential()])
    assert diff.operations == [] and diff.before == {} and diff.after == {}


def test_deterministic_and_order_independent() -> None:
    grants = [_managed(), _inline(), _azure(), _gcp()]
    creds = [credential("aws:key:AKIA1", "emp-0002")]
    a = policy_diff("remove_cloud_access", IDENTITY, grants, grants, creds).as_dict()
    b = policy_diff(
        "remove_cloud_access", IDENTITY, list(reversed(grants)), list(reversed(grants)), creds
    ).as_dict()
    assert a == b
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["cloud"] == "multi"
    assert [o["cloud"] for o in a["operations"]] == sorted(o["cloud"] for o in a["operations"])


def test_as_dict_shape_matches_the_api_contract() -> None:
    diff = policy_diff("revoke_grant", IDENTITY, [_managed()], [_managed()])
    d = diff.as_dict()
    assert set(d) == {"cloud", "before", "after", "operations", "summary"}
    for op in d["operations"]:
        assert set(op) == {"op", "cloud", "target", "detail", "cli"}
        assert isinstance(op["detail"], dict)
    json.dumps(d)  # JSON-serialisable for the remediation_plans.policy_diff column
