"""Every entry of mappings/aws.yaml is exercised (SPEC §5.3): data-driven from the YAML itself."""

from __future__ import annotations

import pytest
from athar.normaliser.expand import expand_action
from athar.normaliser.mappings import (
    category_for_service,
    load_mapping,
    raw_entries,
    resolve_maps,
    role_default_scope,
    role_pairs,
    scope_level,
)

CLOUD = "aws"
ACTIONS = raw_entries(CLOUD, "actions")
POLICIES = raw_entries(CLOUD, "managed_policies")

REQUIRED_POLICIES = (
    "AdministratorAccess",
    "PowerUserAccess",
    "ReadOnlyAccess",
    "IAMFullAccess",
    "AmazonS3FullAccess",
    "AmazonS3ReadOnlyAccess",
    "AmazonEC2FullAccess",
    "AmazonRDSFullAccess",
    "AWSBillingReadOnlyAccess",
    "SecurityAudit",
    "AmazonDynamoDBFullAccess",
    "CloudWatchReadOnlyAccess",
)
REQUIRED_SERVICES = (
    "s3",
    "ec2",
    "rds",
    "dynamodb",
    "iam",
    "sts",
    "kms",
    "lambda",
    "cloudwatch",
    "logs",
    "aws-portal",
    "billing",
    "ce",
    "organizations",
    "secretsmanager",
    "vpc",
)


def _expected(entry: dict) -> set[tuple[str, str]]:
    return set(resolve_maps(entry.get("expect") or entry["maps"]))


@pytest.mark.parametrize("entry", ACTIONS, ids=[e["action"] for e in ACTIONS])
def test_action_entry_maps_as_declared(entry: dict) -> None:
    got = expand_action(CLOUD, entry["action"])
    assert set(got) == _expected(entry)
    assert got == sorted(set(got))
    assert ("unknown", "unknown") not in got


@pytest.mark.parametrize("entry", POLICIES, ids=[e["name"] for e in POLICIES])
def test_managed_policy_entry_maps_by_name_and_arn(entry: dict) -> None:
    assert role_pairs(CLOUD, entry["name"]) == frozenset(_expected(entry))
    assert role_pairs(CLOUD, entry["arn"]) == frozenset(_expected(entry))
    assert role_pairs(CLOUD, entry["name"].lower()) == frozenset(_expected(entry))
    assert role_default_scope(CLOUD, entry["name"]) == "global"


@pytest.mark.parametrize("name", REQUIRED_POLICIES)
def test_spec_required_managed_policies_are_present(name: str) -> None:
    assert role_pairs(CLOUD, name)


@pytest.mark.parametrize("service", REQUIRED_SERVICES)
def test_spec_required_service_prefixes_are_mapped(service: str) -> None:
    assert category_for_service(CLOUD, service) is not None


def test_spec_5_3_identity_semantics() -> None:
    assert role_pairs(CLOUD, "AdministratorAccess") >= {
        (c, "admin") for c in ("compute", "storage", "network", "identity", "data", "security", "billing")
    }
    assert set(expand_action(CLOUD, "iam:*")) == {
        ("identity", "admin"),
        ("identity", "grant"),
        ("identity", "impersonate"),
    }
    for a in ("iam:CreateRole", "iam:CreateUser", "iam:CreatePolicy", "iam:CreateServiceLinkedRole"):
        assert expand_action(CLOUD, a) == [("identity", "write")], a
    for a in (
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
    ):
        assert expand_action(CLOUD, a) == [("identity", "grant")], a
    for a in ("iam:PassRole", "sts:AssumeRole"):
        assert expand_action(CLOUD, a) == [("identity", "impersonate")], a
    assert ("identity", "admin") not in role_pairs(CLOUD, "PowerUserAccess")


def test_unlisted_actions_infer_the_verb_from_the_leading_word() -> None:
    assert expand_action(CLOUD, "s3:GetBucketTagging") == [("storage", "read")]
    assert expand_action(CLOUD, "rds:ModifyDBParameterGroup") == [("data", "write")]
    assert expand_action(CLOUD, "ec2:TerminateClientVpnConnections") == [("compute", "delete")]
    assert expand_action(CLOUD, "dynamodb:BatchGetItem") == [("data", "read")]
    assert expand_action(CLOUD, "s3:Frobnicate") == [("storage", "unknown")]  # known service, unknown verb
    assert expand_action(CLOUD, "s3:Get*") == [("storage", "read")]
    assert expand_action(CLOUD, "kms:Re*") == [("security", "write")]  # glob union of listed actions
    assert expand_action(CLOUD, "S3:GETOBJECT") == expand_action(CLOUD, "s3:GetObject")


@pytest.mark.parametrize(
    ("ref", "level"),
    [
        ("*", "global"),
        ("arn:aws:organizations::123456789012:organization/o-x", "org"),
        ("123456789012", "project"),
        ("arn:aws:iam::123456789012:root", "project"),
        ("arn:aws:s3:::bucket/*", "resource"),
        ("arn:aws:iam::123456789012:role/x", "resource"),
        ("something-else", "resource"),
    ],
)
def test_scope_levels(ref: str, level: str) -> None:
    assert scope_level(CLOUD, ref) == level


def test_mapping_loads_once_and_is_consistent() -> None:
    m = load_mapping(CLOUD)
    assert m.cloud == CLOUD
    assert set(m.services.values()) <= {
        "compute",
        "storage",
        "network",
        "identity",
        "data",
        "security",
        "billing",
    }
    assert len(m.actions) + len(m.action_globs) == len(ACTIONS)
    assert all(key == key.lower() for key in m.actions)
