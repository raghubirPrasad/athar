"""Every entry of mappings/gcp.yaml is exercised (SPEC §5.3): data-driven from the YAML itself."""

from __future__ import annotations

import pytest
from athar.normaliser.expand import expand_action
from athar.normaliser.mappings import category_for_service, raw_entries, resolve_maps, role_pairs, scope_level

CLOUD = "gcp"
PERMISSIONS = raw_entries(CLOUD, "permissions")
ROLES = raw_entries(CLOUD, "roles")

REQUIRED_ROLES = (
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.roleAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/storage.admin",
    "roles/storage.objectViewer",
    "roles/storage.objectAdmin",
    "roles/bigquery.admin",
    "roles/bigquery.dataViewer",
    "roles/bigquery.dataEditor",
    "roles/compute.admin",
    "roles/compute.viewer",
    "roles/billing.admin",
    "roles/billing.viewer",
    "roles/logging.viewer",
    "roles/cloudsql.admin",
    "roles/pubsub.editor",
)


def _expected(entry: dict) -> set[tuple[str, str]]:
    return set(resolve_maps(entry.get("expect") or entry["maps"]))


@pytest.mark.parametrize("entry", PERMISSIONS, ids=[e["permission"] for e in PERMISSIONS])
def test_permission_entry_maps_as_declared(entry: dict) -> None:
    got = expand_action(CLOUD, entry["permission"])
    assert set(got) == _expected(entry)
    assert got == sorted(set(got))
    assert ("unknown", "unknown") not in got


@pytest.mark.parametrize("entry", ROLES, ids=[e["role"] for e in ROLES])
def test_role_entry_maps_as_declared(entry: dict) -> None:
    assert role_pairs(CLOUD, entry["role"]) == frozenset(_expected(entry))
    assert set(expand_action(CLOUD, entry["role"])) == _expected(entry)
    assert role_pairs(CLOUD, entry["role"].upper()) == frozenset(_expected(entry))


@pytest.mark.parametrize("role", REQUIRED_ROLES)
def test_spec_required_roles_are_present(role: str) -> None:
    assert role_pairs(CLOUD, role)


def test_spec_5_3_identity_semantics() -> None:
    assert role_pairs(CLOUD, "roles/owner") >= {
        (c, "admin") for c in ("compute", "storage", "network", "identity", "data", "security", "billing")
    }
    editor = role_pairs(CLOUD, "roles/editor")
    assert {("storage", "write"), ("storage", "delete"), ("compute", "write"), ("data", "delete")} <= editor
    assert not any(v == "admin" for _, v in editor)
    for role in ("roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin"):
        assert ("identity", "write") in role_pairs(CLOUD, role), role
    for role in ("roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin"):
        assert ("identity", "grant") in role_pairs(CLOUD, role), role
    assert expand_action(CLOUD, "resourcemanager.projects.setIamPolicy") == [("identity", "grant")]
    for role in (
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountKeyAdmin",
    ):
        assert ("identity", "impersonate") in role_pairs(CLOUD, role), role


def test_unlisted_permissions_and_roles() -> None:
    assert expand_action(CLOUD, "storage.buckets.get") == [("storage", "read")]
    assert expand_action(CLOUD, "compute.instances.start") == [("compute", "write")]
    assert expand_action(CLOUD, "bigquery.datasets.delete") == [("data", "delete")]
    assert expand_action(CLOUD, "iam.serviceAccounts.setIamPolicy") == [("identity", "grant")]
    assert expand_action(CLOUD, "iam.serviceAccounts.frob") == [("identity", "unknown")]
    assert expand_action(CLOUD, "storage.*") == [
        ("storage", "admin"),
        ("storage", "delete"),
        ("storage", "read"),
        ("storage", "write"),
    ]
    assert expand_action(CLOUD, "roles/storage.somethingNew") == [
        ("storage", "unknown")
    ]  # category from prefix
    assert expand_action(CLOUD, "roles/nonsense") == [("unknown", "unknown")]
    assert expand_action(CLOUD, "nonsense") == [("unknown", "unknown")]
    assert category_for_service(CLOUD, "bigquery") == "data"


@pytest.mark.parametrize(
    ("ref", "level"),
    [
        ("*", "global"),
        ("organizations/123", "org"),
        ("folders/456", "org"),
        ("projects/nda-analytics-prod", "project"),
        ("projects/nda-analytics-prod/", "project"),
        ("projects/nda-analytics-prod/datasets/x", "resource"),
        ("//storage.googleapis.com/projects/_/buckets/b", "resource"),
    ],
)
def test_scope_levels(ref: str, level: str) -> None:
    assert scope_level(CLOUD, ref) == level
