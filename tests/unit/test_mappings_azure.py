"""Every entry of mappings/azure.yaml is exercised (SPEC §5.3): data-driven from the YAML itself."""

from __future__ import annotations

import pytest
from athar.normaliser.expand import expand_action
from athar.normaliser.mappings import category_for_service, raw_entries, resolve_maps, role_pairs, scope_level

CLOUD = "azure"
ACTIONS = raw_entries(CLOUD, "actions")
ROLES = raw_entries(CLOUD, "roles")
SUB = "/subscriptions/11111111-1111-4111-8111-111111111111"

REQUIRED_ROLES = (
    "Owner",
    "Contributor",
    "Reader",
    "User Access Administrator",
    "Storage Blob Data Contributor",
    "Storage Blob Data Reader",
    "Virtual Machine Contributor",
    "SQL DB Contributor",
    "Key Vault Administrator",
    "Security Reader",
    "Billing Reader",
    "Network Contributor",
    "Monitoring Reader",
    "Managed Identity Operator",
)
SPEC_GUIDS = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
}


def _expected(entry: dict) -> set[tuple[str, str]]:
    return set(resolve_maps(entry.get("expect") or entry["maps"]))


@pytest.mark.parametrize("entry", ACTIONS, ids=[e["action"] for e in ACTIONS])
def test_action_entry_maps_as_declared(entry: dict) -> None:
    got = expand_action(CLOUD, entry["action"])
    assert set(got) == _expected(entry)
    assert got == sorted(set(got))
    assert ("unknown", "unknown") not in got


@pytest.mark.parametrize("entry", ROLES, ids=[e["name"] for e in ROLES])
def test_role_entry_maps_by_name_and_guid(entry: dict) -> None:
    assert role_pairs(CLOUD, entry["name"]) == frozenset(_expected(entry))
    assert role_pairs(CLOUD, entry["id"]) == frozenset(_expected(entry))
    assert role_pairs(CLOUD, entry["id"].upper()) == frozenset(_expected(entry))


@pytest.mark.parametrize("name", REQUIRED_ROLES)
def test_spec_required_roles_are_present(name: str) -> None:
    assert role_pairs(CLOUD, name)


@pytest.mark.parametrize(("name", "guid"), sorted(SPEC_GUIDS.items()))
def test_spec_4_6_guids_resolve_to_the_named_role(name: str, guid: str) -> None:
    assert role_pairs(CLOUD, guid) == role_pairs(CLOUD, name)


def test_spec_5_3_identity_semantics() -> None:
    assert expand_action(CLOUD, "Microsoft.Authorization/roleAssignments/write") == [("identity", "grant")]
    assert expand_action(CLOUD, "Microsoft.Authorization/roleDefinitions/write") == [("identity", "write")]
    assert expand_action(CLOUD, "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action") == [
        ("identity", "impersonate")
    ]
    assert role_pairs(CLOUD, "Owner") >= {
        (c, "admin") for c in ("compute", "storage", "network", "identity", "data", "security", "billing")
    }
    assert ("identity", "grant") in role_pairs(CLOUD, "Owner")
    assert ("identity", "grant") in role_pairs(CLOUD, "User Access Administrator")
    assert ("identity", "admin") not in role_pairs(CLOUD, "Contributor")


def test_unlisted_actions_use_the_last_segment_and_the_provider_namespace() -> None:
    assert expand_action(CLOUD, "Microsoft.Compute/availabilitySets/read") == [("compute", "read")]
    assert expand_action(CLOUD, "Microsoft.Network/loadBalancers/write") == [("network", "write")]
    assert expand_action(CLOUD, "Microsoft.Sql/servers/delete") == [("data", "delete")]
    assert expand_action(CLOUD, "Microsoft.KeyVault/vaults/secrets/purge/action") == [("security", "write")]
    assert expand_action(CLOUD, "microsoft.storage/storageaccounts/read") == [("storage", "read")]
    assert expand_action(CLOUD, "Microsoft.Unknown/things/read") == [("unknown", "unknown")]
    assert expand_action(CLOUD, "*") == expand_action("aws", "*")
    assert set(expand_action(CLOUD, "*/write")) == {
        (c, "write") for c in ("compute", "storage", "network", "data", "security")
    } | {("identity", "write"), ("billing", "write")}


def test_activity_log_resource_providers_map_to_categories() -> None:
    assert category_for_service(CLOUD, "Microsoft.Storage") == "storage"
    assert category_for_service(CLOUD, "microsoft.compute") == "compute"
    assert category_for_service(CLOUD, "Microsoft.Authorization") == "identity"
    assert category_for_service(CLOUD, "Microsoft.Consumption") == "billing"
    assert category_for_service(CLOUD, "Microsoft.Nope") is None


@pytest.mark.parametrize(
    ("ref", "level"),
    [
        ("/", "global"),
        ("/providers/Microsoft.Management/managementGroups/nda-root", "org"),
        (SUB, "project"),
        (SUB + "/", "project"),
        (SUB + "/resourceGroups/rg-x", "resource"),
        (SUB + "/resourceGroups/rg-x/providers/Microsoft.Storage/storageAccounts/a", "resource"),
        (SUB + "/providers/Microsoft.Network/x", "resource"),
    ],
)
def test_scope_levels(ref: str, level: str) -> None:
    assert scope_level(CLOUD, ref) == level
