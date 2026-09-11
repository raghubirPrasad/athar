"""The files on disk are the real provider export shapes (SPEC §4.6).

Judges open the raw JSON, so this test reads it the way they would: required keys per file, real
built-in role GUIDs, well-formed ARNs and member strings, the exact credential-report columns, the
`# SYNTHETIC` marker on the HR feed, and `nda.example` as the only email domain anywhere in the
tree (never `gov.ae` or any real one).
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from athar.clock import month_end
from athar.generator import catalogue as cat
from athar.generator.writers.aws import CREDENTIAL_REPORT_COLUMNS
from athar.generator.writers.hr import EMPLOYEE_COLUMNS, EXCEPTION_COLUMNS, PROJECT_COLUMNS

from tests.generator.conftest import SMALL_MONTHS

ARN_USER = re.compile(r"^arn:aws:iam::\d{12}:user/[A-Za-z0-9+=,.@_-]+$")
ARN_ROLE = re.compile(r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]+$")
ARN_GROUP = re.compile(r"^arn:aws:iam::\d{12}:group/[A-Za-z0-9+=,.@_-]+$")
ARN_POLICY = re.compile(r"^arn:aws:iam::(aws|\d{12}):policy/[A-Za-z0-9+=,.@_/-]+$")
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SA_EMAIL = re.compile(r"^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$")

ALLOWED_DOMAIN = "nda.example"
FORBIDDEN = ("gov.ae", "gmail.com", "outlook.com", "example.com", "microsoft.com", "amazonaws.com/user")

BUILT_IN_GUIDS = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
}


@pytest.fixture(scope="module")
def month_dir(small_estate: Path) -> Path:
    return small_estate / f"month-{SMALL_MONTHS:02d}"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    return list(reader.fieldnames or []), list(reader)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


def test_every_month_has_the_four_provider_directories(small_estate: Path) -> None:
    for month in range(1, SMALL_MONTHS + 1):
        month_dir = small_estate / f"month-{month:02d}"
        for provider in ("aws", "azure", "gcp", "hr"):
            assert (month_dir / provider).is_dir(), month_dir
    assert (small_estate / "events.jsonl").is_file()
    assert (small_estate / "ground_truth.json").is_file()
    assert (small_estate / "manifest.json").is_file()


def test_every_json_file_parses(small_estate: Path) -> None:
    files = [p for p in small_estate.rglob("*.json")]
    assert files
    for path in files:
        load_json(path)


def test_events_are_one_json_object_per_line(small_estate: Path) -> None:
    lines = (small_estate / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert lines
    for line in lines:
        event = json.loads(line)
        assert set(event) >= {
            "event_id",
            "month",
            "kind",
            "identity_id",
            "cloud",
            "grants_added",
            "grants_removed",
            "trigger",
            "note",
        }
        assert 1 <= event["month"] <= SMALL_MONTHS


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


def test_authorization_details_has_the_four_top_level_lists(month_dir: Path) -> None:
    details = load_json(month_dir / "aws" / "authorization-details.json")
    assert set(details) == {"UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"}
    assert details["UserDetailList"] and details["GroupDetailList"] and details["RoleDetailList"]


def test_users_carry_arns_ids_policies_and_tags(month_dir: Path) -> None:
    details = load_json(month_dir / "aws" / "authorization-details.json")
    for user in details["UserDetailList"]:
        assert ARN_USER.match(user["Arn"]), user["Arn"]
        assert user["UserId"].startswith("AIDA")
        assert ISO_TS.match(user["CreateDate"])
        assert user["Arn"].endswith(f"/{user['UserName']}")
        assert {t["Key"] for t in user["Tags"]} >= {"department"}
        for policy in user["UserPolicyList"]:
            document = policy["PolicyDocument"]
            assert document["Version"] == "2012-10-17"
            for statement in document["Statement"]:
                assert statement["Effect"] in ("Allow", "Deny")
                assert statement["Action"] and statement["Resource"]
        for attached in user["AttachedManagedPolicies"]:
            assert ARN_POLICY.match(attached["PolicyArn"]), attached
            assert attached["PolicyArn"].endswith(attached["PolicyName"])


def test_wildcards_reach_the_native_policy_documents(month_dir: Path) -> None:
    """`s3:*`, `iam:*` and `*` must appear where the simulator granted a wildcard (SPEC §4.6)."""
    text = (month_dir / "aws" / "authorization-details.json").read_text(encoding="utf-8")
    assert '"s3:*"' in text
    assert '"*"' in text
    details = load_json(month_dir / "aws" / "authorization-details.json")
    actions: set[str] = set()
    for user in details["UserDetailList"]:
        for policy in user["UserPolicyList"]:
            for statement in policy["PolicyDocument"]["Statement"]:
                raw = statement["Action"]
                actions.update(raw if isinstance(raw, list) else [raw])
    assert any(a.endswith(":*") or a == "*" for a in actions), sorted(actions)[:10]


def test_groups_and_roles_are_well_formed(month_dir: Path) -> None:
    details = load_json(month_dir / "aws" / "authorization-details.json")
    for group in details["GroupDetailList"]:
        assert ARN_GROUP.match(group["Arn"])
        assert group["GroupId"].startswith("AGPA")
        assert group["AttachedManagedPolicies"]
    members = {g for u in details["UserDetailList"] for g in u["GroupList"]}
    assert members <= {g["GroupName"] for g in details["GroupDetailList"]}
    for role in details["RoleDetailList"]:
        assert ARN_ROLE.match(role["Arn"])
        assert role["RoleId"].startswith("AROA")
        assert role["AssumeRolePolicyDocument"]["Statement"]
        assert ISO_TS.match(role["RoleLastUsed"]["LastUsedDate"])
        assert {t["Key"] for t in role["Tags"]}.isdisjoint({"owner", "project"}), "R10 needs no owner"


def test_managed_policies_carry_their_documents(month_dir: Path) -> None:
    details = load_json(month_dir / "aws" / "authorization-details.json")
    for policy in details["Policies"]:
        assert ARN_POLICY.match(policy["Arn"])
        assert policy["PolicyId"].startswith("ANPA")
        default = [v for v in policy["PolicyVersionList"] if v["IsDefaultVersion"]]
        assert len(default) == 1
        assert default[0]["Document"]["Statement"]
        assert policy["AttachmentCount"] >= 1


def _attached_managed(details: dict[str, Any]) -> set[str]:
    """Every managed policy name attached to a user, a group or a role this month."""
    out: set[str] = set()
    for key, listing in (
        ("UserDetailList", "AttachedManagedPolicies"),
        ("GroupDetailList", "AttachedManagedPolicies"),
        ("RoleDetailList", "AttachedManagedPolicies"),
    ):
        for holder in details.get(key, []):
            for att in holder.get(listing, []) or []:
                name = att.get("PolicyName")
                if name:
                    out.add(name)
    return out


def test_no_policy_is_attached_without_its_document(month_dir: Path) -> None:
    """The reverse direction of the test above, and the one that actually bites.

    `_policy_details` skips any attached policy with no entry in the catalogue, silently. A policy
    that reaches the export as a bare attachment loses whatever its document said -- which is how
    the citizen-data guardrail's explicit `Deny` went missing from the canonical model while the
    attachment itself looked perfectly healthy in the JSON.
    """
    details = load_json(month_dir / "aws" / "authorization-details.json")
    documented = {p["PolicyName"] for p in details["Policies"]}
    undocumented = sorted(_attached_managed(details) - documented)
    assert not undocumented, f"attached with no PolicyVersionList document: {undocumented}"


def test_credential_report_columns_are_exactly_the_spec_list(month_dir: Path) -> None:
    header, rows = read_csv(month_dir / "aws" / "credential-report.csv")
    assert tuple(header) == CREDENTIAL_REPORT_COLUMNS
    assert rows[0]["user"] == "<root_account>"
    users = [r for r in rows if r["user"] != "<root_account>"]
    assert users
    for row in users:
        assert ARN_USER.match(row["arn"])
        assert row["password_enabled"] in ("true", "false")
        assert row["mfa_active"] in ("true", "false")
        assert row["access_key_1_active"] in ("true", "false")
        assert ISO_TS.match(row["user_creation_time"])


def test_service_last_accessed_is_per_service_not_just_the_last_one(month_dir: Path) -> None:
    """SPEC §4.6: the credential report only names the last service; this file is what the
    least-privilege planner (SPEC §11.5) keeps and drops against, so it must carry every service a
    principal's policies allow, with the date it was last authenticated — or nothing at all when it
    never was."""
    entries = load_json(month_dir / "aws" / "service-last-accessed.json")
    assert entries
    cutoff = (month_end(SMALL_MONTHS) - timedelta(days=90)).isoformat()
    droppable = 0
    for entry in entries:
        assert ARN_USER.match(entry["Arn"]) or ARN_ROLE.match(entry["Arn"])
        assert entry["ServicesLastAccessed"]
        for service in entry["ServicesLastAccessed"]:
            assert service["ServiceName"] and service["ServiceNamespace"]
            used = "LastAuthenticated" in service
            assert service["TotalAuthenticatedEntities"] == (1 if used else 0)
            if used:
                assert ISO_TS.match(service["LastAuthenticated"])
                droppable += service["LastAuthenticated"][:10] < cutoff
            else:
                droppable += 1
    assert any(len(e["ServicesLastAccessed"]) > 1 for e in entries)
    assert droppable, "nothing to drop: every allowed service was used inside the dormancy window"


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


def test_role_assignments_carry_the_spec_fields(month_dir: Path) -> None:
    assignments = load_json(month_dir / "azure" / "role-assignments.json")
    assert assignments
    for assignment in assignments:
        assert set(assignment) >= {
            "id",
            "name",
            "principalId",
            "principalType",
            "principalName",
            "roleDefinitionId",
            "roleDefinitionName",
            "scope",
            "type",
        }
        assert GUID.match(assignment["name"])
        assert GUID.match(assignment["principalId"])
        assert assignment["principalType"] in ("User", "ServicePrincipal")
        assert assignment["type"] == "Microsoft.Authorization/roleAssignments"
        assert assignment["id"].endswith(
            f"/providers/Microsoft.Authorization/roleAssignments/{assignment['name']}"
        )
        assert assignment["id"].startswith(assignment["scope"])
        assert assignment["roleDefinitionName"] in cat.AZURE_ROLE_DEFINITIONS
        assert GUID.match(assignment["roleDefinitionId"].rsplit("/", 1)[-1])


def test_built_in_role_guids_are_the_real_ones(month_dir: Path) -> None:
    definitions = {d["roleName"]: d for d in load_json(month_dir / "azure" / "role-definitions.json")}
    assignments = load_json(month_dir / "azure" / "role-assignments.json")
    seen = {a["roleDefinitionName"]: a["roleDefinitionId"].rsplit("/", 1)[-1] for a in assignments}
    for name, guid in BUILT_IN_GUIDS.items():
        if name in seen:
            assert seen[name] == guid, name
        if name in definitions:
            assert definitions[name]["name"] == guid, name


def test_role_definitions_carry_their_actions(month_dir: Path) -> None:
    definitions = {d["roleName"]: d for d in load_json(month_dir / "azure" / "role-definitions.json")}
    assert "Owner" in definitions
    owner = definitions["Owner"]["permissions"][0]["actions"]
    assert "*" in owner
    for name in ("Owner", "User Access Administrator"):
        if name in definitions:
            actions = definitions[name]["permissions"][0]["actions"]
            assert any(
                a in ("*", "Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/write")
                for a in actions
            ), name
    for definition in definitions.values():
        assert definition["roleType"] in ("BuiltInRole", "CustomRole")
        assert GUID.match(definition["name"])
        assert definition["assignableScopes"]


def test_entra_users_are_the_graph_select_shape(month_dir: Path) -> None:
    users = load_json(month_dir / "azure" / "entra-users.json")
    assert users
    for user in users:
        assert set(user) == {
            "id",
            "userPrincipalName",
            "displayName",
            "accountEnabled",
            "department",
            "signInActivity",
        }
        assert GUID.match(user["id"])
        assert user["userPrincipalName"].endswith(f"@{ALLOWED_DOMAIN}")
        assert isinstance(user["accountEnabled"], bool)
        sign_in = user["signInActivity"]
        assert set(sign_in) == {"lastSignInDateTime", "lastNonInteractiveSignInDateTime"}
        for value in sign_in.values():
            assert value is None or ISO_TS.match(value)


def test_resource_groups_and_activity_summary(month_dir: Path) -> None:
    groups = load_json(month_dir / "azure" / "resource-groups.json")
    assert groups
    for group in groups:
        assert group["name"] and group["location"]
        assert "project" in group["tags"]
        assert group["id"].startswith("/subscriptions/")
    activity = load_json(month_dir / "azure" / "activity-log-summary.json")
    assert activity
    for row in activity:
        assert set(row) == {"principalId", "resourceProvider", "lastOperationTime", "operationCount"}
        assert GUID.match(row["principalId"])
        assert row["resourceProvider"].startswith("Microsoft.")
        assert ISO_TS.match(row["lastOperationTime"])


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


def test_projects_carry_a_region_label(month_dir: Path) -> None:
    projects = load_json(month_dir / "gcp" / "projects.json")
    assert projects
    for project in projects:
        assert project["projectId"] and project["name"]
        assert project["lifecycleState"] == "ACTIVE"
        assert project["labels"]["region"]
        assert project["projectNumber"].isdigit()


def test_iam_policies_are_the_gcloud_shape(month_dir: Path) -> None:
    policies = sorted((month_dir / "gcp").glob("*/iam-policy.json"))
    assert policies
    project_ids = {p["projectId"] for p in load_json(month_dir / "gcp" / "projects.json")}
    members: set[str] = set()
    for path in policies:
        assert path.parent.name in project_ids
        policy = load_json(path)
        assert set(policy) == {"bindings", "etag", "version"}
        assert policy["version"] == 1
        assert policy["etag"]
        for binding in policy["bindings"]:
            assert binding["role"].startswith(("roles/", "organizations/", "projects/"))
            assert binding["members"] == sorted(binding["members"])
            members.update(binding["members"])
    assert members
    for member in members:
        kind, _, value = member.partition(":")
        assert kind in ("user", "serviceAccount", "group"), member
        if kind == "user":
            assert value.endswith(f"@{ALLOWED_DOMAIN}")
        if kind == "serviceAccount":
            assert SA_EMAIL.match(value), member


def test_service_account_keys_and_activity(month_dir: Path) -> None:
    keys = load_json(month_dir / "gcp" / "service-account-keys.json")
    assert keys
    user_managed = 0
    for key in keys:
        assert re.match(r"^projects/[^/]+/serviceAccounts/[^/]+/keys/[0-9a-f]{40}$", key["name"]), key
        assert ISO_TS.match(key["validAfterTime"])
        assert key["keyType"] in ("USER_MANAGED", "SYSTEM_MANAGED")
        user_managed += key["keyType"] == "USER_MANAGED"
    assert user_managed
    activity = load_json(month_dir / "gcp" / "activity.json")
    assert activity
    for row in activity:
        assert set(row) == {
            "project",
            "member",
            "role",
            "lastAuthenticatedTime",
            "usedPermissionsCount",
            "totalPermissionsCount",
        }
        assert row["usedPermissionsCount"] <= row["totalPermissionsCount"]
        assert row["lastAuthenticatedTime"] is None or ISO_TS.match(row["lastAuthenticatedTime"])


# ---------------------------------------------------------------------------
# Inventories and HR
# ---------------------------------------------------------------------------


def test_the_three_inventories_carry_region_and_sensitivity(month_dir: Path) -> None:
    for cloud, ref_key in (("aws", "arn"), ("azure", "ref"), ("gcp", "ref")):
        rows = load_json(month_dir / cloud / "resources.json")
        assert rows, cloud
        for row in rows:
            assert set(row) == {ref_key, "service", "region", "sensitivity", "project"}
            assert row["sensitivity"] in ("low", "high")
            assert row["region"] and row["project"]


def test_hr_feed_is_marked_synthetic_and_has_the_spec_columns(month_dir: Path) -> None:
    employees = month_dir / "hr" / "employees.csv"
    first = employees.read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("#") and "SYNTHETIC" in first
    header, rows = read_csv(employees)
    assert tuple(header) == EMPLOYEE_COLUMNS
    assert rows
    for row in rows:
        assert row["email"].endswith(f"@{ALLOWED_DOMAIN}")
        assert row["employment_type"] in ("staff", "contractor", "service")
        assert row["status"] in ("active", "departed", "on_leave")
    projects_header, project_rows = read_csv(month_dir / "hr" / "projects.csv")
    assert tuple(projects_header) == PROJECT_COLUMNS
    assert project_rows and {r["cloud"] for r in project_rows} <= {"aws", "azure", "gcp"}
    exceptions_header, exception_rows = read_csv(month_dir / "hr" / "exceptions.csv")
    assert tuple(exceptions_header) == EXCEPTION_COLUMNS
    assert exception_rows, "the register carries the decoys' legitimacy (SPEC §4.3)"
    for row in exception_rows:
        assert row["exception_type"] in ("break-glass", "dr-failover", "approved-privileged-role")
        assert row["approved_by"].endswith(f"@{ALLOWED_DOMAIN}")
        assert row["justification"]


def test_no_real_domain_appears_anywhere_in_the_tree(small_estate: Path) -> None:
    for path in sorted(p for p in small_estate.rglob("*") if p.is_file()):
        text = path.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN:
            assert forbidden not in text, f"{path}: {forbidden}"
        for address in EMAIL.findall(text):
            if address.endswith(".iam.gserviceaccount.com") or address.endswith(".amazonaws.com"):
                continue  # provider-owned service principals, not people
            assert address.endswith(f"@{ALLOWED_DOMAIN}"), f"{path}: {address}"


def test_the_prompt_injection_tag_is_carried_as_data(small_estate: Path) -> None:
    """SPEC §11.3's hostile string rides on an AWS tag; the guardrails, not the writer, defuse it."""
    from athar.generator.names import INJECTION_NOTE

    details = load_json(small_estate / "month-01" / "aws" / "authorization-details.json")
    tagged = [
        user
        for user in details["UserDetailList"]
        if any(tag["Key"] == "note" and tag["Value"] == INJECTION_NOTE for tag in user["Tags"])
    ]
    assert len(tagged) == 1, "exactly one identity carries the injection note"
