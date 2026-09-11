"""normalise_month / normalise_provider / to_estate_view on the hand-written SPEC §4.6 estate.

The fixture under tests/unit/fixtures/native follows the native export shapes exactly (SPEC
§4.6) and exercises every SPEC §6 link rule, deny statements, wildcards, mapping misses (R0),
unlinked principals (R10) and the ATHAR-side resource inventories.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import pytest
from athar.clock import month_of
from athar.domain import CATEGORIES, IdentityRow
from athar.normaliser.pipeline import (
    NormalisedMonth,
    NormaliserError,
    hr_rows_to_month,
    normalise_hr,
    normalise_month,
    normalise_provider,
    provider_rows_to_month,
    to_estate_view,
)
from athar.normaliser.schemas import UploadValidationError
from athar.normaliser.types import UNMAPPED_ACTIONS_KEY, HrBundle

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "native"
SUB = "/subscriptions/11111111-1111-4111-8111-111111111111"
AISHA_ARN = "arn:aws:iam::123456789012:user/aisha.almansoori"
OMAR_ARN = "arn:aws:iam::123456789012:user/omar.haddad"
BATCH_ARN = "arn:aws:iam::123456789012:user/svc-batch"
GHOST_ARN = "arn:aws:iam::123456789012:user/ghost-user"
ETL_ROLE_ARN = "arn:aws:iam::123456789012:role/etl-runner"


@pytest.fixture(scope="module")
def m1() -> NormalisedMonth:
    return normalise_month(FIXTURES, 1)


@pytest.fixture(scope="module")
def m2() -> NormalisedMonth:
    return normalise_month(FIXTURES, 2)


def _ids(nm: NormalisedMonth) -> dict[str, IdentityRow]:
    return {i.identity_id: i for i in nm.identities}


def _grants(nm: NormalisedMonth, identity_id: str, cloud: str | None = None) -> list:
    return [g for g in nm.grants if g.identity_id == identity_id and (cloud is None or g.cloud == cloud)]


def _read_dir(path: Path) -> dict[str, bytes]:
    return {p.relative_to(path).as_posix(): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------- shape


def test_reads_every_provider_and_hr(m1: NormalisedMonth) -> None:
    assert m1.month == 1
    assert m1.clouds == ("aws", "azure", "gcp")
    assert {p.project_id for p in m1.projects} == {"prj-analytics", "prj-payments", "prj-legacy"}
    assert {e.identity_id for e in m1.exceptions} == {"emp-0005", "emp-0009"}
    assert len(m1.grants) > 100


def test_hr_comment_line_is_skipped(m1: NormalisedMonth) -> None:
    ids = _ids(m1)
    assert not any(i.startswith("#") for i in ids)
    humans = [i for i in ids.values() if i.identity_type == "human"]
    assert {h.identity_id for h in humans} == {
        "emp-0001",
        "emp-0002",
        "emp-0003",
        "emp-0004",
        "emp-0005",
        "emp-0009",
    }


def test_identity_months_come_from_the_simulated_clock(m1: NormalisedMonth) -> None:
    ids = _ids(m1)
    assert ids["emp-0002"].hire_month == month_of(date(2025, 9, 8)) == 1
    assert ids["emp-0001"].hire_month is None  # hired before the simulated epoch
    assert ids["emp-0003"].employment_status == "departed"
    assert ids["emp-0003"].departure_month == month_of(date(2025, 9, 20)) == 1
    assert ids["emp-0004"].contract_end_month == month_of(date(2026, 6, 30)) == 10
    assert ids["emp-0004"].external is True and ids["emp-0004"].employment_type == "contractor"
    assert ids["emp-0001"].external is False
    assert ids["emp-0001"].first_seen_month == ids["emp-0001"].last_seen_month == 1


def test_hr_service_rows_are_service_identities(m1: NormalisedMonth) -> None:
    svc = _ids(m1)["svc-0001"]
    assert svc.identity_type == "service"
    assert svc.employment_type == "service"
    assert svc.tags["project"] == "prj-analytics"  # from the linked GCP service account's project


def test_mfa_enforced_rule(m1: NormalisedMonth) -> None:
    ids = _ids(m1)
    assert ids["emp-0002"].mfa_enforced is False  # AWS credential report: mfa_active=false
    assert ids["emp-0001"].mfa_enforced is True  # AWS mfa_active=true
    assert ids["emp-0005"].mfa_enforced is True  # Entra export hint
    assert ids["emp-0009"].mfa_enforced is True  # no provider observation: assumed enforced (documented)
    assert ids["svc-0001"].mfa_enforced is False  # service identities never


# ---------------------------------------------------------------- grants


def test_every_grant_cites_an_identity_and_a_principal_row(m1: NormalisedMonth) -> None:
    ids = _ids(m1)
    principals = {p.principal_ref for p in m1.principals}
    for g in m1.grants:
        assert g.identity_id in ids, g
        assert g.principal_ref in principals, g
        assert g.snapshot_month == 1
        assert g.source_file and g.source_pointer
        assert g.raw_snippet, g.grant_id


def test_grant_id_is_sha256_prefix_of_the_natural_key(m1: NormalisedMonth) -> None:
    g = m1.grants[0]
    key = "|".join([g.principal_ref, g.cloud, g.service_category, g.verb, g.scope_ref, g.granted_via, "1"])
    assert g.grant_id == hashlib.sha256(key.encode()).hexdigest()[:32]
    assert len(g.grant_id) == 32


def test_grant_ids_unique_and_sorted(m1: NormalisedMonth) -> None:
    gids = [g.grant_id for g in m1.grants]
    assert len(set(gids)) == len(gids)
    assert gids == sorted(gids)


def test_administrator_access_is_admin_on_every_category_at_global_scope(m1: NormalisedMonth) -> None:
    rows = [
        g for g in _grants(m1, "emp-0002", "aws") if g.granted_via == "managed_policy:AdministratorAccess"
    ]
    assert {(g.service_category, g.verb) for g in rows} >= {(c, "admin") for c in CATEGORIES}
    assert {g.scope_level for g in rows} == {"global"}
    assert {g.scope_ref for g in rows} == {"*"}
    assert all(g.effect == "allow" for g in rows)


def test_deny_statement_produces_deny_rows(m1: NormalisedMonth) -> None:
    denies = [g for g in _grants(m1, "emp-0002", "aws") if g.effect == "deny"]
    assert {(g.service_category, g.verb) for g in denies} == {("billing", "read"), ("billing", "billing")}
    assert all(g.granted_via == "direct" for g in denies)
    assert denies[0].raw_snippet["PolicyName"] == "deny-billing"


def test_granted_via_vocabulary(m1: NormalisedMonth) -> None:
    via = {g.granted_via for g in m1.grants}
    assert "direct" in via
    assert "managed_policy:AdministratorAccess" in via
    assert "group:finance-readers" in via
    assert "role:Owner" in via
    assert "role:roles/owner" in via


def test_group_policies_reach_the_member(m1: NormalisedMonth) -> None:
    rows = [g for g in _grants(m1, "emp-0001", "aws") if g.granted_via == "group:finance-readers"]
    table = "arn:aws:dynamodb:me-central-1:123456789012:table/finance-ledger"
    inline = [g for g in rows if g.scope_ref == table]
    assert {(g.service_category, g.verb) for g in inline} == {("data", "read")}
    assert inline[0].region == "me-central-1"  # ARN region segment
    assert inline[0].scope_level == "resource"
    assert inline[0].source_pointer == "/GroupDetailList/0/GroupPolicyList/0/PolicyDocument/Statement/0"
    managed = [g for g in rows if g.scope_ref == "*"]
    assert {(g.service_category, g.verb) for g in managed} == {(c, "read") for c in CATEGORIES}


def test_inline_statement_pointer_and_raw_snippet(m1: NormalisedMonth) -> None:
    rows = [g for g in _grants(m1, "emp-0001", "aws") if g.granted_via == "direct"]
    assert {(g.service_category, g.verb) for g in rows} == {("storage", "read")}
    g = rows[0]
    assert g.source_file == "aws/authorization-details.json"
    assert g.source_pointer == "/UserDetailList/0/UserPolicyList/0/PolicyDocument/Statement/0"
    assert g.raw_snippet["Statement"]["Action"] == ["s3:GetObject", "s3:ListBucket"]
    assert g.raw_snippet["raw_action"] == ["s3:GetObject", "s3:ListBucket"]
    assert g.raw_snippet["UserName"] == "aisha.almansoori"
    assert g.scope_ref == "arn:aws:s3:::nda-finance-reports/*"
    assert g.region == "me-central-1"  # bucket ARN has no region: taken from the inventory


def test_trust_policy_becomes_an_impersonate_grant(m1: NormalisedMonth) -> None:
    rows = [g for g in _grants(m1, "svc:prj-legacy:svc-batch", "aws") if g.verb == "impersonate"]
    assert len(rows) == 1
    g = rows[0]
    assert g.service_category == "identity"
    assert g.scope_ref == ETL_ROLE_ARN
    assert g.source_pointer == "/RoleDetailList/0/AssumeRolePolicyDocument"
    assert g.raw_snippet["raw_action"] == "sts:AssumeRole"


def test_bucket_wildcard_expands_to_every_storage_verb(m1: NormalisedMonth) -> None:
    rows = [
        g
        for g in _grants(m1, "svc:prj-legacy:svc-batch", "aws")
        if g.scope_ref == "arn:aws:s3:::nda-citizen-data/*"
    ]
    assert {(g.service_category, g.verb) for g in rows} == {
        ("storage", "read"),
        ("storage", "write"),
        ("storage", "delete"),
        ("storage", "admin"),
    }


def test_customer_managed_policy_uses_its_default_version(m1: NormalisedMonth) -> None:
    ghost = "unlinked:aws:" + GHOST_ARN
    rows = [g for g in _grants(m1, ghost, "aws") if g.granted_via == "managed_policy:LegacyCustomPolicy"]
    assert {(g.service_category, g.verb) for g in rows} == {("compute", "read"), ("network", "read")}
    assert rows[0].source_pointer.startswith("/Policies/0")


def test_unknown_actions_and_roles_become_unknown_verb_and_are_reported(m1: NormalisedMonth) -> None:
    reported = {(u.cloud, u.raw) for u in m1.unmapped}
    assert reported == {
        ("aws", "mysteryservice:DoThing"),
        ("aws", "MysteryVendorAccess"),
        ("azure", "Vendor Custom Role"),
        ("gcp", "roles/customVendorRole"),
        ("gcp", "roles/spanner.databaseAdmin"),
    }
    unknown = [g for g in m1.grants if g.verb == "unknown"]
    assert {g.granted_via for g in unknown} >= {
        "managed_policy:MysteryVendorAccess",
        "role:Vendor Custom Role",
        "role:roles/customVendorRole",
        "role:roles/spanner.databaseAdmin",
        "direct",
    }
    spanner = next(g for g in unknown if g.granted_via == "role:roles/spanner.databaseAdmin")
    assert spanner.service_category == "data"  # known service prefix keeps its category
    for u in m1.unmapped:
        assert u.source_file and u.source_pointer and u.principal_ref


def test_unknown_rows_record_which_raw_action_failed_to_map(m1: NormalisedMonth) -> None:
    """SPEC §5.3: the `unknown` row names the action a mapping entry would fix, and only it."""
    reported = {u.raw for u in m1.unmapped}
    unknown = [g for g in m1.grants if g.verb == "unknown"]
    recorded = {a for g in unknown for a in g.raw_snippet.get(UNMAPPED_ACTIONS_KEY, [])}
    assert recorded and recorded <= reported
    for g in m1.grants:
        if g.verb != "unknown":
            assert UNMAPPED_ACTIONS_KEY not in g.raw_snippet


def test_azure_custom_role_resolves_through_role_definitions(m1: NormalisedMonth) -> None:
    rows = [g for g in m1.grants if g.granted_via == "role:Custom Ops Role"]
    assert {(g.service_category, g.verb) for g in rows} == {
        ("compute", "read"),
        ("compute", "write"),
        ("storage", "admin"),
    }


def test_region_from_arn_inventory_resource_group_and_project_label(m1: NormalisedMonth) -> None:
    khalid_rg = [g for g in _grants(m1, "emp-0009", "azure")]
    assert {g.region for g in khalid_rg} == {"westeurope"}  # resource group location
    sub_scope = [g for g in _grants(m1, "emp-0005", "azure")]
    assert {g.region for g in sub_scope} == {None}  # subscription scope has no location
    sandbox = [g for g in _grants(m1, "emp-0002", "gcp") if g.scope_ref == "projects/nda-sandbox"]
    assert {g.region for g in sandbox} == {"europe-west1"}  # project label
    prod = [g for g in _grants(m1, "emp-0003", "gcp")]
    assert {g.region for g in prod} == {"me-central1"}
    storage_account = [g for g in _grants(m1, "emp-0001", "azure") if "storageAccounts" in g.scope_ref]
    assert {g.region for g in storage_account} == {"uaecentral"}


def test_scope_levels_follow_spec_5_2(m1: NormalisedMonth) -> None:
    levels = {(g.cloud, g.scope_ref): g.scope_level for g in m1.grants}
    assert levels[("aws", "*")] == "global"
    assert levels[("aws", "arn:aws:s3:::nda-citizen-data")] == "resource"
    assert levels[("azure", SUB)] == "project"
    assert levels[("azure", f"{SUB}/resourceGroups/rg-analytics-dev")] == "resource"
    assert levels[("gcp", "projects/nda-analytics-prod")] == "project"


# ---------------------------------------------------------------- principals / linker


def test_every_spec_6_link_rule_is_exercised(m1: NormalisedMonth) -> None:
    links = {p.principal_ref: (p.identity_id, p.link_method, p.link_confidence) for p in m1.principals}
    assert links[AISHA_ARN] == ("emp-0001", "hr_email", "exact")
    assert links["aaaaaaaa-0005-4000-8000-000000000005"] == ("emp-0005", "entra_directory", "derived")
    assert links[OMAR_ARN] == ("emp-0002", "aws_username", "derived")
    assert links[BATCH_ARN] == ("svc:prj-legacy:svc-batch", "sa_project", "derived")
    assert links["arn:aws:iam::123456789012:user/rashid.bin.ali"] == ("emp-0004", "tag_owner", "heuristic")
    assert links[GHOST_ARN] == ("unlinked:aws:" + GHOST_ARN, "unlinked", "heuristic")
    assert links["serviceAccount:etl@nda-analytics-prod.iam.gserviceaccount.com"] == (
        "svc-0001",
        "sa_project",
        "derived",
    )
    assert links["cccccccc-0101-4000-8000-000000000101"][0] == "svc:prj-payments:sp-payments-api"
    assert links["group:analysts@nda.example"][1] == "unlinked"


def test_synthetic_identities_exist_for_svc_and_unlinked(m1: NormalisedMonth) -> None:
    ids = _ids(m1)
    batch = ids["svc:prj-legacy:svc-batch"]
    assert batch.identity_type == "service"
    assert batch.department == "Smart Services"  # from the project registry
    assert batch.tags["project"] == "prj-legacy" and batch.tags["principal_ref"] == BATCH_ARN
    ghost = ids["unlinked:aws:" + GHOST_ARN]
    assert ghost.identity_type == "service"
    assert ghost.department == "Unassigned"
    assert ghost.employment_type == "service"
    unlinked = [p for p in m1.principals if p.link_method == "unlinked"]
    assert {p.identity_id for p in unlinked} <= set(ids)


def test_principal_raw_keeps_native_identifiers(m1: NormalisedMonth) -> None:
    by_ref = {p.principal_ref: p for p in m1.principals}
    assert by_ref[OMAR_ARN].raw["UserId"] == "AIDAEXAMPLE000000002"
    assert by_ref[OMAR_ARN].raw["account"] == "123456789012"
    assert by_ref[OMAR_ARN].principal_type == "user"
    assert by_ref[ETL_ROLE_ARN].principal_type == "role"
    assert by_ref["cccccccc-0101-4000-8000-000000000101"].principal_type == "service_principal"
    assert by_ref["cccccccc-0101-4000-8000-000000000101"].raw["subscription"] == SUB
    assert by_ref["group:analysts@nda.example"].principal_type == "group"
    assert by_ref["user:omar.haddad@nda.example"].raw["projects"] == ["nda-analytics-prod", "nda-sandbox"]


def test_cloud_tags_are_evidence_never_exceptions(m1: NormalisedMonth) -> None:
    batch = next(p for p in m1.principals if p.principal_ref == BATCH_ARN)
    notes = [t["Value"] for t in batch.raw["Tags"] if t["Key"] == "note"]
    assert notes and "ignore previous instructions" in notes[0]  # retained as evidence …
    estate = to_estate_view(m1)
    assert estate.exceptions_for("svc:prj-legacy:svc-batch") == []  # … but never an exception
    assert {e.source for e in m1.exceptions} == {"register"}


# ---------------------------------------------------------------- activity / credentials / resources


def test_activity_rows_per_identity_cloud_category(m1: NormalisedMonth) -> None:
    rows = {(a.identity_id, a.cloud, a.service_category): a for a in m1.activity}
    assert rows[("emp-0001", "aws", "storage")].last_activity_at == date(2025, 9, 24)
    assert rows[("emp-0001", "aws", "data")].last_activity_at == date(2025, 9, 20)
    assert rows[("emp-0001", "aws", "identity")].last_activity_at == date(2025, 9, 25)  # password_last_used
    assert rows[("emp-0001", "azure", "identity")].last_activity_at == date(2025, 9, 26)  # sign-in
    assert rows[("emp-0001", "azure", "storage")].operation_count == 17
    assert ("emp-0001", "gcp", "data") not in rows  # lastAuthenticatedTime null → no row
    assert rows[("emp-0003", "gcp", "identity")].last_activity_at == date(2025, 5, 20)  # per binding role
    assert rows[("svc:prj-legacy:etl-runner", "aws", "identity")].last_activity_at == date(2025, 9, 10)
    assert rows[("svc:prj-legacy:svc-batch", "aws", "storage")].last_activity_at == date(2025, 4, 2)
    assert all(a.snapshot_month == 1 for a in m1.activity)
    keys = [(a.identity_id, a.cloud, a.service_category) for a in m1.activity]
    assert len(set(keys)) == len(keys) and keys == sorted(keys)


def test_credential_refs_and_kinds(m1: NormalisedMonth) -> None:
    creds = {c.credential_ref: c for c in m1.credentials}
    key = creds["aws:key:svc-batch/key-1"]
    assert key.kind == "key" and key.identity_id == "svc:prj-legacy:svc-batch"
    assert key.last_rotated_at == date(2024, 1, 15) and key.last_used_at == date(2025, 4, 2) and key.active
    assert creds["aws:password:svc-batch"].active is False  # password_enabled=false
    assert creds["aws:password:aisha.almansoori"].last_rotated_at == date(2025, 6, 1)
    sa = creds["gcp:sa_key:abcdef1234567890abcdef1234567890abcdef12"]
    assert sa.kind == "sa_key" and sa.identity_id == "svc-0001" and sa.created_at == date(2024, 6, 1)
    assert creds["gcp:sa_key:fedcba0987654321fedcba0987654321fedcba09"].active is False  # disabled
    assert "gcp:sa_key:0123456789abcdef0123456789abcdef01234567" not in creds  # SYSTEM_MANAGED skipped
    assert all(c.snapshot_month == 1 for c in m1.credentials)
    assert all(c.identity_id in _ids(m1) for c in m1.credentials)


def test_resources_from_inventories(m1: NormalisedMonth) -> None:
    res = {r.resource_ref: r for r in m1.resources}
    assert len(res) == 10
    eu = res["arn:aws:s3:::nda-backup-eu"]
    assert (eu.cloud, eu.service_category, eu.region, eu.sensitivity, eu.project_ref) == (
        "aws",
        "storage",
        "eu-west-1",
        "high",
        "123456789012",
    )
    fin = res[f"{SUB}/resourceGroups/rg-finance/providers/Microsoft.Storage/storageAccounts/ndafinance"]
    assert (fin.service_category, fin.region, fin.project_ref) == ("storage", "uaecentral", SUB)
    lake = res["//storage.googleapis.com/projects/_/buckets/nda-citizen-lake"]
    assert (lake.service_category, lake.region, lake.project_ref, lake.sensitivity) == (
        "storage",
        "me-central1",
        "nda-analytics-prod",
        "high",
    )
    assert all(r.snapshot_month == 1 for r in m1.resources)


def test_resources_are_derived_from_scope_refs_without_an_inventory() -> None:
    files = {k: v for k, v in _read_dir(FIXTURES / "month-01" / "aws").items() if k != "resources.json"}
    hr = normalise_hr(1, _read_dir(FIXTURES / "month-01" / "hr")).bundle
    rows = normalise_provider("aws", 1, files, hr)
    res = {r.resource_ref: r for r in rows.resources}
    assert "arn:aws:s3:::nda-finance-reports" in res
    assert res["arn:aws:s3:::nda-finance-reports"].region is None
    assert res["arn:aws:s3:::nda-finance-reports"].sensitivity == "low"
    assert res["arn:aws:s3:::nda-finance-reports"].service_category == "storage"
    assert res["arn:aws:dynamodb:me-central-1:123456789012:table/finance-ledger"].service_category == "data"
    assert "*" not in res


# ---------------------------------------------------------------- events / hashes / determinism


def test_events_read_up_to_the_month_with_grant_delta(m1: NormalisedMonth, m2: NormalisedMonth) -> None:
    assert [e.event_id for e in m1.events] == ["ev-01-001", "ev-01-002"]
    assert [e.event_id for e in m2.events] == ["ev-01-001", "ev-01-002", "ev-02-00002", "ev-02-002"]
    first = m1.events[0]
    assert first.kind == "new_hire" and first.identity_id == "emp-0002" and first.cloud == "aws"
    assert first.grant_delta["added"][0]["principal_ref"] == OMAR_ARN
    assert first.grant_delta["removed"] == []
    minted = next(e for e in m2.events if e.event_id == "ev-02-00002")  # line without event_id
    assert len(minted.grant_delta["added"]) == 1 and len(minted.grant_delta["removed"]) == 1
    extra = next(e for e in m2.events if e.event_id == "ev-02-002")
    assert extra.grant_delta["credential_ref"].startswith("azure:password:")
    assert any("malformed JSON" in w for w in m1.warnings)


def test_file_hashes_cover_every_file(m1: NormalisedMonth) -> None:
    month_dir = FIXTURES / "month-01"
    expected = {p.relative_to(month_dir).as_posix() for p in month_dir.rglob("*") if p.is_file()}
    assert set(m1.file_hashes) == expected
    csv = month_dir / "hr" / "employees.csv"
    assert m1.file_hashes["hr/employees.csv"] == hashlib.sha256(csv.read_bytes()).hexdigest()


def test_second_run_is_identical(m1: NormalisedMonth) -> None:
    again = normalise_month(FIXTURES, 1)
    assert again == m1


def test_month_two_reflects_the_changed_files(m1: NormalisedMonth, m2: NormalisedMonth) -> None:
    ids2 = _ids(m2)
    assert "emp-0006" in ids2 and "emp-0006" not in _ids(m1)
    assert ids2["emp-0006"].hire_month == 2
    assert "unlinked:aws:" + GHOST_ARN not in ids2
    assert {g.granted_via for g in _grants(m2, "emp-0002", "aws")} == {
        "direct",
        "managed_policy:PowerUserAccess",
    }
    assert ids2["emp-0002"].mfa_enforced is True
    assert ("azure", "Vendor Custom Role") not in {(u.cloud, u.raw) for u in m2.unmapped}
    assert all(g.snapshot_month == 2 for g in m2.grants)
    assert not {g.grant_id for g in m1.grants} & {g.grant_id for g in m2.grants}  # month is in the key


def test_missing_month_directory_raises_normaliser_error() -> None:
    with pytest.raises(NormaliserError):
        normalise_month(FIXTURES, 99)


def test_to_estate_view_round_trip(m1: NormalisedMonth) -> None:
    estate = to_estate_view(m1)
    assert estate.month == 1
    assert set(estate.identities) == {i.identity_id for i in m1.identities}
    assert set(estate.principals) == {p.principal_ref for p in m1.principals}
    assert len(estate.grants_for("emp-0002")) == len(_grants(m1, "emp-0002"))
    assert estate.valid_exception("emp-0005", "break-glass") is not None
    assert estate.valid_exception("emp-0009", "approved-privileged-role") is None
    assert estate.expired_exception("emp-0009", "approved-privileged-role") is not None
    assert estate.project_for_ref("legacy-portal") is not None
    assert estate.project_for_ref("legacy-portal").status == "retired"
    assert [e.event_id for e in estate.events_for("emp-0002")] == ["ev-01-001"]
    assert estate.clouds_for("emp-0002") == ["aws", "gcp"]
    assert estate.last_activity("emp-0003") == date(2025, 6, 1)


# ---------------------------------------------------------------- uploads


def test_normalise_provider_links_against_an_hr_bundle(m1: NormalisedMonth) -> None:
    hr = normalise_hr(1, _read_dir(FIXTURES / "month-01" / "hr"))
    assert {i.identity_id for i in hr.identities} == {
        i.identity_id for i in m1.identities if not i.identity_id.startswith(("svc:", "unlinked:"))
    }
    rows = normalise_provider("aws", 1, _read_dir(FIXTURES / "month-01" / "aws"), hr.bundle)
    assert rows.cloud == "aws" and rows.month == 1
    expected = {(p.principal_ref, p.identity_id, p.link_method) for p in m1.principals if p.cloud == "aws"}
    assert {(p.principal_ref, p.identity_id, p.link_method) for p in rows.principals} == expected
    assert {g.grant_id for g in rows.grants} == {g.grant_id for g in m1.grants if g.cloud == "aws"}
    assert all(i.identity_id.startswith(("svc:", "unlinked:")) for i in rows.identities)
    assert set(rows.file_hashes) == {
        "aws/" + n
        for n in (
            "authorization-details.json",
            "credential-report.csv",
            "resources.json",
            "service-last-accessed.json",
        )
    }
    assert {u.raw for u in rows.unmapped} == {"mysteryservice:DoThing", "MysteryVendorAccess"}


def test_normalise_provider_without_hr_leaves_every_principal_unlinked() -> None:
    rows = normalise_provider("gcp", 1, _read_dir(FIXTURES / "month-01" / "gcp"), None)
    assert rows.principals and all(p.link_method == "unlinked" for p in rows.principals)
    assert all(i.identity_id.startswith("unlinked:gcp:") for i in rows.identities)
    assert all(g.identity_id.startswith("unlinked:gcp:") for g in rows.grants)


def test_hr_bundle_rebuilt_from_stored_identities_links_the_same_way(m1: NormalisedMonth) -> None:
    bundle = HrBundle.from_identities(m1.identities, m1.projects, m1.exceptions)
    rows = normalise_provider("aws", 1, _read_dir(FIXTURES / "month-01" / "aws"), bundle)
    expected = {(p.principal_ref, p.identity_id) for p in m1.principals if p.cloud == "aws"}
    assert {(p.principal_ref, p.identity_id) for p in rows.principals} == expected


def test_normalise_provider_rejects_unknown_provider_and_bad_files() -> None:
    with pytest.raises(UploadValidationError) as exc:
        normalise_provider("oracle", 1, {}, None)
    assert exc.value.code == "upload.unknown_provider"
    with pytest.raises(UploadValidationError) as exc:
        normalise_provider("aws", 1, {"authorization-details.json": b"{not json"}, None)
    assert exc.value.code == "upload.malformed_json"


def test_wrappers_produce_normalised_months_for_upsert(m1: NormalisedMonth) -> None:
    hr = normalise_hr(1, _read_dir(FIXTURES / "month-01" / "hr"))
    hr_month = hr_rows_to_month(hr)
    assert hr_month.clouds == () and hr_month.month == 1
    assert {i.identity_id for i in hr_month.identities} == {e.employee_id for e in hr.bundle.employees}
    assert hr_month.file_hashes.keys() == {"hr/employees.csv", "hr/projects.csv", "hr/exceptions.csv"}
    rows = normalise_provider("azure", 1, _read_dir(FIXTURES / "month-01" / "azure"), hr.bundle)
    month = provider_rows_to_month(rows, hr.bundle)
    assert month.clouds == ("azure",)
    assert month.projects == list(hr.bundle.projects)
    assert {g.grant_id for g in month.grants} == {g.grant_id for g in m1.grants if g.cloud == "azure"}
