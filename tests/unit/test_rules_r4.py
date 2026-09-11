"""R4 Cross-cloud superuser (SPEC §7): the same power at scope ≥ project in all three clouds."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import AWS_ACCT, AZ_SUB, GCP_PROJECT_REF, f, run, wide_grant


def _estate(*grants):  # type: ignore[no-untyped-def]
    return f.estate(identities=[f.identity()], grants=list(grants))


def test_admin_in_all_three_clouds_is_critical() -> None:
    est = _estate(
        wide_grant("g-aws", "aws", "admin"),
        wide_grant(
            "g-az",
            "azure",
            "admin",
            scope_level="org",
            scope_ref="/providers/Microsoft.Management/managementGroups/nda",
        ),
        wide_grant("g-gcp", "gcp", "admin"),
    )
    drafts = run("R4", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "Critical" and d.facts["power"] == "admin"
    assert d.facts["per_cloud"] == {
        "aws": [AWS_ACCT],
        "azure": ["/providers/Microsoft.Management/managementGroups/nda"],
        "gcp": [GCP_PROJECT_REF],
    }
    assert d.facts["grant_ids"] == ["g-aws", "g-az", "g-gcp"]
    assert d.facts["clouds"] == ["aws", "azure", "gcp"]


def test_write_and_delete_in_all_three_clouds_is_high() -> None:
    grants = [wide_grant(f"g-{c}-{v}", c, v) for c in ("aws", "azure", "gcp") for v in ("write", "delete")]
    drafts = run("R4", _estate(*grants))
    assert len(drafts) == 1
    assert drafts[0].severity == "High" and drafts[0].facts["power"] == "write_delete"
    assert len(drafts[0].facts["grant_ids"]) == 6


def test_admin_in_two_clouds_only_does_not_fire() -> None:
    est = _estate(wide_grant("g-aws", "aws", "admin"), wide_grant("g-az", "azure", "admin"))
    assert run("R4", est) == []


def test_write_without_delete_in_one_cloud_does_not_fire() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "write"),
        wide_grant("g-2", "aws", "delete"),
        wide_grant("g-3", "azure", "write"),
        wide_grant("g-4", "azure", "delete"),
        wide_grant("g-5", "gcp", "write"),
    )
    assert run("R4", est) == []


def test_mixed_admin_and_write_delete_is_high() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin"),
        wide_grant("g-2", "azure", "admin"),
        wide_grant("g-3", "gcp", "write"),
        wide_grant("g-4", "gcp", "delete"),
    )
    drafts = run("R4", est)
    assert drafts[0].severity == "High" and drafts[0].facts["power"] == "write_delete"


def test_resource_scope_does_not_count() -> None:
    est = _estate(
        wide_grant("g-aws", "aws", "admin"),
        wide_grant("g-az", "azure", "admin"),
        wide_grant("g-gcp", "gcp", "admin", scope_level="resource", scope_ref="projects/p/buckets/b"),
    )
    assert run("R4", est) == []


def test_write_delete_pairs_must_each_be_at_project_scope() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "write"),
        wide_grant("g-2", "aws", "delete", scope_level="resource", scope_ref="arn:aws:s3:::b"),
        wide_grant("g-3", "azure", "write"),
        wide_grant("g-4", "azure", "delete"),
        wide_grant("g-5", "gcp", "write"),
        wide_grant("g-6", "gcp", "delete"),
    )
    assert run("R4", est) == []


def test_inactive_and_deny_grants_are_ignored() -> None:
    est = _estate(
        wide_grant("g-aws", "aws", "admin", active=False),
        wide_grant("g-az", "azure", "admin"),
        wide_grant("g-gcp", "gcp", "admin", effect="deny"),
    )
    assert run("R4", est) == []


def test_per_cloud_scope_refs_are_sorted_and_deduplicated() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin", scope_ref="222222222222"),
        wide_grant("g-2", "aws", "admin", scope_ref="111111111111"),
        wide_grant("g-3", "aws", "admin", scope_ref="111111111111"),
        wide_grant("g-4", "azure", "admin"),
        wide_grant("g-5", "gcp", "admin"),
    )
    per_cloud = run("R4", est)[0].facts["per_cloud"]
    assert per_cloud["aws"] == ["111111111111", "222222222222"]
    assert per_cloud["azure"] == [AZ_SUB]


def test_deterministic_sorted_and_facts_complete() -> None:
    grants = [
        wide_grant(f"g-{i}-{c}", c, "admin", identity_id=i)
        for i in ("emp-0002", "emp-0001")
        for c in ("aws", "azure", "gcp")
    ]
    est = f.estate(identities=[f.identity("emp-0002"), f.identity("emp-0001")], grants=grants)
    a, b = run("R4", est), run("R4", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R4", d.facts) == [] for d in a)
