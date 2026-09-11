"""R8 Data-residency drift (SPEC §7): a grant on a high-sensitivity resource outside approved regions."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from athar.domain import Thresholds
from test_rules_support import AWS_ACCT, AWS_USER, GCP_PROJECT, GCP_PROJECT_REF, f, run

CITIZEN = "arn:aws:s3:::nda-citizen-records"


def _estate(*grants, resources=(), identities=None, events=()):  # type: ignore[no-untyped-def]
    return f.estate(
        identities=identities or [f.identity()],
        principals=[f.principal(AWS_USER)],
        grants=list(grants),
        resources=list(resources),
        events=list(events),
    )


def _citizen(region: str = "eu-west-1", sensitivity: str = "high"):  # type: ignore[no-untyped-def]
    return f.resource(CITIZEN, category="data", region=region, sensitivity=sensitivity)


def test_high_sensitivity_outside_region_fires_high() -> None:
    est = _estate(
        f.grant("g-1", verb="read", scope_ref=CITIZEN, service_category="data"), resources=[_citizen()]
    )
    drafts = run("R8", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "High" and d.facts["region"] == "eu-west-1"
    assert d.facts["resource_ref"] == CITIZEN and d.facts["resource_sensitivity"] == "high"
    assert d.facts["approved_regions"] == sorted(Thresholds().approved_regions)
    assert d.facts["grant_ids"] == ["g-1"] and d.facts["resource_refs"] == [CITIZEN]
    refs = {(e.kind, e.ref) for e in d.evidence}
    assert ("grant", "g-1") in refs and ("resource", CITIZEN) in refs


def test_approved_region_does_not_fire() -> None:
    est = _estate(f.grant("g-1", scope_ref=CITIZEN), resources=[_citizen(region="me-central-1")])
    assert run("R8", est) == []


def test_low_sensitivity_outside_region_does_not_fire() -> None:
    est = _estate(f.grant("g-1", scope_ref=CITIZEN), resources=[_citizen(sensitivity="low")])
    assert run("R8", est) == []


def test_resource_without_region_falls_back_to_grant_region() -> None:
    res = f.resource(CITIZEN, category="data", region=None, sensitivity="high")  # type: ignore[arg-type]
    drafts = run("R8", _estate(f.grant("g-1", scope_ref=CITIZEN, region="eu-west-1"), resources=[res]))
    assert len(drafts) == 1 and drafts[0].facts["region"] == "eu-west-1"
    assert any(e.kind == "resource" and "eu-west-1" in e.note for e in drafts[0].evidence)


def test_resource_without_region_and_approved_grant_region_does_not_fire() -> None:
    res = f.resource(CITIZEN, category="data", region=None, sensitivity="high")  # type: ignore[arg-type]
    assert run("R8", _estate(f.grant("g-1", scope_ref=CITIZEN, region="me-central-1"), resources=[res])) == []


def test_resource_region_wins_over_grant_region() -> None:
    est = _estate(f.grant("g-1", scope_ref=CITIZEN, region="me-central-1"), resources=[_citizen("us-east-1")])
    assert run("R8", est)[0].facts["region"] == "us-east-1"


def test_no_region_anywhere_cannot_fire() -> None:
    res = f.resource(CITIZEN, category="data", region=None, sensitivity="high")  # type: ignore[arg-type]
    assert run("R8", _estate(f.grant("g-1", scope_ref=CITIZEN, region=None), resources=[res])) == []


def test_prefix_match_on_resource_scope() -> None:
    est = _estate(f.grant("g-1", scope_ref=f"{CITIZEN}/*"), resources=[_citizen()])
    assert len(run("R8", est)) == 1


def test_narrower_grant_than_resource_matches_too() -> None:
    est = _estate(f.grant("g-1", scope_ref=f"{CITIZEN}/exports/2026"), resources=[_citizen()])
    assert len(run("R8", est)) == 1


def test_unrelated_resource_scope_does_not_match() -> None:
    est = _estate(f.grant("g-1", scope_ref="arn:aws:s3:::other-bucket"), resources=[_citizen()])
    assert run("R8", est) == []


def test_project_scope_matches_resources_by_project_ref() -> None:
    res = f.resource(
        f"{GCP_PROJECT_REF}/datasets/citizen_records",
        cloud="gcp",
        category="data",
        region="europe-west1",
        sensitivity="high",
        project_ref=GCP_PROJECT,
    )
    est = _estate(
        f.grant("g-1", cloud="gcp", verb="write", scope_level="project", scope_ref=GCP_PROJECT_REF),
        resources=[res],
    )
    drafts = run("R8", est)
    assert len(drafts) == 1 and drafts[0].facts["cloud"] == "gcp"


def test_project_scope_in_another_project_does_not_match() -> None:
    res = f.resource(
        "projects/other/datasets/x",
        cloud="gcp",
        region="europe-west1",
        sensitivity="high",
        project_ref="other",
    )
    est = _estate(
        f.grant("g-1", cloud="gcp", scope_level="project", scope_ref=GCP_PROJECT_REF), resources=[res]
    )
    assert run("R8", est) == []


def test_short_project_ref_is_not_a_substring_match() -> None:
    """`prod` must not match `projects/nda-analytics-prod` (SPEC §5.1 project_ref is a name, not a fragment)."""
    res = f.resource(
        "projects/prod/datasets/x", cloud="gcp", region="europe-west1", sensitivity="high", project_ref="prod"
    )
    est = _estate(
        f.grant("g-1", cloud="gcp", scope_level="project", scope_ref=GCP_PROJECT_REF), resources=[res]
    )
    assert run("R8", est) == []


def test_aws_account_scope_matches_resources_by_account_project_ref() -> None:
    res = f.resource(CITIZEN, category="data", region="eu-west-1", sensitivity="high", project_ref=AWS_ACCT)
    est = _estate(f.grant("g-1", scope_level="project", scope_ref=AWS_ACCT, verb="write"), resources=[res])
    assert len(run("R8", est)) == 1


def test_org_scope_is_not_matched() -> None:
    est = _estate(f.grant("g-1", verb="admin", scope_level="org", scope_ref=AWS_ACCT), resources=[_citizen()])
    assert run("R8", est) == []


def test_grant_region_alone_without_resource_row_does_not_fire() -> None:
    est = _estate(f.grant("g-1", region="eu-west-1", scope_ref="arn:aws:s3:::somewhere"))
    assert run("R8", est) == []


def test_other_cloud_resource_with_same_ref_is_ignored() -> None:
    res = f.resource(CITIZEN, cloud="gcp", category="data", region="europe-west1", sensitivity="high")
    est = _estate(f.grant("g-1", scope_ref=CITIZEN), resources=[res])
    assert run("R8", est) == []


def test_approved_regions_come_from_thresholds() -> None:
    est = _estate(f.grant("g-1", scope_ref=CITIZEN), resources=[_citizen()])
    assert run("R8", est, Thresholds(approved_regions=("eu-west-1",))) == []
    assert len(run("R8", est, Thresholds(approved_regions=("uaenorth",)))) == 1


def test_one_draft_cites_every_hit() -> None:
    other = f.resource("arn:aws:s3:::nda-health", category="data", region="us-east-1", sensitivity="high")
    est = _estate(
        f.grant("g-2", scope_ref="arn:aws:s3:::nda-health"),
        f.grant("g-1", scope_ref=CITIZEN),
        f.grant("g-3", scope_ref=CITIZEN, active=False),
        resources=[_citizen(), other],
    )
    drafts = run("R8", est)
    assert len(drafts) == 1
    assert drafts[0].facts["grant_ids"] == ["g-1", "g-2"]
    assert drafts[0].facts["resource_refs"] == [CITIZEN, "arn:aws:s3:::nda-health"]
    assert drafts[0].facts["resource_ref"] == CITIZEN  # first grant by id drives the headline facts


def test_region_drift_event_is_causal() -> None:
    est = _estate(
        f.grant("g-1", principal_ref=AWS_USER, scope_ref=CITIZEN),
        resources=[_citizen()],
        events=[
            f.event("ev-drift", 9, "region_drift", trigger="region_drift"),
            f.event(
                "ev-grant",
                4,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": CITIZEN}]},
            ),
        ],
    )
    assert run("R8", est)[0].causal_event_ids == ["ev-drift", "ev-grant"]


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        grants=[
            f.grant("g-b", identity_id="emp-0002", scope_ref=CITIZEN),
            f.grant("g-a", identity_id="emp-0001", scope_ref=CITIZEN),
        ],
        resources=[_citizen()],
    )
    a, b = run("R8", est), run("R8", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R8", d.facts) == [] for d in a)
