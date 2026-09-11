"""R3 Orphaned identity (SPEC §7): departed ≥ 1 month with access, or a retired project's SA."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import AWS_ROLE, AWS_USER, GCP_PROJECT, GCP_PROJECT_REF, GCP_SA, f, run

SVC_ID = "svc:prj-001:etl"


def _departed(month: int | None = 11, status: str = "departed"):  # type: ignore[no-untyped-def]
    return f.identity(employment_status=status, departure_month=month)


def _svc(identity_id: str = SVC_ID, **kw):  # type: ignore[no-untyped-def]
    return f.identity(
        identity_id, identity_type="service", employment_type="service", department="Data Services", **kw
    )


def _svc_grant(grant_id: str = "g-svc", identity_id: str = SVC_ID, **kw):  # type: ignore[no-untyped-def]
    base = dict(
        identity_id=identity_id,
        principal_ref=GCP_SA,
        cloud="gcp",
        verb="write",
        scope_level="project",
        scope_ref=GCP_PROJECT_REF,
    )
    base.update(kw)
    return f.grant(grant_id, **base)


def test_departed_last_month_with_grant_fires_critical() -> None:
    est = f.estate(identities=[_departed(11)], grants=[f.grant("g-1")])
    drafts = run("R3", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "Critical" and d.facts["orphan_kind"] == "departed"
    assert d.facts["departure_month"] == 11 and d.facts["months_since_departure"] == 1
    assert d.facts["project_id"] is None and d.facts["retired_month"] is None
    assert d.facts["grant_ids"] == ["g-1"]


def test_departed_this_month_does_not_fire_yet() -> None:
    est = f.estate(identities=[_departed(12)], grants=[f.grant("g-1")])
    assert run("R3", est) == []


def test_departed_long_ago_counts_months() -> None:
    est = f.estate(identities=[_departed(3)], grants=[f.grant("g-1")])
    assert run("R3", est)[0].facts["months_since_departure"] == 9


def test_departed_without_active_grants_does_not_fire() -> None:
    est = f.estate(identities=[_departed(5)], grants=[f.grant("g-1", active=False)])
    assert run("R3", est) == []


def test_active_and_on_leave_humans_do_not_fire() -> None:
    est = f.estate(
        identities=[_departed(None, status="active"), f.identity("emp-0002", employment_status="on_leave")],
        grants=[f.grant("g-1"), f.grant("g-2", identity_id="emp-0002")],
    )
    assert run("R3", est) == []


def test_departed_without_departure_month_does_not_fire() -> None:
    est = f.estate(identities=[_departed(None)], grants=[f.grant("g-1")])
    assert run("R3", est) == []


def test_departure_event_cited_and_causal() -> None:
    est = f.estate(
        identities=[_departed(10)],
        grants=[f.grant("g-1", principal_ref=AWS_USER, scope_ref="arn:aws:s3:::x")],
        events=[
            f.event("ev-hr", 10, "departure", cloud=None, trigger="departure"),
            f.event(
                "ev-grant",
                4,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": "arn:aws:s3:::x"}]},
            ),
            f.event("ev-other", 6, "role_change", grant_delta={"added": [{"principal_ref": "nope"}]}),
        ],
    )
    d = run("R3", est)[0]
    assert d.causal_event_ids == ["ev-grant", "ev-hr"]
    assert ("event", "ev-hr") in {(e.kind, e.ref) for e in d.evidence}


def test_service_on_retired_project_by_identity_id_pattern() -> None:
    est = f.estate(
        identities=[_svc()],
        grants=[_svc_grant()],
        projects=[f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT)],
    )
    drafts = run("R3", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.facts["orphan_kind"] == "retired_project" and d.facts["project_id"] == "prj-001"
    assert d.facts["retired_month"] == 9 and d.facts["departure_month"] is None
    assert ("project", "prj-001") in {(e.kind, e.ref) for e in d.evidence}


def test_service_on_retired_project_by_project_ref_in_identity_id() -> None:
    est = f.estate(
        identities=[_svc(f"svc:{GCP_PROJECT}:etl")],
        grants=[_svc_grant(identity_id=f"svc:{GCP_PROJECT}:etl")],
        projects=[f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT)],
    )
    assert run("R3", est)[0].facts["project_id"] == "prj-001"


def test_service_on_retired_project_by_tag() -> None:
    est = f.estate(
        identities=[_svc("sa-legacy", tags={"project": "prj-001"})],
        grants=[_svc_grant(identity_id="sa-legacy", scope_ref="arn:aws:s3:::unrelated", cloud="aws")],
        projects=[f.project("prj-001", status="retired", retired_month=2)],
    )
    assert run("R3", est)[0].facts["project_id"] == "prj-001"


def test_service_on_retired_project_by_grant_scope() -> None:
    est = f.estate(
        identities=[_svc("sa-legacy")],
        grants=[_svc_grant(identity_id="sa-legacy")],
        projects=[f.project("prj-001", status="retired", retired_month=2, project_ref=GCP_PROJECT)],
    )
    assert run("R3", est)[0].facts["project_id"] == "prj-001"


def test_service_on_retired_project_by_resource_project_ref() -> None:
    est = f.estate(
        identities=[_svc("sa-legacy")],
        grants=[
            _svc_grant(
                identity_id="sa-legacy", scope_level="resource", scope_ref="arn:aws:s3:::etl", cloud="aws"
            )
        ],
        resources=[f.resource("arn:aws:s3:::etl", project_ref="acct-prod")],
        projects=[
            f.project("prj-001", status="retired", retired_month=2, cloud="aws", project_ref="acct-prod")
        ],
    )
    assert run("R3", est)[0].facts["project_id"] == "prj-001"


def test_short_project_ref_does_not_substring_match_scope() -> None:
    est = f.estate(
        identities=[_svc("sa-legacy")],
        grants=[_svc_grant(identity_id="sa-legacy")],  # scope projects/nda-analytics-prod
        projects=[f.project("prj-prod", status="retired", retired_month=2, project_ref="prod")],
    )
    assert run("R3", est) == []


def test_resource_scope_inside_retired_gcp_project_matches() -> None:
    est = f.estate(
        identities=[_svc("sa-legacy")],
        grants=[
            _svc_grant(
                identity_id="sa-legacy", scope_level="resource", scope_ref=f"{GCP_PROJECT_REF}/buckets/etl"
            )
        ],
        projects=[f.project("prj-001", status="retired", retired_month=2, project_ref=GCP_PROJECT)],
    )
    assert run("R3", est)[0].facts["project_id"] == "prj-001"


def test_service_on_active_project_does_not_fire() -> None:
    est = f.estate(
        identities=[_svc()],
        grants=[_svc_grant()],
        projects=[f.project("prj-001", status="active", project_ref=GCP_PROJECT)],
    )
    assert run("R3", est) == []


def test_service_without_project_does_not_fire() -> None:
    est = f.estate(identities=[_svc("sa-lonely")], grants=[_svc_grant(identity_id="sa-lonely")])
    assert run("R3", est) == []


def test_retired_project_service_without_grants_does_not_fire() -> None:
    est = f.estate(identities=[_svc()], projects=[f.project("prj-001", status="retired", retired_month=9)])
    assert run("R3", est) == []


def test_project_retirement_event_is_causal() -> None:
    est = f.estate(
        identities=[_svc()],
        grants=[_svc_grant()],
        projects=[f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT)],
        events=[
            f.event(
                "ev-ret",
                9,
                "project_retirement",
                identity_id=SVC_ID,
                cloud="gcp",
                trigger="project_retirement",
            )
        ],
    )
    d = run("R3", est)[0]
    assert d.causal_event_ids == ["ev-ret"]
    assert ("event", "ev-ret") in {(e.kind, e.ref) for e in d.evidence}


def test_departed_human_is_not_checked_against_projects() -> None:
    est = f.estate(
        identities=[f.identity(tags={"project": "prj-001"})],
        grants=[f.grant("g-1", principal_ref=AWS_ROLE)],
        projects=[f.project("prj-001", status="retired", retired_month=9)],
    )
    assert run("R3", est) == []


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        identities=[_svc(), f.identity("emp-0009", employment_status="departed", departure_month=8)],
        grants=[_svc_grant(), f.grant("g-9", identity_id="emp-0009")],
        projects=[f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT)],
    )
    a, b = run("R3", est), run("R3", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0009", SVC_ID]
    assert all(missing_slots("R3", d.facts) == [] for d in a)


def test_a_cloud_tag_cannot_hide_a_retired_project() -> None:
    """Non-negotiable 9: provider data may add a finding, never remove one.

    A service identity whose grants sit in a retired project used to escape R3 entirely when
    someone with tagging rights set `project` to a live one: the tag was consulted before the
    grant scope and short-circuited it.
    """
    est = f.estate(
        identities=[_svc("unlinked:gcp:etl", tags={"project": "prj-live"})],
        grants=[_svc_grant(identity_id="unlinked:gcp:etl")],
        projects=[
            f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT),
            f.project("prj-live", status="active", retired_month=None, project_ref="nda-current"),
        ],
    )
    drafts = run("R3", est)
    assert [d.rule_id for d in drafts] == ["R3"], "the retired project behind the grant still fires"
    assert drafts[0].facts["orphan_kind"] == "retired_project"
    assert drafts[0].facts["project_id"] == "prj-001"
