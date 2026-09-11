"""Access graph (SPEC §8.1): membership, deny cancellation, reachability, escalation paths."""

from __future__ import annotations

import pytest
from athar.domain import EstateView
from athar.scoring import graph as ag
from athar.scoring.types import PathEdge
from tests import factories as f

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
USER = f"arn:aws:iam::{ACCOUNT}:user/alia.hassan"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/PlatformAdmin"
BUCKET = "arn:aws:s3:::nda-citizen-data"
LEDGER = "arn:aws:s3:::nda-finance-ledger"
OTHER_BUCKET = "arn:aws:s3:::nda-archive"


def _aws_estate(grants: list, extra_principals: list | None = None, **kw) -> EstateView:
    principals = [
        f.principal(USER, identity_id="emp-0001"),
        f.principal(ADMIN_ROLE, identity_id="svc-admin", principal_type="role"),
        *(extra_principals or []),
    ]
    resources = [
        f.resource(BUCKET, category="storage", sensitivity="high", project_ref=ACCOUNT),
        f.resource(LEDGER, category="storage", sensitivity="high", project_ref=ACCOUNT),
        f.resource(
            f"arn:aws:ec2:me-central-1:{ACCOUNT}:instance/i-1", category="compute", project_ref=ACCOUNT
        ),
        f.resource(OTHER_BUCKET, category="storage", project_ref=OTHER_ACCOUNT),
    ]
    identities = [f.identity("emp-0001"), f.identity("svc-admin", identity_type="service")]
    return f.estate(identities=identities, principals=principals, resources=resources, grants=grants, **kw)


def _admin_role_grant() -> object:
    return f.grant(
        "g-admin",
        identity_id="svc-admin",
        principal_ref=ADMIN_ROLE,
        service_category="compute",
        verb="admin",
        scope_level="project",
        scope_ref=ACCOUNT,
    )


# --- pure helpers -----------------------------------------------------------


def test_scope_container_per_cloud():
    assert ag.scope_container("aws", USER) == ACCOUNT
    assert ag.scope_container("aws", ACCOUNT) == ACCOUNT
    assert ag.scope_container("aws", "*") is None
    assert (
        ag.scope_container("azure", "/subscriptions/ABC-123/resourceGroups/rg-x") == "/subscriptions/abc-123"
    )
    assert ag.scope_container("azure", "/providers/Microsoft.Management/managementGroups/mg") is None
    assert ag.scope_container("gcp", "projects/nda-analytics-prod") == "nda-analytics-prod"
    assert ag.scope_container("gcp", "etl@nda-analytics-prod.iam.gserviceaccount.com") == "nda-analytics-prod"
    assert ag.scope_container("gcp", "user:a.b@nda.example") is None
    assert ag.scope_container("gcp", "nda-analytics-prod") == "nda-analytics-prod"


def test_ref_matches_handles_trailing_wildcards():
    assert ag.ref_matches(f"{BUCKET}/x.csv", f"{BUCKET}/*")
    assert ag.ref_matches(BUCKET, BUCKET)
    assert ag.ref_matches("anything", "*")
    assert not ag.ref_matches(OTHER_BUCKET, f"{BUCKET}/*")
    assert not ag.ref_matches("anything", "")


def test_cancel_by_deny_higher_scope_cancels_allow():
    allow = f.grant("g-allow", verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*")
    deny = f.grant("g-deny", verb="write", scope_level="project", scope_ref=ACCOUNT, effect="deny")
    assert ag.cancel_by_deny([allow, deny]) == []


def test_cancel_by_deny_equal_scope_cancels_allow():
    allow = f.grant("g-allow", verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*")
    deny = f.grant("g-deny", verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*", effect="deny")
    assert ag.cancel_by_deny([allow, deny]) == []


def test_cancel_by_deny_lower_scope_does_not_cancel():
    allow = f.grant("g-allow", verb="write", scope_level="project", scope_ref=ACCOUNT)
    deny = f.grant("g-deny", verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*", effect="deny")
    assert [g.grant_id for g in ag.cancel_by_deny([allow, deny])] == ["g-allow"]


def test_cancel_by_deny_ignores_other_verb_category_or_principal():
    allow = f.grant("g-allow", verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*")
    other_verb = f.grant("g-d1", verb="delete", scope_level="global", scope_ref="*", effect="deny")
    other_cat = f.grant(
        "g-d2", verb="write", service_category="compute", scope_level="global", scope_ref="*", effect="deny"
    )
    other_principal = f.grant(
        "g-d3", principal_ref=ADMIN_ROLE, verb="write", scope_level="global", scope_ref="*", effect="deny"
    )
    inactive = f.grant("g-d4", verb="write", scope_level="global", scope_ref="*", effect="deny", active=False)
    kept = ag.cancel_by_deny([allow, other_verb, other_cat, other_principal, inactive])
    assert [g.grant_id for g in kept] == ["g-allow"]


# --- build + reachability ------------------------------------------------------


def test_read_grants_reach_nothing():
    estate = _aws_estate(
        [f.grant("g-read", principal_ref=USER, verb="read", scope_level="global", scope_ref="*")]
    )
    graph = ag.build_graph(estate)
    assert graph.reachable_resources("emp-0001") == set()
    assert graph.escalation_paths("emp-0001") == []


def test_resource_scope_reaches_prefix_matches_only():
    estate = _aws_estate(
        [f.grant("g-w", principal_ref=USER, verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*")]
    )
    graph = ag.build_graph(estate)
    assert graph.reachable_resources("emp-0001") == {BUCKET}


def test_project_scope_reaches_same_account_same_category_only():
    estate = _aws_estate(
        [f.grant("g-w", principal_ref=USER, verb="write", scope_level="project", scope_ref=ACCOUNT)]
    )
    graph = ag.build_graph(estate)
    assert graph.reachable_resources("emp-0001") == {
        BUCKET,
        LEDGER,
    }  # storage in ACCOUNT, not compute, not other account


def test_admin_ignores_category_and_org_scope_reaches_whole_cloud():
    estate = _aws_estate(
        [f.grant("g-a", principal_ref=USER, verb="admin", scope_level="org", scope_ref="o-root")]
    )
    graph = ag.build_graph(estate)
    assert graph.reachable_resources("emp-0001") == set(estate.resources)


def test_deny_cancels_allow_removes_reachability():
    allow = f.grant("g-w", principal_ref=USER, verb="write", scope_level="resource", scope_ref=f"{BUCKET}/*")
    deny = f.grant(
        "g-d", principal_ref=USER, verb="write", scope_level="project", scope_ref=ACCOUNT, effect="deny"
    )
    graph = ag.build_graph(_aws_estate([allow, deny]))
    assert graph.reachable_resources("emp-0001") == set()
    assert not graph.g.has_edge(ag.principal_node(USER), ag.resource_node(BUCKET))


def test_unknown_identity_has_no_reach_and_no_paths():
    graph = ag.build_graph(_aws_estate([]))
    assert graph.reachable_resources("nobody") == set()
    assert graph.escalation_paths("nobody") == []
    assert graph.paths_to("nobody", BUCKET) == []


# --- escalation paths -------------------------------------------------------------


def test_create_role_plus_attach_policy_at_account_scope_yields_short_escalation_path():
    grants = [
        f.grant(
            "g-create",
            principal_ref=USER,
            service_category="identity",
            verb="write",
            scope_level="project",
            scope_ref=ACCOUNT,
        ),
        f.grant(
            "g-attach",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="project",
            scope_ref=ACCOUNT,
        ),
        _admin_role_grant(),
    ]
    graph = ag.build_graph(_aws_estate(grants))
    paths = graph.escalation_paths("emp-0001")
    assert paths, "grant at account scope covers the identity's own principal → grant-self path"
    assert all(0 < len(p) <= 3 for p in paths)
    shortest = paths[0]
    assert shortest[0].src == ag.identity_node("emp-0001")
    assert {e.verb for e in shortest} <= {"grant-self", "grant", "owns"}
    assert all(e.grant_id == "g-attach" for e in shortest if e.verb != "owns")
    # the whole account is now reachable, including the high-sensitivity buckets
    assert {BUCKET, LEDGER} <= graph.reachable_resources("emp-0001")


def test_passrole_to_admin_role_yields_impersonate_path():
    grants = [
        f.grant(
            "g-pass",
            principal_ref=USER,
            service_category="identity",
            verb="impersonate",
            scope_level="resource",
            scope_ref=ADMIN_ROLE,
        ),
        _admin_role_grant(),
    ]
    graph = ag.build_graph(_aws_estate(grants))
    paths = graph.escalation_paths("emp-0001")
    assert paths
    edge = [e for e in paths[0] if e.verb != "owns"]
    assert edge == [
        PathEdge(ag.identity_node("emp-0001"), "impersonate", ag.principal_node(ADMIN_ROLE), "g-pass")
    ]
    # everything the admin role controls is reachable through the impersonation
    assert graph.reachable_resources("emp-0001") >= {BUCKET, LEDGER}


def test_impersonate_non_admin_is_not_an_escalation():
    weak_role = f"arn:aws:iam::{ACCOUNT}:role/ReadOnly"
    grants = [
        f.grant(
            "g-pass",
            principal_ref=USER,
            service_category="identity",
            verb="impersonate",
            scope_level="resource",
            scope_ref=weak_role,
        ),
        f.grant(
            "g-ro",
            identity_id="svc-admin",
            principal_ref=weak_role,
            verb="read",
            scope_level="global",
            scope_ref="*",
        ),
    ]
    graph = ag.build_graph(
        _aws_estate(
            grants, extra_principals=[f.principal(weak_role, identity_id=None, principal_type="role")]
        )
    )
    assert graph.escalation_paths("emp-0001") == []


def test_grant_over_admin_principal_is_an_escalation_of_length_one():
    grants = [
        f.grant(
            "g-attach",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="resource",
            scope_ref=ADMIN_ROLE,
        ),
        _admin_role_grant(),
    ]
    graph = ag.build_graph(_aws_estate(grants))
    paths = graph.escalation_paths("emp-0001")
    assert paths and [e.verb for e in paths[0] if e.verb != "owns"] == ["grant"]
    assert paths[0][-1].dst == ag.principal_node(ADMIN_ROLE)


def test_chain_impersonate_then_grant_composes_within_depth():
    """A impersonates P; P can rewrite the admin role Q → a two-hop escalation."""
    pivot = f"arn:aws:iam::{ACCOUNT}:role/Deployer"
    grants = [
        f.grant(
            "g-pass",
            principal_ref=USER,
            service_category="identity",
            verb="impersonate",
            scope_level="resource",
            scope_ref=pivot,
        ),
        f.grant(
            "g-pivot",
            identity_id="svc-pivot",
            principal_ref=pivot,
            service_category="identity",
            verb="grant",
            scope_level="resource",
            scope_ref=ADMIN_ROLE,
        ),
        _admin_role_grant(),
    ]
    extra = [f.principal(pivot, identity_id="svc-pivot", principal_type="role")]
    graph = ag.build_graph(_aws_estate(grants, extra_principals=extra))
    paths = graph.escalation_paths("emp-0001")
    assert paths
    verbs = [e.verb for e in paths[0] if e.verb != "owns"]
    assert verbs == ["impersonate", "grant"]
    assert graph.escalation_paths("emp-0001", max_len=1) == []
    assert graph.reachable_resources("emp-0001") >= {BUCKET, LEDGER}


def test_escalation_paths_are_deterministic_and_sorted():
    grants = [
        f.grant(
            "g-attach",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="project",
            scope_ref=ACCOUNT,
        ),
        _admin_role_grant(),
    ]
    a = ag.build_graph(_aws_estate(grants))
    b = ag.build_graph(_aws_estate(grants))
    assert a.escalation_paths("emp-0001") == b.escalation_paths("emp-0001")
    assert list(a.g.nodes) == list(b.g.nodes)
    assert list(a.g.edges(data=True)) == list(b.g.edges(data=True))
    strings = [ag.path_string(p) for p in a.escalation_paths("emp-0001")]
    assert strings == sorted(strings, key=lambda s: (s.count(";"), s))


def test_escalation_paths_prefer_shortest_and_cap_at_limit_on_dense_estates():
    """More 1-hop escalations than the cap: the result is exactly the first ESCALATION_LIMIT of them
    by path string — never a longer path ahead of a missing shorter one (iterative deepening)."""
    roles = [f"arn:aws:iam::{ACCOUNT}:role/Admin-{i:02d}" for i in range(ag.ESCALATION_LIMIT + 5)]
    principals = [f.principal(USER, identity_id="emp-0001")] + [
        f.principal(r, identity_id=None, principal_type="role") for r in roles
    ]
    grants = [
        f.grant(
            "g-org",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="org",
            scope_ref="o-root",
        )
    ] + [
        f.grant(
            f"g-admin-{i:02d}",
            identity_id=f"svc-{i:02d}",
            principal_ref=r,
            verb="admin",
            scope_level="project",
            scope_ref=ACCOUNT,
        )
        for i, r in enumerate(roles)
    ]
    estate = f.estate(identities=[f.identity("emp-0001")], principals=principals, grants=grants)
    paths = ag.build_graph(estate).escalation_paths("emp-0001")
    assert len(paths) == ag.ESCALATION_LIMIT
    assert all(len(p) == 1 and p[0].verb == "grant" and p[0].grant_id == "g-org" for p in paths)
    expected = sorted(ag.principal_node(r) for r in roles)[: ag.ESCALATION_LIMIT]
    assert [p[0].dst for p in paths] == expected


def test_escalation_paths_include_longer_routes_when_the_cap_is_not_met():
    pivot = f"arn:aws:iam::{ACCOUNT}:role/Deployer"
    grants = [
        f.grant(
            "g-attach",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="resource",
            scope_ref=ADMIN_ROLE,
        ),
        f.grant(
            "g-pass",
            principal_ref=USER,
            service_category="identity",
            verb="impersonate",
            scope_level="resource",
            scope_ref=pivot,
        ),
        f.grant(
            "g-pivot",
            identity_id="svc-pivot",
            principal_ref=pivot,
            service_category="identity",
            verb="grant",
            scope_level="resource",
            scope_ref=ADMIN_ROLE,
        ),
        _admin_role_grant(),
    ]
    extra = [f.principal(pivot, identity_id="svc-pivot", principal_type="role")]
    paths = ag.build_graph(_aws_estate(grants, extra_principals=extra)).escalation_paths("emp-0001")
    hops = [sum(1 for e in p if e.verb != "owns") for p in paths]
    assert hops == [1, 2]
    assert [e.grant_id for e in paths[1] if e.verb != "owns"] == ["g-pass", "g-pivot"]


def test_paths_to_resource_and_sample_paths():
    grants = [f.grant("g-w", principal_ref=USER, verb="write", scope_level="project", scope_ref=ACCOUNT)]
    graph = ag.build_graph(_aws_estate(grants))
    paths = graph.paths_to("emp-0001", BUCKET)
    assert paths == [
        [
            PathEdge(ag.identity_node("emp-0001"), "owns", ag.principal_node(USER), None),
            PathEdge(ag.principal_node(USER), "write", ag.resource_node(BUCKET), "g-w"),
        ]
    ]
    samples = graph.sample_paths("emp-0001")
    assert samples and samples[0][-1].dst in (ag.resource_node(BUCKET), ag.resource_node(LEDGER))


def test_linked_principal_without_grants_is_owned():
    graph = ag.build_graph(_aws_estate([]))
    assert graph.own_principals("emp-0001") == (ag.principal_node(USER),)
    assert graph.is_admin(ag.principal_node(ADMIN_ROLE)) is False


@pytest.mark.parametrize(
    ("cloud", "principal_ref", "scope_ref", "resource_ref", "project_ref"),
    [
        (
            "azure",
            "11111111-2222-3333-4444-555555555555",
            "/subscriptions/sub-a",
            "/subscriptions/sub-a/resourceGroups/rg-pay/providers/Microsoft.Storage/storageAccounts/pay",
            "/subscriptions/sub-a",
        ),
        (
            "gcp",
            "user:alia.hassan@nda.example",
            "projects/nda-analytics-prod",
            "//storage.googleapis.com/projects/nda-analytics-prod/buckets/raw",
            "nda-analytics-prod",
        ),
    ],
)
def test_project_scope_membership_for_azure_and_gcp(
    cloud, principal_ref, scope_ref, resource_ref, project_ref
):
    estate = f.estate(
        identities=[f.identity("emp-0001")],
        principals=[f.principal(principal_ref, cloud=cloud, identity_id="emp-0001")],
        resources=[f.resource(resource_ref, cloud=cloud, category="storage", project_ref=project_ref)],
        grants=[
            f.grant(
                "g-w",
                principal_ref=principal_ref,
                cloud=cloud,
                verb="write",
                scope_level="project",
                scope_ref=scope_ref,
            )
        ],
    )
    graph = ag.build_graph(estate)
    assert graph.reachable_resources("emp-0001") == {resource_ref}


def test_r5_fires_on_a_graph_escalation_path_and_cites_it():
    """Contract with the detection lane: R5 gates on `escalation_paths` and cites the path's grants."""
    from athar.detection import r5
    from athar.domain import Thresholds

    grants = [
        f.grant(
            "g-create",
            principal_ref=USER,
            service_category="identity",
            verb="write",
            scope_level="project",
            scope_ref=ACCOUNT,
        ),
        f.grant(
            "g-attach",
            principal_ref=USER,
            service_category="identity",
            verb="grant",
            scope_level="project",
            scope_ref=ACCOUNT,
        ),
        _admin_role_grant(),
    ]
    drafts = r5.evaluate(_aws_estate(grants), Thresholds())
    assert [d.identity_id for d in drafts] == ["emp-0001"]
    assert drafts[0].facts["path_len"] <= 3
    assert "g-attach" in drafts[0].facts["grant_ids"]
    assert any(e.kind == "path" for e in drafts[0].evidence)
    # no grant verb → no path → R5 stays silent even though the write-identity grant exists
    assert r5.evaluate(_aws_estate(grants[:1] + grants[2:]), Thresholds()) == []
