"""R5 Toxic combination (SPEC §7, §8.1): fires only when the graph shows a ≤ 3-hop self-escalation path.

Lane B's graph is monkeypatched through `athar.detection.r5.access_graph.build_graph`
except in the two `real_graph` tests, which exercise the actual `athar.scoring.graph`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from athar.domain import EstateView
from athar.scoring.types import PathEdge
from test_rules_support import (
    AWS_ACCT,
    AWS_BUCKET,
    AWS_ROLE,
    AWS_USER,
    access_graph,
    f,
    fake_build_graph,
    grant_path,
    run,
    wide_grant,
)


def _patch(monkeypatch: pytest.MonkeyPatch, paths: dict[str, list[list[PathEdge]]]):  # type: ignore[no-untyped-def]
    build = fake_build_graph(paths)
    monkeypatch.setattr(access_graph, "build_graph", build)
    return build.graph  # type: ignore[attr-defined]


def _write_identity_and_grant(*extra) -> EstateView:  # type: ignore[no-untyped-def]
    return f.estate(
        identities=[f.identity()],
        principals=[f.principal(AWS_USER)],
        grants=[
            wide_grant("g-w", "aws", "write", service_category="identity"),
            wide_grant("g-g", "aws", "grant", service_category="identity"),
            *extra,
        ],
    )


def test_write_identity_and_grant_with_path_fires_high(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    drafts = run("R5", _write_identity_and_grant())
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "High" and d.facts["combination"] == "write_identity+grant"
    assert d.facts["path_len"] == 1 and d.facts["grant_ids"] == ["g-g", "g-w"]
    assert d.facts["path"] == [
        {"src": "id:emp-0001", "verb": "grant", "dst": f"p:{AWS_ROLE}", "grant_id": "g-g"}
    ]


def test_path_is_the_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    refs = {(e.kind, e.ref) for e in run("R5", _write_identity_and_grant())[0].evidence}
    assert ("path", f"id:emp-0001->p:{AWS_ROLE}") in refs
    assert ("grant", "g-g") in refs and ("grant", "g-w") in refs


def test_no_path_does_not_fire(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {})
    assert run("R5", _write_identity_and_grant()) == []


def test_path_longer_than_three_hops_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    long_path = [
        PathEdge("id:emp-0001", "grant", "p:a", "g-g"),
        PathEdge("p:a", "grant", "p:b", "g-2"),
        PathEdge("p:b", "grant", "p:c", "g-3"),
        PathEdge("p:c", "grant", "p:d", "g-4"),
    ]
    _patch(monkeypatch, {"emp-0001": [long_path]})
    assert run("R5", _write_identity_and_grant()) == []


def test_owns_edge_does_not_cost_a_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    path = [
        PathEdge("id:emp-0001", "owns", f"p:{AWS_USER}", None),
        PathEdge(f"p:{AWS_USER}", "grant", "p:a", "g-g"),
        PathEdge("p:a", "grant", "p:b", "g-2"),
        PathEdge("p:b", "grant", f"p:{AWS_ROLE}", "g-3"),
    ]
    _patch(monkeypatch, {"emp-0001": [path]})
    drafts = run("R5", _write_identity_and_grant())
    assert len(drafts) == 1 and drafts[0].facts["path_len"] == 3
    assert len(drafts[0].facts["path"]) == 4


def test_shortest_path_is_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    two = [PathEdge("id:emp-0001", "grant", "p:a", "g-g"), PathEdge("p:a", "grant", f"p:{AWS_ROLE}", "g-2")]
    _patch(monkeypatch, {"emp-0001": [two, grant_path("emp-0001", "g-g")]})
    assert run("R5", _write_identity_and_grant())[0].facts["path_len"] == 1


def test_grants_on_the_path_are_cited_too(monkeypatch: pytest.MonkeyPatch) -> None:
    other = f.grant(
        "g-x",
        identity_id="emp-0002",
        principal_ref=AWS_ROLE,
        verb="admin",
        scope_level="project",
        scope_ref=AWS_ACCT,
    )
    est = _write_identity_and_grant(other)
    est.identities["emp-0002"] = f.identity("emp-0002")
    path = [
        PathEdge("id:emp-0001", "grant", f"p:{AWS_ROLE}", "g-g"),
        PathEdge(f"p:{AWS_ROLE}", "admin", f"r:{AWS_BUCKET}", "g-x"),
    ]
    _patch(monkeypatch, {"emp-0001": [path]})
    assert run("R5", est)[0].facts["grant_ids"] == ["g-g", "g-w", "g-x"]


def test_write_identity_without_grant_does_not_call_the_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(estate: EstateView) -> None:
        raise AssertionError("graph must not be built without a candidate")

    monkeypatch.setattr(access_graph, "build_graph", boom)
    est = f.estate(
        identities=[f.identity()], grants=[wide_grant("g-w", "aws", "write", service_category="identity")]
    )
    assert run("R5", est) == []


def test_non_overlapping_scopes_are_not_a_combination(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    est = f.estate(
        identities=[f.identity()],
        grants=[
            f.grant(
                "g-w", verb="write", service_category="identity", scope_ref="arn:aws:iam::111111111111:role/a"
            ),
            f.grant(
                "g-g", verb="grant", service_category="identity", scope_ref="arn:aws:iam::222222222222:role/b"
            ),
        ],
    )
    assert run("R5", est) == [] and graph.calls == []


def test_write_identity_and_grant_across_clouds_is_not_a_combination(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    est = f.estate(
        identities=[f.identity()],
        grants=[
            wide_grant("g-w", "aws", "write", service_category="identity"),
            f.grant(
                "g-g",
                cloud="gcp",
                verb="grant",
                service_category="identity",
                scope_ref="projects/p/serviceAccounts/x",
            ),
        ],
    )
    assert run("R5", est) == [] and graph.calls == []


def test_wide_grant_alone_is_a_grant_self_candidate_gated_by_the_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    est = f.estate(
        identities=[f.identity()], grants=[wide_grant("g-g", "aws", "grant", service_category="identity")]
    )
    graph = _patch(monkeypatch, {})
    assert run("R5", est) == [] and graph.calls == [("emp-0001", 3)]
    _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    assert run("R5", est)[0].facts["combination"] == "grant_self"


def test_impersonate_target_holding_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    est = f.estate(
        identities=[f.identity(), f.identity("emp-0002")],
        principals=[
            f.principal(AWS_USER),
            f.principal(AWS_ROLE, identity_id="emp-0002", principal_type="role"),
        ],
        grants=[
            f.grant("g-imp", verb="impersonate", service_category="identity", scope_ref=AWS_ROLE),
            wide_grant("g-adm", "aws", "admin", identity_id="emp-0002", principal_ref=AWS_ROLE),
        ],
    )
    _patch(monkeypatch, {"emp-0001": [[PathEdge("id:emp-0001", "impersonate", f"p:{AWS_ROLE}", "g-imp")]]})
    drafts = run("R5", est)
    assert len(drafts) == 1 and drafts[0].facts["combination"] == "impersonate+admin"
    assert drafts[0].facts["grant_ids"] == ["g-adm", "g-imp"]


def test_impersonate_target_without_admin_does_not_fire(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _patch(
        monkeypatch, {"emp-0001": [[PathEdge("id:emp-0001", "impersonate", f"p:{AWS_ROLE}", "g-imp")]]}
    )
    est = f.estate(
        identities=[f.identity()],
        grants=[f.grant("g-imp", verb="impersonate", service_category="identity", scope_ref=AWS_ROLE)],
    )
    assert run("R5", est) == [] and graph.calls == []


def test_grant_reaching_own_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    est = f.estate(
        identities=[f.identity()],
        principals=[f.principal(AWS_USER)],
        grants=[f.grant("g-self", verb="grant", service_category="identity", scope_ref=AWS_USER)],
    )
    _patch(monkeypatch, {"emp-0001": [[PathEdge("id:emp-0001", "grant-self", f"r:{AWS_BUCKET}", "g-self")]]})
    drafts = run("R5", est)
    assert len(drafts) == 1 and drafts[0].facts["combination"] == "grant_self"


def test_max_len_three_is_requested_from_the_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _patch(monkeypatch, {"emp-0001": [grant_path("emp-0001", "g-g")]})
    run("R5", _write_identity_and_grant())
    assert graph.calls == [("emp-0001", 3)]


def test_real_graph_write_identity_and_grant_at_account_scope() -> None:
    """Integration with lane B: a `grant` at account scope reaches the identity's own principal."""
    est = f.estate(
        identities=[f.identity(), f.identity("emp-0002")],
        principals=[
            f.principal(AWS_USER),
            f.principal(AWS_ROLE, identity_id="emp-0002", principal_type="role"),
        ],
        grants=[
            wide_grant("g-g", "aws", "grant", service_category="identity"),
            wide_grant("g-adm", "aws", "admin", identity_id="emp-0002", principal_ref=AWS_ROLE),
            wide_grant("g-w", "aws", "write", service_category="identity"),
        ],
        resources=[f.resource(AWS_BUCKET, project_ref=AWS_ACCT, sensitivity="high")],
    )
    drafts = run("R5", est)
    assert len(drafts) == 1
    assert drafts[0].facts["combination"] == "write_identity+grant"
    assert 1 <= drafts[0].facts["path_len"] <= 3
    assert "g-g" in drafts[0].facts["grant_ids"]


def test_real_graph_impersonate_admin_role() -> None:
    est = f.estate(
        identities=[f.identity(), f.identity("emp-0002")],
        principals=[
            f.principal(AWS_USER),
            f.principal(AWS_ROLE, identity_id="emp-0002", principal_type="role"),
        ],
        grants=[
            f.grant("g-imp", verb="impersonate", service_category="identity", scope_ref=AWS_ROLE),
            wide_grant("g-adm", "aws", "admin", identity_id="emp-0002", principal_ref=AWS_ROLE),
        ],
        resources=[f.resource(AWS_BUCKET, project_ref=AWS_ACCT, sensitivity="high")],
    )
    drafts = run("R5", est)
    assert len(drafts) == 1 and drafts[0].facts["combination"] == "impersonate+admin"
    assert drafts[0].facts["path"][0]["verb"] == "impersonate"


def test_deterministic_sorted_and_facts_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        grants=[
            wide_grant("g-b-w", "aws", "write", identity_id="emp-0002", service_category="identity"),
            wide_grant("g-b-g", "aws", "grant", identity_id="emp-0002", service_category="identity"),
            wide_grant("g-a-w", "aws", "write", identity_id="emp-0001", service_category="identity"),
            wide_grant("g-a-g", "aws", "grant", identity_id="emp-0001", service_category="identity"),
        ],
    )
    _patch(
        monkeypatch,
        {"emp-0001": [grant_path("emp-0001", "g-a-g")], "emp-0002": [grant_path("emp-0002", "g-b-g")]},
    )
    a, b = run("R5", est), run("R5", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R5", d.facts) == [] for d in a)
