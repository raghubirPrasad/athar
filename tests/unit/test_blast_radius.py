"""Blast radius (SPEC §8.2): weighted share, ×3 for high sensitivity, sentence."""

from __future__ import annotations

from athar.scoring import blast_radius as br
from athar.scoring import graph as ag
from athar.scoring.constants import ScoringConstants
from tests import factories as f

ACCOUNT = "123456789012"
USER = f"arn:aws:iam::{ACCOUNT}:user/alia.hassan"


def _estate(reach_high: bool):
    resources = [
        f.resource("arn:aws:s3:::high-1", sensitivity="high", project_ref=ACCOUNT),
        f.resource("arn:aws:s3:::low-1", project_ref=ACCOUNT),
        f.resource("arn:aws:s3:::low-2", project_ref=ACCOUNT),
        f.resource("arn:aws:s3:::low-3", project_ref=ACCOUNT),
    ]
    target = "arn:aws:s3:::high-1" if reach_high else "arn:aws:s3:::low-1"
    grants = [f.grant("g-w", principal_ref=USER, verb="write", scope_level="resource", scope_ref=target)]
    return f.estate(
        identities=[f.identity("emp-0001")],
        principals=[f.principal(USER, identity_id="emp-0001")],
        resources=resources,
        grants=grants,
    )


def test_high_sensitivity_counts_three_times():
    graph = ag.build_graph(_estate(reach_high=True))
    result = br.compute(graph, "emp-0001")
    assert result.total == 4
    assert result.weighted_total == 6.0  # 3 + 1 + 1 + 1
    assert result.reachable == 1
    assert result.high_sensitivity == 1
    assert result.weighted_reachable == 3.0
    assert result.share == 0.5


def test_low_sensitivity_counts_once():
    graph = ag.build_graph(_estate(reach_high=False))
    result = br.compute(graph, "emp-0001")
    assert result.weighted_reachable == 1.0
    assert result.share == 1.0 / 6.0
    assert result.high_sensitivity == 0


def test_weight_is_a_scoring_constant():
    graph = ag.build_graph(_estate(reach_high=True))
    result = br.compute(graph, "emp-0001", ScoringConstants(high_sensitivity_weight=1.0))
    assert result.share == 0.25


def test_sentence_format():
    graph = ag.build_graph(_estate(reach_high=True))
    assert (
        br.compute(graph, "emp-0001").sentence()
        == "can reach 50% of the estate (1 high-sensitivity resource)"
    )
    assert (
        br.compute(graph, "nobody").sentence() == "can reach 0% of the estate (0 high-sensitivity resources)"
    )


def test_empty_estate_gives_zero_share_without_division_error():
    graph = ag.build_graph(f.estate(identities=[f.identity("emp-0001")]))
    result = br.compute(graph, "emp-0001")
    assert result.share == 0.0 and result.total == 0 and result.sample_paths == []


def test_sample_paths_lead_to_reached_resources():
    graph = ag.build_graph(_estate(reach_high=True))
    result = br.compute(graph, "emp-0001")
    assert result.sample_paths and result.sample_paths[0][-1].dst == ag.resource_node("arn:aws:s3:::high-1")
    assert result.as_dict()["sample_paths"][0][-1]["grant_id"] == "g-w"
