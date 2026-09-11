"""Risk score (SPEC §8.3): formula, floor, line items, decoy credits, bounds, performance."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from datetime import date

import networkx as nx
from athar.detection.base import EvidenceRef, FindingDraft
from athar.domain import SEVERITY_FLOOR, SEVERITY_RANK, EstateView, severity_band
from athar.scoring import graph as ag
from athar.scoring import score as sc
from athar.scoring.constants import DEFAULT, ScoringConstants
from athar.scoring.types import PathEdge
from hypothesis import given, settings
from hypothesis import strategies as st
from tests import factories as f

ACCOUNT = "123456789012"
USER = f"arn:aws:iam::{ACCOUNT}:user/alia.hassan"
TERMS = {"reach", "exploitability", "compensating", "formula", "floor", "final"}


def _draft(rule_id: str, severity: str, identity_id: str = "emp-0001", **facts) -> FindingDraft:
    return FindingDraft(rule_id, identity_id, severity, [EvidenceRef("grant", "g-1")], [], dict(facts))


@dataclass
class StubGraph(ag.AccessGraph):
    """An AccessGraph whose reachability is dictated, so the formula can be tested in isolation."""

    reached: set[str] = field(default_factory=set)

    def reachable_resources(self, identity_id: str, max_depth: int = ag.MAX_DEPTH) -> set[str]:
        return set(self.reached)

    def sample_paths(self, identity_id: str, max_depth: int = ag.MAX_DEPTH) -> list[list[PathEdge]]:
        return []

    def escalation_paths(
        self, identity_id: str, max_len: int = ag.ESCALATION_MAX_LEN
    ) -> list[list[PathEdge]]:
        return []


def _resources(n_high: int, n_low: int) -> list:
    return [f.resource(f"arn:aws:s3:::high-{i}", sensitivity="high") for i in range(n_high)] + [
        f.resource(f"arn:aws:s3:::low-{i}") for i in range(n_low)
    ]


def _stub(estate: EstateView, reached: set[str]) -> StubGraph:
    return StubGraph(g=nx.DiGraph(), estate=estate, reached=reached)


# --- the worked example --------------------------------------------------------


def test_worked_example_departed_dormant_floor_from_r3_gives_75():
    """68 from the formula, floor from R3 = 75 → 75 (SPEC §8.3 transparency paragraph).

    Share 0.095 → reach 0.38; departed +0.5 and dormant +0.3 → exploitability 1.8; no controls.
    # SPEC? the paragraph quotes reach 0.76 × 1.8 = 68, but 100 × 0.76 × 1.8 is 136.8; the formula
    # line is the contract, so the example is reproduced with reach 0.38.
    """
    estate = f.estate(
        identities=[f.identity("emp-0001", employment_status="departed", departure_month=11)],
        resources=_resources(6, 182),  # weighted total 200; 6 high + 1 low reached = 19 → 9.5%
    )
    graph = _stub(estate, {f"arn:aws:s3:::high-{i}" for i in range(6)} | {"arn:aws:s3:::low-0"})
    fired = [_draft("R3", "Critical"), _draft("R2", "Medium")]
    result = sc.score_identity(estate, "emp-0001", fired, graph)
    assert result.blast_radius == 0.095
    assert result.high_sensitivity_reached == 6
    assert result.reach == 0.38
    assert result.exploitability == 1.8
    assert result.compensating == 0.0
    assert result.formula_score == 68.4
    assert result.rule_floor == 75
    assert result.score == 75
    assert result.severity == "Critical"
    labels = [li.label for li in result.line_items]
    assert "departed +0.5" in labels and "dormant +0.3" in labels
    assert [li.label for li in result.line_items if li.term == "floor"] == ["R3"]


def test_worked_example_renders_through_the_narrative_score_line():
    from athar.narrative.templates import render_score_line

    estate = f.estate(
        identities=[f.identity("emp-0001", employment_status="departed", departure_month=11)],
        resources=_resources(6, 182),
    )
    graph = _stub(estate, {f"arn:aws:s3:::high-{i}" for i in range(6)} | {"arn:aws:s3:::low-0"})
    result = sc.score_identity(estate, "emp-0001", [_draft("R3", "Critical"), _draft("R2", "Medium")], graph)
    assert render_score_line(result) == (
        "reach 0.38 (blast radius 10% of estate, 6 high-sensitivity resources) "
        "× exploitability 1.8 (departed +0.5, dormant +0.3) × controls 1.0 = 68 "
        "· floor from R3 = 75 → 75"
    )


def test_departed_identity_with_narrow_access_is_critical_via_floor():
    estate = f.estate(
        identities=[f.identity("emp-0001", employment_status="departed", departure_month=10)],
        resources=_resources(0, 100),
    )
    result = sc.score_identity(
        estate, "emp-0001", [_draft("R3", "Critical")], _stub(estate, {"arn:aws:s3:::low-0"})
    )
    assert result.formula_score == 6.0  # 100 × 0.04 × 1.5
    assert result.score == 75 and result.severity == "Critical"
    final = result.line_items[-1]
    assert final.term == "final" and final.detail["floored"] is True


def test_no_findings_still_scores_from_blast_radius():
    estate = f.estate(identities=[f.identity("emp-0001")], resources=_resources(0, 4))
    result = sc.score_identity(
        estate, "emp-0001", [], _stub(estate, {"arn:aws:s3:::low-0", "arn:aws:s3:::low-1"})
    )
    assert result.blast_radius == 0.5 and result.reach == 1.0
    assert result.score == 100 and result.rule_floor == 0
    assert [li.label for li in result.line_items if li.term == "floor"] == ["none"]


# --- exploitability increments ------------------------------------------------------


def test_no_mfa_increment_applies_to_humans_only():
    estate = f.estate(
        identities=[
            f.identity("h", mfa_enforced=False),
            f.identity("s", identity_type="service", mfa_enforced=False),
        ],
        resources=_resources(0, 4),
    )
    graph = _stub(estate, {"arn:aws:s3:::low-0"})
    assert sc.score_identity(estate, "h", [_draft("R9", "High", "h")], graph).exploitability == 1.3
    assert sc.score_identity(estate, "s", [_draft("R9", "High", "s")], graph).exploitability == 1.0


def test_external_or_contractor_increment():
    estate = f.estate(
        identities=[f.identity("c", employment_type="contractor"), f.identity("x", external=True)],
        resources=_resources(0, 4),
    )
    graph = _stub(estate, set())
    assert sc.score_identity(estate, "c", [], graph).exploitability == 1.2
    assert sc.score_identity(estate, "x", [], graph).exploitability == 1.2


def test_service_account_long_lived_key_increment():
    old = date(2025, 9, 1)  # month-12 end is 2026-08-31 → 364 days
    estate = f.estate(
        identities=[f.identity("svc", identity_type="service"), f.identity("h")],
        resources=_resources(0, 4),
        credentials=[
            f.credential(
                "gcp:sa_key:1",
                identity_id="svc",
                cloud="gcp",
                kind="sa_key",
                last_rotated_at=old,
                created_at=old,
            ),
            f.credential("aws:key:2", identity_id="h", kind="key", last_rotated_at=old, created_at=old),
        ],
    )
    graph = _stub(estate, set())
    svc = sc.score_identity(estate, "svc", [], graph)
    assert svc.exploitability == 1.2
    item = next(li for li in svc.line_items if li.label.startswith("long-lived key"))
    assert item.detail == {"credential_ref": "gcp:sa_key:1", "threshold_days": 180}
    assert sc.score_identity(estate, "h", [], graph).exploitability == 1.0  # humans: not this term


def test_fresh_or_inactive_key_does_not_count_as_long_lived():
    recent = date(2026, 6, 1)
    estate = f.estate(
        identities=[f.identity("svc", identity_type="service")],
        credentials=[
            f.credential("k-fresh", identity_id="svc", kind="key", last_rotated_at=recent, created_at=recent),
            f.credential(
                "k-old-off", identity_id="svc", kind="key", last_rotated_at=date(2025, 9, 1), active=False
            ),
            f.credential("pw", identity_id="svc", kind="password", last_rotated_at=date(2025, 9, 1)),
        ],
    )
    assert sc.score_identity(estate, "svc", [], _stub(estate, set())).exploitability == 1.0


def test_cross_cloud_and_dormant_increments_come_from_fired_rules():
    estate = f.estate(identities=[f.identity("emp-0001")])
    graph = _stub(estate, set())
    result = sc.score_identity(estate, "emp-0001", [_draft("R4", "Critical"), _draft("R2", "Medium")], graph)
    assert result.exploitability == 1.5
    assert result.rule_floor == 75


def test_drafts_of_other_identities_are_ignored():
    estate = f.estate(identities=[f.identity("emp-0001"), f.identity("emp-0002")])
    result = sc.score_identity(
        estate, "emp-0001", [_draft("R3", "Critical", "emp-0002")], _stub(estate, set())
    )
    assert result.rule_floor == 0 and result.score == 0


# --- compensating controls (register only, never tags) -----------------------------


def test_decoy_break_glass_with_mfa_gets_035():
    estate = f.estate(
        identities=[f.identity("bg", mfa_enforced=True, tags={"exception": "break-glass"})],
        exceptions=[f.exception("bg", "break-glass", review_date=date(2027, 1, 1))],
        resources=_resources(0, 4),
    )
    result = sc.score_identity(
        estate, "bg", [_draft("R1", "High", "bg")], _stub(estate, {"arn:aws:s3:::low-0"})
    )
    assert result.compensating == 0.35
    assert result.formula_score == 65.0  # 100 × 1.0 × 1.0 × 0.65
    labels = [li.label for li in result.line_items if li.term == "compensating"]
    assert labels == ["break-glass (register, MFA enforced) −0.35", "controls 0.65"]


def test_break_glass_without_mfa_gets_no_credit():
    estate = f.estate(
        identities=[f.identity("bg", mfa_enforced=False)],
        exceptions=[f.exception("bg", "break-glass")],
    )
    result = sc.score_identity(estate, "bg", [], _stub(estate, set()))
    assert result.compensating == 0.0
    assert [li.label for li in result.line_items if li.term == "compensating"] == ["none", "controls 1.0"]


def test_cloud_tag_alone_is_never_a_compensating_control():
    estate = f.estate(identities=[f.identity("bg", mfa_enforced=True, tags={"exception": "break-glass"})])
    assert sc.score_identity(estate, "bg", [], _stub(estate, set())).compensating == 0.0


def test_expired_register_entry_gives_no_credit():
    estate = f.estate(
        identities=[f.identity("bg", mfa_enforced=True)],
        exceptions=[f.exception("bg", "break-glass", review_date=date(2026, 1, 1))],
    )
    assert sc.score_identity(estate, "bg", [], _stub(estate, set())).compensating == 0.0


def test_time_boxed_contract_credit_only_while_unexpired():
    estate = f.estate(
        month=12,
        identities=[
            f.identity("live", employment_type="contractor", contract_end_month=12),
            f.identity("gone", employment_type="contractor", contract_end_month=11),
        ],
    )
    graph = _stub(estate, set())
    live = sc.score_identity(estate, "live", [], graph)
    assert live.compensating == 0.2 and live.exploitability == 1.2
    assert sc.score_identity(estate, "gone", [], graph).compensating == 0.0


def test_approved_role_and_dr_failover_credit_015():
    estate = f.estate(
        identities=[f.identity("pa"), f.identity("dr", identity_type="service")],
        exceptions=[
            f.exception("pa", "approved-privileged-role", exception_id="exc-pa"),
            f.exception("dr", "dr-failover", exception_id="exc-dr"),
        ],
    )
    graph = _stub(estate, set())
    assert sc.score_identity(estate, "pa", [], graph).compensating == 0.15
    assert sc.score_identity(estate, "dr", [], graph).compensating == 0.15


def test_credits_stack():
    estate = f.estate(
        identities=[f.identity("x", mfa_enforced=True, employment_type="contractor", contract_end_month=12)],
        exceptions=[
            f.exception("x", "break-glass", exception_id="e1"),
            f.exception("x", "dr-failover", exception_id="e2"),
        ],
    )
    result = sc.score_identity(estate, "x", [], _stub(estate, set()))
    assert result.compensating == 0.7


# --- transparency ---------------------------------------------------------------------


def test_every_term_is_a_line_item_with_a_stage_summary():
    estate = f.estate(
        identities=[f.identity("emp-0001", employment_status="departed", mfa_enforced=True)],
        exceptions=[f.exception("emp-0001", "break-glass")],
        resources=_resources(1, 3),
    )
    result = sc.score_identity(
        estate, "emp-0001", [_draft("R3", "Critical")], _stub(estate, {"arn:aws:s3:::high-0"})
    )
    assert {li.term for li in result.line_items} == TERMS
    for term in TERMS:
        assert any(li.term == term for li in result.line_items)
    by_term = {term: [li.label for li in result.line_items if li.term == term] for term in TERMS}
    assert by_term["exploitability"] == ["base", "departed +0.5", "exploitability 1.5"]
    assert by_term["compensating"][-1] == "controls 0.65"
    assert by_term["formula"] == ["100 × reach × exploitability × controls"]
    assert by_term["final"] == [result.severity]
    assert all(isinstance(li.as_dict()["detail"], dict) for li in result.line_items)


def test_constants_are_the_only_source_of_numbers():
    estate = f.estate(
        identities=[f.identity("emp-0001", employment_status="departed")], resources=_resources(0, 4)
    )
    tuned = ScoringConstants(
        ref_share=0.5, departed=1.0, floors={"Critical": 90, "High": 50, "Medium": 25, "Low": 0}
    )
    result = sc.score_identity(
        estate, "emp-0001", [_draft("R3", "Critical")], _stub(estate, {"arn:aws:s3:::low-0"}), tuned
    )
    assert (
        result.reach == 0.5
        and result.exploitability == 2.0
        and result.rule_floor == 90
        and result.score == 100
    )
    assert DEFAULT.floors == SEVERITY_FLOOR


def test_score_all_covers_every_identity_and_draft_only_identities():
    estate = f.estate(identities=[f.identity("a"), f.identity("b")], resources=_resources(0, 2))
    graph = _stub(estate, {"arn:aws:s3:::low-0"})
    drafts = {"b": [_draft("R1", "High", "b")], "unlinked:aws:x": [_draft("R10", "Medium", "unlinked:aws:x")]}
    results = sc.score_all(estate, drafts, graph)
    assert list(results) == ["a", "b", "unlinked:aws:x"]
    assert (
        results["a"].rule_floor == 0
        and results["b"].rule_floor == 50
        and results["unlinked:aws:x"].rule_floor == 25
    )
    assert all(r.score >= r.rule_floor for r in results.values())


# --- property: bounds, floor, sort order -------------------------------------------


@settings(max_examples=150, deadline=None)
@given(
    share=st.floats(min_value=0.0, max_value=1.0),
    departed=st.booleans(),
    contractor=st.booleans(),
    human=st.booleans(),
    mfa=st.booleans(),
    break_glass=st.booleans(),
    fired=st.lists(st.sampled_from(["R1", "R2", "R3", "R4", "R5", "R9"]), max_size=4, unique=True),
)
def test_score_is_bounded_floored_and_consistent_with_its_band(
    share, departed, contractor, human, mfa, break_glass, fired
):
    severities = {
        "R1": "High",
        "R2": "Medium",
        "R3": "Critical",
        "R4": "Critical",
        "R5": "High",
        "R9": "High",
    }
    estate = f.estate(
        identities=[
            f.identity(
                "x",
                identity_type="human" if human else "service",
                employment_status="departed" if departed else "active",
                employment_type="contractor" if contractor else "staff",
                mfa_enforced=mfa,
            )
        ],
        exceptions=[f.exception("x", "break-glass")] if break_glass else [],
        resources=_resources(0, 100),
    )
    reached = {f"arn:aws:s3:::low-{i}" for i in range(round(share * 100))}
    drafts = [_draft(r, severities[r], "x") for r in fired]
    result = sc.score_identity(estate, "x", drafts, _stub(estate, reached))
    assert 0 <= result.score <= 100
    expected_floor = max([SEVERITY_FLOOR[severities[r]] for r in fired], default=0)
    assert result.rule_floor == expected_floor
    assert result.score >= expected_floor
    assert result.severity == severity_band(result.score)
    assert SEVERITY_RANK[result.severity] >= max([SEVERITY_RANK[severities[r]] for r in fired], default=0)
    assert 1.0 <= result.exploitability <= 2.5 and 0.0 <= result.compensating <= 0.7


def test_sort_by_score_agrees_with_severity_column():
    estate = f.estate(
        identities=[
            f.identity("narrow", employment_status="departed"),
            f.identity("wide"),
            f.identity("mid"),
        ],
        resources=_resources(0, 100),
    )
    results = {
        "narrow": sc.score_identity(
            estate, "narrow", [_draft("R3", "Critical", "narrow")], _stub(estate, {"arn:aws:s3:::low-0"})
        ),
        "wide": sc.score_identity(
            estate, "wide", [], _stub(estate, {f"arn:aws:s3:::low-{i}" for i in range(15)})
        ),
        "mid": sc.score_identity(estate, "mid", [_draft("R1", "High", "mid")], _stub(estate, set())),
    }
    ordered = sorted(results.values(), key=sc.sort_key)
    ranks = [SEVERITY_RANK[r.severity] for r in ordered]
    assert ranks == sorted(ranks, reverse=True)
    assert [r.identity_id for r in ordered] == ["narrow", "wide", "mid"]


# --- performance on a 500 × 1500 × 300 synthetic estate --------------------------------


def synthetic_estate(
    seed: int = 7, identities: int = 500, grants: int = 1500, resources: int = 300
) -> EstateView:
    rng = random.Random(seed)
    clouds = ("aws", "azure", "gcp")
    containers = {
        "aws": ["123456789012", "210987654321"],
        "azure": [
            "/subscriptions/aaaaaaaa-0000-0000-0000-000000000001",
            "/subscriptions/bbbbbbbb-0000-0000-0000-000000000002",
        ],
        "gcp": ["nda-analytics-prod", "nda-smart-dev"],
    }
    categories = ("compute", "storage", "network", "identity", "data", "security", "billing")
    verbs = (
        ["read"] * 5 + ["write"] * 4 + ["delete"] * 2 + ["admin"] + ["grant"] + ["impersonate"] + ["billing"]
    )
    levels = ["resource"] * 5 + ["project"] * 3 + ["org"] + ["global"]

    ids = [
        f.identity(f"emp-{i:04d}", identity_type="service" if i % 4 == 0 else "human")
        for i in range(identities)
    ]
    principals = []
    principal_of: dict[tuple[str, str], str] = {}
    for i in range(identities):
        for cloud in rng.sample(clouds, k=rng.choice((1, 1, 2, 3))):
            container = rng.choice(containers[cloud])
            if cloud == "aws":
                ref = f"arn:aws:iam::{container}:user/u{i:04d}"
            elif cloud == "azure":
                ref = f"{i:08x}-0000-4000-8000-{rng.getrandbits(48):012x}"
            else:
                ref = f"user:u{i:04d}@nda.example"
            principals.append(
                f.principal(ref, cloud=cloud, identity_id=f"emp-{i:04d}", raw={"scope": container})
            )
            principal_of[(f"emp-{i:04d}", cloud)] = ref

    res = []
    for j in range(resources):
        cloud = clouds[j % 3]
        container = rng.choice(containers[cloud])
        cat = rng.choice(categories)
        if cloud == "aws":
            ref = f"arn:aws:{cat}:me-central-1:{container}:thing/{j}"
        elif cloud == "azure":
            ref = f"{container}/resourceGroups/rg-{j}/providers/Microsoft.{cat}/x{j}"
        else:
            ref = f"//{cat}.googleapis.com/projects/{container}/things/{j}"
        res.append(
            f.resource(
                ref,
                cloud=cloud,
                category=cat,
                project_ref=container,
                sensitivity="high" if j % 7 == 0 else "low",
            )
        )

    keyed = list(principal_of.items())
    rows = []
    for k in range(grants):
        (identity_id, cloud), pref = rng.choice(keyed)
        level = rng.choice(levels)
        container = rng.choice(containers[cloud])
        target_resource = rng.choice([r for r in res if r.cloud == cloud])
        verb = rng.choice(verbs)
        if level == "resource":
            scope = (
                rng.choice([p for (_, c), p in keyed if c == cloud])
                if verb in ("grant", "impersonate")
                else target_resource.resource_ref
            )
        elif level == "project":
            scope = container
        else:
            scope = "*" if level == "global" else f"org-{cloud}"
        rows.append(
            f.grant(
                f"g-{k:05d}",
                identity_id=identity_id,
                principal_ref=pref,
                cloud=cloud,
                service_category=rng.choice(categories),
                verb=verb,
                scope_level=level,
                scope_ref=scope,
                effect="deny" if rng.random() < 0.03 else "allow",
            )
        )
    return f.estate(identities=ids, principals=principals, resources=res, grants=rows)


def test_build_graph_and_score_all_500_identities_under_five_seconds():
    estate = synthetic_estate()
    assert len(estate.identities) == 500 and len(estate.grants) == 1500 and len(estate.resources) == 300
    started = time.perf_counter()
    graph = ag.build_graph(estate)
    results = sc.score_all(estate, {}, graph)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"took {elapsed:.2f}s"
    assert len(results) == 500
    assert any(r.escalation_paths for r in results.values()), (
        "a 1500-grant estate has at least one escalation"
    )
    assert all(0 <= r.score <= 100 and r.severity == severity_band(r.score) for r in results.values())


def test_synthetic_estate_scores_are_deterministic():
    a = sc.score_all(synthetic_estate(), {}, ag.build_graph(synthetic_estate()))
    b = sc.score_all(synthetic_estate(), {}, ag.build_graph(synthetic_estate()))
    assert {k: (v.score, v.line_items_json(), v.paths_json()) for k, v in a.items()} == {
        k: (v.score, v.line_items_json(), v.paths_json()) for k, v in b.items()
    }
