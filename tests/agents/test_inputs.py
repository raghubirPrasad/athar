"""Agent inputs (SPEC §11.3/§11.4) are built only from canonical facts, with provider text wrapped."""

from __future__ import annotations

from datetime import date
from typing import get_args

from athar.agents.guard import is_wrapped
from athar.agents.inputs import (
    CANONICAL_EVIDENCE_KINDS,
    CANONICAL_SLOTS,
    PROVIDER_TEXT_SLOTS,
    activity_window,
    build_investigate_input,
    build_plan_input,
    build_summary_input,
    citation_values,
    payload,
    redact_headline,
    sanitize_citations,
    sanitize_facts,
)
from athar.detection.base import EvidenceKind, FindingDraft
from athar.detection.facts import COMMON_SLOTS, RULE_SLOTS
from athar.domain import EstateView
from athar.drift.types import CausalStep, HalfLifeRow
from athar.hashing import finding_key
from athar.scoring.types import ScoreResult

from tests import factories as f
from tests.agents.conftest import HOSTILE_NAME, HOSTILE_NOTE, rule_spec


def _score(identity_id: str = "emp-0042") -> ScoreResult:
    return ScoreResult(
        identity_id=identity_id,
        blast_radius=0.42,
        reachable_resources=10,
        high_sensitivity_reached=3,
        reach=0.5,
        exploitability=0.7,
        compensating=0.1,
        formula_score=81.0,
        rule_floor=80,
        score=81,
        severity="Critical",
        line_items=[],
        escalation_paths=[],
    )


def _causal() -> list[CausalStep]:
    return [
        CausalStep(
            3,
            "ev-0001",
            "grant",
            "role_change",
            "aws",
            f"AWS admin added ({HOSTILE_NOTE})",
            {"added": ["g-002"]},
        ),
        CausalStep(9, "ev-0002", "departure", "departure", None, "Employee departed", {}),
    ]


# --- sanitize_facts -----------------------------------------------------------


def test_sanitize_facts_wraps_provider_keys_and_passes_canonical_through() -> None:
    facts = {
        "display_name": HOSTILE_NAME,
        "note": HOSTILE_NOTE,
        "tags": {"note": HOSTILE_NOTE, "owner": "ops@nda.example"},
        "grant_ids": ["g-001"],
        "months_since_departure": 3,
        "clouds": ["aws"],
        "project_id": None,
    }
    out = sanitize_facts(facts)
    assert out["display_name"] == {"untrusted_text": HOSTILE_NAME}
    assert out["note"] == {"untrusted_text": HOSTILE_NOTE}
    assert out["tags"]["note"] == {"untrusted_text": HOSTILE_NOTE}
    assert out["tags"]["owner"] == {"untrusted_text": "ops@nda.example"}
    assert out["grant_ids"] == ["g-001"]
    assert out["months_since_departure"] == 3
    assert out["clouds"] == ["aws"]
    assert out["project_id"] is None  # only string leaves are wrapped


def test_sanitize_facts_does_not_double_wrap() -> None:
    out = sanitize_facts({"note": {"untrusted_text": "already"}})
    assert out["note"] == {"untrusted_text": "already"}


def test_sanitize_facts_wraps_a_slot_nobody_has_classified_yet() -> None:
    """The default is "provider text", so a new rule slot is safe before anyone reviews it."""
    out = sanitize_facts({"slot_added_next_sprint": HOSTILE_NOTE, "nested": [{"x": HOSTILE_NAME}]})
    assert out["slot_added_next_sprint"] == {"untrusted_text": HOSTILE_NOTE}
    assert out["nested"][0]["x"] == {"untrusted_text": HOSTILE_NAME}


def test_canonical_slots_are_not_trusted_below_the_top_level() -> None:
    """A provider names the keys of its own tag dict; calling one `grant_ids` buys nothing."""
    out = sanitize_facts({"tags": {"grant_ids": HOSTILE_NOTE, "cloud": HOSTILE_NAME}})
    assert out["tags"]["grant_ids"] == {"untrusted_text": HOSTILE_NOTE}
    assert out["tags"]["cloud"] == {"untrusted_text": HOSTILE_NAME}


def test_every_rule_slot_is_classified_as_canonical_or_provider_text() -> None:
    """Safe by construction: an unclassified slot is wrapped anyway, but it must be a decision.

    Adding a slot to `detection.facts.RULE_SLOTS` fails here until it is listed in one set or
    the other, so nobody classifies a provider string as canonical by omission.
    """
    slots = {slot for slots in RULE_SLOTS.values() for slot in slots} | set(COMMON_SLOTS)
    unclassified = sorted(slots - CANONICAL_SLOTS - PROVIDER_TEXT_SLOTS)
    assert not unclassified, f"classify these in athar.agents.inputs: {unclassified}"
    assert not CANONICAL_SLOTS & PROVIDER_TEXT_SLOTS


def test_causal_step_keys_are_classified_too() -> None:
    """`sanitize_facts` wraps causal steps as well (SPEC §9.2 shape)."""
    step = CausalStep(3, "ev-0001", "grant", "role_change", "aws", HOSTILE_NOTE, {"added": ["g-002"]})
    out = sanitize_facts(step.as_dict())
    assert out["description"] == {"untrusted_text": HOSTILE_NOTE}
    assert (out["month"], out["event_id"], out["kind"], out["trigger"], out["cloud"]) == (
        3,
        "ev-0001",
        "grant",
        "role_change",
        "aws",
    )
    assert out["grant_delta"] == {"added": ["g-002"]}


# --- citations (evidence and credential refs) ---------------------------------


def test_sanitize_citations_keeps_athar_minted_refs_and_wraps_provider_ones() -> None:
    refs = [
        "grant:9f2c1ab34d5e6f708192a3b4c5d6e7f8",
        "event:ev-09-00012",
        "exception:3c1d0f9a8b7c6d5e4f3a2b1c0d9e8f7a",
        f"credential:aws:key:AKIA{HOSTILE_NOTE}",
        "principal:arn:aws:iam::123456789012:user/ghost",
        "resource:arn:aws:s3:::nda-payments",
        "project:nda-analytics-prod",
        "path:emp-0042->svc-42",
        "identity:unlinked:aws:arn:aws:iam::123456789012:user/ghost",
    ]
    out = sanitize_citations(refs)
    assert out[:3] == refs[:3]
    for wrapped in out[3:]:
        assert is_wrapped(wrapped), wrapped
    assert citation_values(out)[3].startswith("credential:aws:key:AKIA")
    assert HOSTILE_NOTE not in " ".join(str(r) for r in out[:3])


def test_canonical_evidence_kinds_are_a_subset_of_the_evidence_vocabulary() -> None:
    assert set(get_args(EvidenceKind)) >= CANONICAL_EVIDENCE_KINDS


# --- build_investigate_input ---------------------------------------------------


def test_build_investigate_input_uses_canonical_rows_and_wraps_free_text(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    inp = build_investigate_input(
        r3_estate,
        r3_draft,
        _score(),
        _causal(),
        {"median_grants": 3, "identities": 12},
        rule_spec("R3", "Orphaned access"),
    )
    assert inp.finding.finding_key == finding_key("emp-0042", "R3")
    assert inp.finding.rule_id == "R3"
    assert inp.finding.rule_name == "Orphaned access"
    assert inp.finding.severity == "Critical" and inp.finding.score == 81
    assert inp.identity.identity_id == "emp-0042"
    assert inp.identity.display_name == {"untrusted_text": HOSTILE_NAME}
    assert inp.identity.employment_status == "departed"
    assert inp.identity.department == "Finance"
    assert inp.department_baseline.median_grants == 3.0
    assert inp.department_baseline.identities == 12
    assert inp.department_baseline.median_categories == 0.0
    assert inp.allowed_actions == list(rule_spec("R3").allowed_actions)
    # Every ref is offered, but only the ones ATHAR minted are offered bare (SPEC §11.3).
    assert citation_values(inp.evidence_refs) == r3_draft.evidence_keys()
    assert "grant:g-002" in inp.evidence_refs and "event:ev-0002" in inp.evidence_refs
    assert {"untrusted_text": "identity:emp-0042"} in inp.evidence_refs
    assert is_wrapped(inp.facts["note"])
    assert is_wrapped(inp.facts["tags"]["note"])
    assert inp.facts["grant_ids"] == ["g-001", "g-002", "g-003"]


def test_build_investigate_input_wraps_causal_descriptions(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    inp = build_investigate_input(r3_estate, r3_draft, None, _causal(), {}, rule_spec("R3"))
    assert len(inp.causal_history) == 2
    assert is_wrapped(inp.causal_history[0]["description"])
    assert inp.causal_history[0]["kind"] == "grant"
    assert inp.causal_history[0]["grant_delta"] == {"added": ["g-002"]}
    assert inp.finding.score is None
    assert inp.finding.severity == r3_draft.severity


def test_build_investigate_input_for_unknown_identity_uses_draft_facts(r3_estate: EstateView) -> None:
    draft = FindingDraft(
        rule_id="R10",
        identity_id="unlinked:aws:arn:aws:iam::123456789012:user/ghost",
        severity="High",
        evidence=[],
        facts={"display_name": "ghost", "identity_type": "service", "department": "unknown"},
    )
    inp = build_investigate_input(r3_estate, draft, None, [], {}, rule_spec("R10"))
    assert inp.identity.identity_type == "service"
    assert inp.identity.employment_status == "unknown"
    assert inp.identity.display_name == {"untrusted_text": "ghost"}


def test_investigate_payload_is_json_ready_and_deterministic(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    a = payload(build_investigate_input(r3_estate, r3_draft, _score(), _causal(), {}, rule_spec("R3")))
    b = payload(build_investigate_input(r3_estate, r3_draft, _score(), _causal(), {}, rule_spec("R3")))
    assert a == b
    assert isinstance(a["finding"]["finding_key"], str)


# --- build_plan_input -------------------------------------------------------------


def test_build_plan_input_lists_grants_activity_window_and_credentials(
    r3_estate: EstateView, r3_draft: FindingDraft
) -> None:
    inp = build_plan_input(r3_estate, r3_draft, _score(), rule_spec("R3"), as_of=date(2026, 8, 31))
    assert [g.grant_id for g in inp.grants] == ["g-001", "g-002", "g-003"]
    g2 = inp.grants[1]
    assert g2.scope_ref == {"untrusted_text": "arn:aws:iam::123456789012:policy/AdministratorAccess"}
    assert g2.granted_via == {"untrusted_text": HOSTILE_NOTE}
    assert g2.verb == "admin" and g2.scope_level == "org"
    # only the storage activity is inside the 90-day window ending 2026-08-31
    assert [(a.cloud, a.service_category) for a in inp.activity_90d] == [("aws", "storage")]
    assert inp.activity_90d[0].last_activity_at == date(2026, 8, 20)
    # A credential ref is a provider string, so the model sees it wrapped (SPEC §11.3).
    assert inp.credential_refs == [{"untrusted_text": "aws:key:AKIA0042"}]
    assert citation_values(inp.credential_refs) == ["aws:key:AKIA0042"]
    assert inp.current_blast_radius == 0.42
    assert inp.as_of == date(2026, 8, 31)
    assert inp.allowed_actions[0] == "disable_identity"


def test_activity_window_is_inclusive_and_ignores_none_and_future() -> None:
    rows = [
        f.activity("x", "aws", "a", last=date(2026, 6, 2)),  # exactly 90 days before 2026-08-31
        f.activity("x", "aws", "b", last=date(2026, 6, 1)),  # one day too old
        f.activity("x", "aws", "c", last=None),
        f.activity("x", "aws", "d", last=date(2026, 9, 1)),  # after as_of
        f.activity("x", "aws", "e", last=date(2026, 8, 31)),
    ]
    out = activity_window(rows, date(2026, 8, 31))
    assert [a.service_category for a in out] == ["a", "e"]


# --- build_summary_input ----------------------------------------------------------


def test_redact_headline_removes_emails_ids_and_capitalised_name_pairs() -> None:
    text = "Fatima Al-Mansoori (fatima@nda.example, emp-0042) in Finance still has access since May 2026."
    out = redact_headline(text)
    assert "fatima@" not in out
    assert "emp-0042" not in out
    assert "Fatima" not in out
    assert "Finance" in out
    assert "May 2026" in out


def test_redact_headline_keeps_department_and_org_phrases() -> None:
    text = "Digital Services holds the most Critical findings at Nahar Digital Authority."
    assert redact_headline(text) == text


def test_build_summary_input_sorts_counts_caps_headlines_and_redacts() -> None:
    rows = [
        HalfLifeRow("Finance", "all", 40, 2, None, "Broken"),
        {"department": "HR", "trigger": "all", "label": "Healthy"},
    ]
    inp = build_summary_input(
        month=12,
        counts_per_rule={"R3": 4, "R1": 9},
        counts_per_department={"HR": 1, "Finance": 5},
        counts_per_severity={"High": 3, "Critical": 2},
        halflife_table=rows,
        top_headlines=["Omar Haddad left in May 2026", "h2", "h3", "h4"],
        rule_names={"R1": "Wildcard privilege"},
    )
    assert list(inp.counts_per_rule) == ["R1", "R3"]
    assert list(inp.counts_per_department) == ["Finance", "HR"]
    assert len(inp.top_headlines) == 3
    assert "Omar" not in inp.top_headlines[0]
    assert inp.halflife_table[0]["label"] == "Broken"
    assert inp.halflife_table[1]["department"] == "HR"
    assert inp.org_name == "Nahar Digital Authority"
    assert inp.rule_names["R1"] == "Wildcard privilege"


def test_a_deny_row_is_never_offered_to_the_planner(r3_estate: EstateView, r3_draft: FindingDraft) -> None:
    """A remediation plan removes access; a `deny` row is a control, not access (SPEC §5.2).

    The citizen-data guardrail is exactly such a row: an explicit Deny bolted over a standing
    allow. Handed to the planner as an ordinary grant it becomes a candidate for `drop`, and the
    tool proposes deleting a data-protection measure — with the approver's own privilege-reduction
    figure counting the deletion as an improvement.
    """
    import dataclasses

    allow = r3_estate.grants[0]
    guardrail = dataclasses.replace(
        allow,
        grant_id="g-deny",
        effect="deny",
        granted_via="managed_policy:NdaCitizenDataGuardrail",
        scope_ref="arn:aws:s3:::nda-citizen-data",
    )
    estate = dataclasses.replace(r3_estate, grants=[*r3_estate.grants, guardrail])

    inp = build_plan_input(estate, r3_draft, _score(), rule_spec("R3"), as_of=date(2026, 8, 31))

    ids = [g.grant_id for g in inp.grants]
    assert "g-deny" not in ids, "the planner must not be able to propose revoking a guardrail"
    assert ids == ["g-001", "g-002", "g-003"], "and every allow row it used to see is still there"
