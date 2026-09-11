"""Evidence altitude (SPEC §10.2, §12), score line (SPEC §8.3), half-life sentence (SPEC §9.3)."""

from __future__ import annotations

import dataclasses

from athar.drift.types import HalfLifeRow
from athar.narrative.examples import EXAMPLE_GRANTS, example_causal, example_facts, example_score
from athar.narrative.templates import (
    EVIDENCE_SECTIONS,
    Altitudes,
    render_all,
    render_evidence,
    render_halflife_sentence,
    render_line_items,
    render_score_line,
)

PROOF = ["0x" + "ab" * 32, "0x" + "cd" * 32]
LEAF = "0x" + "11" * 32


def _evidence(**kw):
    base = dict(
        evidence_refs=[{"kind": "grant", "ref": "g-aws-0042-01", "note": "admin at org"}],
        grants=EXAMPLE_GRANTS,
        score=example_score(),
        leaf=LEAF,
        proof=PROOF,
        causal=example_causal(),
    )
    base.update(kw)
    return render_evidence("R5", example_facts("R5"), **base)


def test_evidence_sections_present_and_ordered():
    ev = _evidence()
    keys = [k for k in ev if k in EVIDENCE_SECTIONS]
    assert keys == list(EVIDENCE_SECTIONS)
    assert "text" in ev and "evidence_refs" in ev


def test_evidence_raw_snippets_and_canonical_rows_from_grants():
    ev = _evidence()
    assert ev["raw_snippets"][0] == {
        "source_file": "aws/authorization-details.json",
        "source_pointer": "/RoleDetailList/3/AttachedManagedPolicies/0",
        "snippet": EXAMPLE_GRANTS[0]["raw_snippet"],
    }
    assert ev["canonical_rows"][1]["verb"] == "admin"
    assert "raw_snippet" not in ev["canonical_rows"][0]


def test_evidence_accepts_dataclass_rows():
    from tests.factories import grant

    ev = render_evidence("R1", example_facts("R1"), grants=[grant("g-1", verb="admin")])
    assert ev["canonical_rows"][0]["grant_id"] == "g-1"
    assert ev["raw_snippets"][0]["source_file"] == "aws/authorization-details.json"


def test_evidence_rules_fired_carries_name_and_verify_marks():
    rule = _evidence()["rules_fired"][0]
    assert rule["id"] == "R5" and rule["name"] == "Toxic combination"
    assert all("(verify)" in t for t in rule["attack_techniques"])
    assert all("(verify)" in c for c in rule["control_refs"])


def test_evidence_escalation_chain_format():
    ev = _evidence()
    assert ev["escalation_chain"][0] == (
        "id:emp-0042 --grant--> p:arn:aws:iam::123456789012:role/finance-admin [g-aws-0042-05]"
    )
    explicit = _evidence(path=[{"src": "a", "verb": "impersonate", "dst": "b"}])
    assert explicit["escalation_chain"] == ["a --impersonate--> b"]


def test_evidence_ledger_section():
    ev = _evidence()
    assert ev["ledger"] == {"leaf": LEAF, "proof": PROOF, "note": ev["ledger"]["note"]}
    assert "keccak256(keccak256" in ev["ledger"]["note"]
    unanchored = _evidence(leaf=None, proof=None)
    assert unanchored["ledger"]["leaf"] is None and "Not yet anchored" in unanchored["ledger"]["note"]


def test_evidence_remediation_diff_and_causal():
    diff = {"before": {"Action": "*"}, "after": {"Action": ["s3:GetObject"]}}
    ev = _evidence(policy_diff=diff)
    assert ev["remediation_diff"] == diff
    assert [c["month"] for c in ev["causal"]] == [3, 7, 9, 11]
    assert _evidence()["remediation_diff"] is None


def test_evidence_text_renders_every_section():
    text = _evidence()["text"]
    for header in (
        "1. Raw provider snippets",
        "2. Canonical rows",
        "3. Rules fired",
        "4. Score line items",
        "5. Escalation chain",
        "6. Remediation diff",
        "7. Ledger",
        "8. Causal history",
    ):
        assert header in text
    assert LEAF in text and "AdministratorAccess" in text


def test_evidence_without_anything_still_renders():
    ev = render_evidence("R0", {})
    assert ev["score_line_items"] == [] and ev["escalation_chain"] == []
    assert "not scored" in ev["text"]


def test_render_all_as_dict():
    alt = render_all(
        "R1", example_facts("R1"), score=example_score(), first_seen_month=3, leaf=LEAF, proof=PROOF
    )
    assert isinstance(alt, Altitudes) and dataclasses.is_dataclass(alt)
    d = alt.as_dict()
    assert set(d) == {"headline", "explanation", "evidence"}
    assert d["evidence"]["ledger"]["leaf"] == LEAF
    assert "month 3" in d["explanation"]


# --- score line (SPEC §8.3) ----------------------------------------------------------


def test_render_score_line_matches_spec_example():
    assert render_score_line(example_score()) == (
        "reach 0.76 (blast radius 19% of estate, 6 high-sensitivity resources) "
        "× exploitability 1.8 (departed +0.5, dormant +0.3) × controls 1.0 = 68 · floor from R3 = 75 → 75"
    )


def test_render_score_line_no_floor_and_compensating():
    score = dataclasses.replace(
        example_score(),
        compensating=0.35,
        rule_floor=0,
        formula_score=44.46,
        score=44,
        severity="Medium",
        line_items=[li for li in example_score().line_items if li.term != "floor"]
        + [dataclasses.replace(example_score().line_items[4], label="break-glass +0.35", value=0.35)],
    )
    line = render_score_line(score)
    assert "× controls 0.65 (break-glass +0.35) = 44 · no floor → 44" in line


def test_render_line_items_has_every_term():
    lines = render_line_items(example_score())
    assert [line.split(" ")[0] for line in lines] == [
        "reach",
        "exploitability",
        "controls",
        "formula",
        "floor",
        "final",
    ]


# --- half-life (SPEC §9.3) ------------------------------------------------------------


def test_halflife_never_broken_sentence():
    row = HalfLifeRow("Finance", "departure", 34, 2, None, "Broken")
    assert render_halflife_sentence(row, window_months=12) == (
        "Finance granted 34 permissions and revoked two in twelve months; offboarding half-life: Never (Broken)."
    )


def test_halflife_numeric_and_zero_revocations():
    row = HalfLifeRow("HR", "all", 8, 0, None, "Broken")
    assert "HR granted eight permissions and revoked none" in render_halflife_sentence(row, 12)
    healthy = HalfLifeRow("Cyber Security", "role_change", 12, 6, 3.0, "Healthy")
    text = render_halflife_sentence(healthy, 12)
    assert text.endswith("role-change half-life: three months (Healthy).")
    fractional = HalfLifeRow("Data Services", "all", 12, 6, 4.5, "Slow")
    assert "permission half-life: 4.5 months (Slow)." in render_halflife_sentence(fractional, 12)


def test_halflife_window_defaults_to_configured_months():
    row = HalfLifeRow("Finance", "departure", 1, 1, 1.0, "Healthy")
    text = render_halflife_sentence(row)
    assert "granted one permission and revoked one in" in text
    assert "one month (Healthy)" in text
