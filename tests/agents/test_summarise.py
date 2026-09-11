"""Executive-summary agent (SPEC §11.4): aggregate-only input, static template, three-theme cap."""

from __future__ import annotations

from athar.agents.guard import walk_output_strings
from athar.agents.inputs import SummaryInput, build_summary_input
from athar.agents.summarise import executive_summary, template_summary
from athar.drift.types import HalfLifeRow

from tests.agents.conftest import FakeTransport, make_client


def _inp() -> SummaryInput:
    return build_summary_input(
        month=12,
        counts_per_rule={"R1": 9, "R2": 12, "R3": 4, "R9": 1},
        counts_per_department={"Finance": 10, "HR": 6, "Digital Services": 10},
        counts_per_severity={"Critical": 3, "High": 8, "Medium": 15},
        halflife_table=[
            HalfLifeRow("Finance", "all", 40, 2, None, "Broken"),
            HalfLifeRow("Finance", "departure", 10, 1, None, "Broken"),
            HalfLifeRow("HR", "all", 30, 20, 2.0, "Healthy"),
        ],
        top_headlines=["Aisha Rahman left in May 2026 but keeps admin", "h2", "h3"],
        rule_names={"R1": "Wildcard privilege", "R2": "Dormant access", "R3": "Orphaned access"},
    )


def test_template_summary_is_composed_from_counts_only() -> None:
    out = template_summary(_inp())
    p = out.summary_paragraph
    assert "August 2026" in p
    assert "26 open access-governance findings" in p
    assert "3 critical, 8 high, 15 medium" in p
    assert "Digital Services with 10 findings" in p  # tie broken alphabetically
    assert "Dormant access; Wildcard privilege; Orphaned access" in p
    assert "effectively broken in: Finance" in p
    assert "HR" not in p.split("effectively broken in:")[1]
    assert out.top_themes == ["Dormant access", "Wildcard privilege", "Orphaned access"]
    assert "Aisha" not in " ".join(walk_output_strings(out))


def test_template_summary_handles_empty_aggregates() -> None:
    out = template_summary(
        SummaryInput(
            month=0,
            counts_per_rule={},
            counts_per_department={},
            counts_per_severity={},
            halflife_table=[],
            top_headlines=[],
        )
    )
    assert "0 open access-governance findings" in out.summary_paragraph
    assert "(none)" in out.summary_paragraph
    assert out.top_themes == []


def test_executive_summary_falls_back_to_template_with_provider_none() -> None:
    res = executive_summary(_inp(), make_client("none"), None)
    assert res.meta.generated_by == "template" and res.meta.prompt_version == "sum-v1"
    assert res.output == template_summary(_inp())


def test_executive_summary_model_output_is_guarded_and_capped() -> None:
    gem = FakeTransport(
        {
            "summary_paragraph": "Posture worsened. Contact ciso@nda-secret.example for details. Dormant access dominates.",
            "top_themes": ["Dormant access", "Orphaned admins", "MFA gaps", "Regions", "More"],
        }
    )
    res = executive_summary(_inp(), make_client("gemini", gemini=gem), None)
    assert res.meta.generated_by == "model"
    assert len(res.output.top_themes) == 3
    assert "ciso@" not in res.output.summary_paragraph
    assert "[redacted]" in res.output.summary_paragraph
    assert "Dormant access dominates" in res.output.summary_paragraph
    assert "top_themes_truncated" in res.meta.guard_flags


def test_summary_payload_contains_no_identifiers_or_names() -> None:
    from athar.agents.guard import extract_identifiers
    from athar.agents.inputs import payload

    data = payload(_inp())
    assert extract_identifiers(data) == set()
    assert "Aisha" not in str(data)


def test_the_estate_wide_aggregate_is_not_listed_as_a_department() -> None:
    """`halflife_overall` emits a row whose department is the literal "all" (drift.halflife).

    It used to be enumerated beside the real departments, so the opening screen of the demo read
    "broken in: Contractors, …, Unassigned, all".
    """
    inp = _inp()
    rows = [*inp.halflife_table, {"department": "all", "trigger": "all", "label": "Broken"}]
    out = template_summary(inp.model_copy(update={"halflife_table": rows}))
    listed = out.summary_paragraph.split("effectively broken in:")[1]
    assert "all (grants" not in listed and ", all" not in listed
    assert "Finance" in listed, "the real departments are still named"
