"""Timeline series (SPEC §9.4): per-month points and per-identity risk history."""

from __future__ import annotations

from athar.drift import timeline as tl
from athar.drift.types import CausalStep, HalfLifeRow, TimelinePoint


def _step(month: int, event_id: str, description: str = "x") -> CausalStep:
    return CausalStep(month, event_id, "grant", "role_change", "aws", description, {})


def test_timeline_points_shape_and_zero_filled_severities():
    stats = [
        tl.MonthStats(
            2,
            120,
            ["High", "Low", "High"],
            [10, 50, 90],
            [HalfLifeRow("Finance", "all", 3, 1, 2.0, "Healthy")],
        ),
        tl.MonthStats(1, 100, [], [], []),
    ]
    points = tl.timeline_points(stats)
    assert [p.month for p in points] == [1, 2]
    assert isinstance(points[0], TimelinePoint)
    assert points[0].as_dict() == {
        "month": 1,
        "identity_count": 100,
        "findings_by_severity": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
        "median_score": 0.0,
        "half_life": {},
    }
    assert points[1].findings_by_severity == {"Low": 1, "Medium": 0, "High": 2, "Critical": 0}
    assert points[1].median_score == 50.0
    assert points[1].half_life == {"Finance": 2.0}


def test_median_score_of_even_count_and_unknown_severity_ignored():
    assert tl.median_score([10, 20, 30, 40]) == 25.0
    assert tl.findings_by_severity(["Critical", "bogus"]) == {"Low": 0, "Medium": 0, "High": 0, "Critical": 1}


def test_half_life_uses_the_all_trigger_only():
    rows = [HalfLifeRow("HR", "departure", 5, 1, None, "Broken"), HalfLifeRow("HR", "all", 5, 3, 6.0, "Slow")]
    point = tl.timeline_points([tl.MonthStats(1, 1, [], [], rows)])[0]
    assert point.half_life == {"HR": 6.0}


def test_risk_history_attaches_events_to_the_first_scanned_month_at_or_after_them():
    events = [
        _step(7, "b", "AWS IAMRoleManager added"),
        _step(5, "a", "Azure Contributor added"),
        _step(6, "c"),
        _step(13, "z"),
    ]
    history = tl.risk_history({5: 31, 7: 67, 9: 91, 1: 12}, events)
    assert [(p["month"], p["score"], p["severity"]) for p in history] == [
        (1, 12, "Low"),
        (5, 31, "Medium"),
        (7, 67, "High"),
        (9, 91, "Critical"),
    ]
    assert [[e["event_id"] for e in p["events"]] for p in history] == [[], ["a"], ["c", "b"], []]
    assert history[1]["events"][0]["description"] == "Azure Contributor added"


def test_risk_history_is_empty_without_scores():
    assert tl.risk_history({}, [_step(1, "a")]) == []


def test_risk_history_sentence_lists_only_the_months_that_moved():
    history = tl.risk_history(
        {1: 12, 3: 12, 5: 31, 7: 67},
        [_step(5, "a", "Azure Contributor added"), _step(7, "b", "AWS IAMRoleManager")],
    )
    assert tl.risk_history_sentence(history) == (
        "risk 12 → 31 (month 5, Azure Contributor added) → 67 (month 7, AWS IAMRoleManager)"
    )
    assert tl.risk_history_sentence([]) == ""
