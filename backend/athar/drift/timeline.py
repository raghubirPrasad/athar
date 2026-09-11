"""Timeline series (SPEC §9.4). Pure transforms over already-computed per-month data.

Per month: identity count, findings by severity, median score, half-life per department —
the replay control animates month 1 → 12. Per identity: a risk history (one point per
scanned month) with the causal events that moved it, rendered as a sparkline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import pairwise
from statistics import median
from typing import Any

from athar.domain import SEVERITIES, severity_band
from athar.drift.halflife import TRIGGER_ALL, half_life_map
from athar.drift.types import CausalStep, HalfLifeRow, TimelinePoint


@dataclass(frozen=True)
class MonthStats:
    """What one scanned month contributes to the timeline."""

    month: int
    identity_count: int
    findings: list[str] = field(default_factory=list)  # one severity per finding
    scores: list[int] = field(default_factory=list)  # one score per identity
    halflife: list[HalfLifeRow] = field(default_factory=list)


def findings_by_severity(severities: list[str]) -> dict[str, int]:
    """Every band present, zero-filled, in SEVERITIES order; unknown labels are ignored."""
    counts = {s: 0 for s in SEVERITIES}
    for s in severities:
        if s in counts:
            counts[s] += 1
    return counts


def median_score(scores: list[int]) -> float:
    return float(median(scores)) if scores else 0.0


def timeline_points(per_month: list[MonthStats]) -> list[TimelinePoint]:
    """One point per month, sorted by month; a duplicated month keeps the last stats given."""
    by_month = {m.month: m for m in per_month}
    return [
        TimelinePoint(
            month=m.month,
            identity_count=m.identity_count,
            findings_by_severity=findings_by_severity(m.findings),
            median_score=median_score(m.scores),
            half_life=half_life_map(m.halflife, TRIGGER_ALL),
        )
        for m in (by_month[k] for k in sorted(by_month))
    ]


def risk_history(identity_scores_by_month: dict[int, int], events: list[CausalStep]) -> list[dict[str, Any]]:
    """Sparkline points `{month, score, severity, events}`; each event lands on the first scanned
    month at or after it (so a gap in scans loses nothing); events after the last point are dropped."""
    months = sorted(identity_scores_by_month)
    ordered = sorted(events, key=lambda s: (s.month, s.event_id))
    points: list[dict[str, Any]] = []
    previous = None
    for month in months:
        moved = [s for s in ordered if s.month <= month and (previous is None or s.month > previous)]
        score = int(identity_scores_by_month[month])
        points.append(
            {
                "month": month,
                "score": score,
                "severity": severity_band(score),
                "events": [s.as_dict() for s in moved],
            }
        )
        previous = month
    return points


def risk_history_sentence(points: list[dict[str, Any]]) -> str:
    """'risk 12 → 31 (month 5, Azure Contributor added) → 67 (month 7, …)': only the months that moved."""
    if not points:
        return ""
    parts = [f"risk {points[0]['score']}"]
    for prev, cur in pairwise(points):
        if cur["score"] == prev["score"] and not cur["events"]:
            continue
        labels = "; ".join(e["description"] for e in cur["events"])
        detail = f" (month {cur['month']}, {labels})" if labels else f" (month {cur['month']})"
        parts.append(f"{cur['score']}{detail}")
    return " → ".join(parts)
