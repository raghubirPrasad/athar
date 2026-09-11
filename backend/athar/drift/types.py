"""Drift result types (SPEC §9). FROZEN — shared by scoring/drift (producers) and narrative/API (consumers)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CausalStep:
    """One event in a finding's birth certificate, in month order."""

    month: int
    event_id: str
    kind: str  # grant | revoke | role_change | departure | new_hire | project_launch | project_retirement | incident_response | mfa_lapse | region_drift | remediation | activity_stop
    trigger: str  # generator trigger or "unknown"
    cloud: str | None
    description: (
        str  # short deterministic phrase, e.g. "GCP roles/owner on nda-analytics-prod added (role change)"
    )
    grant_delta: dict[str, Any] = field(default_factory=dict)  # {"added": [...], "removed": [...]}

    def as_dict(self) -> dict[str, Any]:
        return {
            "month": self.month,
            "event_id": self.event_id,
            "kind": self.kind,
            "trigger": self.trigger,
            "cloud": self.cloud,
            "description": self.description,
            "grant_delta": self.grant_delta,
        }


@dataclass(frozen=True)
class HalfLifeRow:
    department: str
    trigger: str  # "all" | "departure" | "role_change" | ...
    grants: int
    revocations: int
    half_life_months: float | None  # None == Never (R/G < 0.10)
    label: str  # Healthy | Slow | Broken

    def as_dict(self) -> dict[str, Any]:
        return {
            "department": self.department,
            "trigger": self.trigger,
            "grants": self.grants,
            "revocations": self.revocations,
            "half_life_months": self.half_life_months,
            "label": self.label,
        }


@dataclass(frozen=True)
class TimelinePoint:
    month: int
    identity_count: int
    findings_by_severity: dict[str, int]
    median_score: float
    half_life: dict[str, float | None]  # department -> months (None = Never)

    def as_dict(self) -> dict[str, Any]:
        return {
            "month": self.month,
            "identity_count": self.identity_count,
            "findings_by_severity": self.findings_by_severity,
            "median_score": self.median_score,
            "half_life": self.half_life,
        }
