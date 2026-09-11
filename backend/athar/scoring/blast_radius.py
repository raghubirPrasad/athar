"""Blast radius (SPEC §8.2). Pure.

`blast_radius(identity) = |reachable resources with control verbs| / |resources in estate|`,
weighted: `sensitivity=high` resources count ×3 (`ScoringConstants.high_sensitivity_weight`).
Reported as "can reach X% of the estate (Y high-sensitivity resources)".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from athar.scoring.constants import DEFAULT, ScoringConstants
from athar.scoring.graph import AccessGraph
from athar.scoring.types import PathEdge


@dataclass(frozen=True)
class BlastRadius:
    share: float  # weighted_reachable / weighted_total, 0.0 when the estate has no resources
    reachable: int  # distinct resources reached with a control verb
    high_sensitivity: int  # of those, sensitivity=high
    total: int  # resources in the estate
    weighted_reachable: float
    weighted_total: float
    sample_paths: list[list[PathEdge]] = field(
        default_factory=list
    )  # shortest path to a few reached resources

    @property
    def percent(self) -> int:
        return max(0, min(100, round(self.share * 100)))

    def sentence(self) -> str:
        """'can reach 19% of the estate (6 high-sensitivity resources)'."""
        noun = "high-sensitivity resource" if self.high_sensitivity == 1 else "high-sensitivity resources"
        return f"can reach {self.percent}% of the estate ({self.high_sensitivity} {noun})"

    def as_dict(self) -> dict[str, Any]:
        return {
            "share": self.share,
            "reachable": self.reachable,
            "high_sensitivity": self.high_sensitivity,
            "total": self.total,
            "weighted_reachable": self.weighted_reachable,
            "weighted_total": self.weighted_total,
            "sample_paths": [[e.as_dict() for e in p] for p in self.sample_paths],
        }


def _weight(sensitivity: str, constants: ScoringConstants) -> float:
    return constants.high_sensitivity_weight if sensitivity == "high" else 1.0


def compute(graph: AccessGraph, identity_id: str, constants: ScoringConstants = DEFAULT) -> BlastRadius:
    """Weighted share of the estate the identity can reach with a control verb (BFS depth ≤ 4)."""
    resources = graph.estate.resources
    weighted_total = sum(_weight(r.sensitivity, constants) for r in resources.values())
    reached = graph.reachable_resources(identity_id)
    known = [resources[ref] for ref in sorted(reached) if ref in resources]
    high = sum(1 for r in known if r.sensitivity == "high")
    weighted_reachable = sum(_weight(r.sensitivity, constants) for r in known)
    share = weighted_reachable / weighted_total if weighted_total > 0 else 0.0
    return BlastRadius(
        share=min(1.0, share),
        reachable=len(known),
        high_sensitivity=high,
        total=len(resources),
        weighted_reachable=weighted_reachable,
        weighted_total=weighted_total,
        sample_paths=graph.sample_paths(identity_id),
    )
