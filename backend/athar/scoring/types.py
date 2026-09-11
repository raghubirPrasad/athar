"""Result types for scoring (SPEC §8.3). Every term is a line item."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LineItem:
    term: str  # reach | exploitability | compensating | formula | floor | final
    label: str  # human-readable ("departed +0.5")
    value: float
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"term": self.term, "label": self.label, "value": self.value, "detail": self.detail}


@dataclass(frozen=True)
class PathEdge:
    src: str
    verb: str
    dst: str
    grant_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"src": self.src, "verb": self.verb, "dst": self.dst, "grant_id": self.grant_id}


@dataclass
class ScoreResult:
    identity_id: str
    blast_radius: float  # weighted share of estate reachable with control verbs
    reachable_resources: int
    high_sensitivity_reached: int
    reach: float
    exploitability: float
    compensating: float
    formula_score: float
    rule_floor: int
    score: int
    severity: str
    line_items: list[LineItem]
    escalation_paths: list[list[PathEdge]]

    def line_items_json(self) -> list[dict[str, Any]]:
        return [li.as_dict() for li in self.line_items]

    def paths_json(self) -> list[list[dict[str, Any]]]:
        return [[e.as_dict() for e in p] for p in self.escalation_paths]
