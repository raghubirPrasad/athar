"""Rule interface (SPEC §7). Rules are pure: `evaluate(estate, thresholds) -> list[FindingDraft]`.

A FindingDraft MUST cite concrete rows through `evidence`; a rule that cannot cite rows
does not fire (CLAUDE.md non-negotiable 8).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from athar.domain import EstateView, Thresholds

EvidenceKind = Literal[
    "grant",
    "credential",
    "activity",
    "event",
    "principal",
    "exception",
    "identity",
    "resource",
    "path",
    "project",
]


@dataclass(frozen=True)
class EvidenceRef:
    kind: EvidenceKind
    ref: str
    note: str = ""

    def key(self) -> str:
        """Stable string that goes into the committed instance (SPEC §10.1)."""
        return f"{self.kind}:{self.ref}"


@dataclass
class FindingDraft:
    rule_id: str
    identity_id: str
    severity: str
    evidence: list[EvidenceRef]
    causal_event_ids: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)  # JSON-serialisable slots for narrative templates

    def evidence_keys(self) -> list[str]:
        return sorted({e.key() for e in self.evidence})


@dataclass(frozen=True)
class RuleSpec:
    id: str
    name: str
    severity: str
    version: str
    attack_techniques: tuple[str, ...]  # marked "(verify)" until docs/MAPPINGS.md confirms them
    control_refs: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    evaluate: Callable[[EstateView, Thresholds], list[FindingDraft]]
    description: str = ""

    def run(self, estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
        drafts = self.evaluate(estate, thresholds)
        # Non-negotiable 8: evidence or it did not fire.
        return [d for d in drafts if d.evidence]
