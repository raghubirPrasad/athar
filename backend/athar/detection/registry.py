"""Rule registry (SPEC §7). Order is the evaluation order; ids are unique."""

from __future__ import annotations

from athar.detection.base import FindingDraft, RuleSpec
from athar.domain import EstateView, Thresholds

_RULES: dict[str, RuleSpec] = {}
_LOADED = False


def register(rule: RuleSpec) -> RuleSpec:
    if rule.id in _RULES:
        raise ValueError(f"duplicate rule id {rule.id}")
    _RULES[rule.id] = rule
    return rule


def all_rules() -> list[RuleSpec]:
    _load()
    return [_RULES[k] for k in sorted(_RULES, key=lambda r: int(r[1:]))]


def get_rule(rule_id: str) -> RuleSpec:
    _load()
    return _RULES[rule_id]


def rule_versions() -> dict[str, str]:
    return {r.id: r.version for r in all_rules()}


def run_all(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for rule in all_rules():
        drafts.extend(rule.run(estate, thresholds))
    return drafts


def _load() -> None:
    """Import every rule module so each self-registers. Idempotent, and safe even if a caller
    imported a single rule module first (re-importing is a no-op; register() rejects duplicates)."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    import importlib

    for mod in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"):
        try:
            importlib.import_module(f"athar.detection.{mod}")
        except ModuleNotFoundError as exc:  # pragma: no cover — only during scaffold
            if exc.name != f"athar.detection.{mod}":
                raise
