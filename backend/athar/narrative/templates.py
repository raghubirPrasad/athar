"""Three altitudes from templates (SPEC §10.2, §8.3, §9.2, §12). Pure; no LLM.

render_headline     — director / auditor: one sentence, no identifiers beyond name + department
render_explanation  — manager / risk officer: why, since when, blast radius, causal, remediation effect
render_evidence     — security engineer: structured sections plus a plain-text rendering
render_all          — Altitudes(headline, explanation, evidence)
render_score_line   — the §8.3 transparency line
render_halflife_sentence, rule_name, rule_summary
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from athar.drift.types import CausalStep, HalfLifeRow
from athar.log import get_logger
from athar.narrative import catalogue
from athar.narrative import phrases as p
from athar.narrative.causal import causal_steps_json, render_causal
from athar.narrative.slots import SafeDict, derive_slots, path_edge_text, safe_display_name
from athar.scoring.types import LineItem, ScoreResult

log = get_logger(__name__)

CPM_COLUMNS: tuple[str, ...] = (
    "grant_id",
    "identity_id",
    "principal_ref",
    "cloud",
    "service_category",
    "verb",
    "scope_level",
    "scope_ref",
    "region",
    "effect",
    "granted_via",
    "snapshot_month",
    "active",
)
EVIDENCE_SECTIONS: tuple[str, ...] = (
    "raw_snippets",
    "canonical_rows",
    "rules_fired",
    "score_line_items",
    "escalation_chain",
    "remediation_diff",
    "ledger",
    "causal",
)
LEDGER_NOTE = (
    "leaf = keccak256(keccak256(canonical_json(instance))); the proof verifies the leaf against the "
    "findings root committed on chain (SPEC §12.3). Narratives and status are not part of the leaf."
)
LEDGER_UNANCHORED_NOTE = "Not yet anchored: no leaf or proof is available for this finding."
_EXPLANATION_FALLBACK = "Rule {rule_id} fired for {display_name} ({department_phrase})."
_HEADLINE_FALLBACK = "{display_name} ({department_phrase}) has an access finding under rule {rule_id}."
_SPACES = re.compile(r"[ \t]{2,}")


@dataclass(frozen=True)
class Altitudes:
    headline: str
    explanation: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"headline": self.headline, "explanation": self.explanation, "evidence": dict(self.evidence)}


# --- rule text ---------------------------------------------------------------


def rule_name(rule_id: str) -> str:
    return catalogue.rule_text(rule_id).get("name") or f"Rule {rule_id}"


def rule_summary(rule_id: str) -> str:
    return catalogue.rule_text(rule_id).get("summary") or f"No definition recorded for rule {rule_id}."


# --- filling -----------------------------------------------------------------


def _fill(template: str, slots: dict[str, Any], rule_id: str) -> str:
    text = template.format_map(SafeDict(slots, rule_id))
    text = _SPACES.sub(" ", text).strip()
    return text if text.endswith((".", "!", "?")) else text + "."


def _slots(rule_id: str, facts: dict[str, Any], thresholds: dict[str, Any] | None = None) -> dict[str, Any]:
    slots = derive_slots(rule_id, facts, thresholds)
    slots["rule_id"] = rule_id
    return slots


# --- headline ----------------------------------------------------------------


def render_headline(rule_id: str, facts: dict[str, Any]) -> str:
    """One business sentence; identifier-like display names are masked (SPEC §10.2)."""
    slots = _slots(rule_id, facts)
    slots["display_name"] = safe_display_name(facts.get("display_name") if isinstance(facts, dict) else None)
    template = catalogue.template(rule_id, "headline") or _HEADLINE_FALLBACK
    return _fill(template, slots, rule_id)


# --- explanation -------------------------------------------------------------


def blast_radius_sentence(score: ScoreResult) -> str:
    pct = _pct(score.blast_radius)
    return (
        f"This identity can reach {pct}% of the estate "
        f"({p.count_phrase(score.high_sensitivity_reached, 'high-sensitivity resource', 'high-sensitivity resources')})."
    )


def _since_sentence(first_seen_month: int | None) -> str:
    label = p.month_or_unknown(first_seen_month)
    if label == p.UNKNOWN:
        return ""
    return f"The condition has existed since {label} (month {first_seen_month})."


def _exception_sentence(rule_id: str, facts: dict[str, Any]) -> str:
    expired = facts.get("exception_expired_on")
    if not expired:
        return ""
    kind = facts.get("exception_type") or ("dr-failover" if rule_id == "R2" else "break-glass")
    return (
        f"The {kind} exception recorded in the governance register expired on {p.format_date(expired)}; "
        "the register, not cloud tags, is the source of truth for exceptions."
    )


def _severity(rule_id: str, facts: dict[str, Any], score: ScoreResult | None) -> str:
    """Severity for prose: the finding's own, else the score band, else the rule's declared one (SPEC §7)."""
    own = facts.get("severity")
    if isinstance(own, str) and own:
        return own
    if score and score.severity:
        return score.severity
    if rule_id == "R4":  # Critical for admin everywhere, High for write+delete everywhere
        return "Critical" if facts.get("power") == "admin" else "High"
    return catalogue.rule_text(rule_id).get("severity") or "a finding"


def render_explanation(
    rule_id: str,
    facts: dict[str, Any],
    score: ScoreResult | None = None,
    causal: Sequence[CausalStep] = (),
    first_seen_month: int | None = None,
    thresholds: dict[str, Any] | None = None,
) -> str:
    """Manager / risk-officer paragraph (SPEC §10.2 explanation altitude)."""
    facts = facts if isinstance(facts, dict) else {}
    slots = _slots(rule_id, facts, thresholds)
    severity = _severity(rule_id, facts, score)
    parts = [
        _fill(catalogue.template(rule_id, "explanation") or _EXPLANATION_FALLBACK, slots, rule_id),
        _since_sentence(first_seen_month),
        blast_radius_sentence(score) if score else "",
        render_causal(causal, severity, first_seen_month) if causal else "",
        _fill(catalogue.template(rule_id, "remediation_effect") or "", slots, rule_id)
        if catalogue.template(rule_id, "remediation_effect")
        else "",
        _exception_sentence(rule_id, facts),
    ]
    return " ".join(s for s in parts if s)


# --- score line (SPEC §8.3) ----------------------------------------------------


def _num(x: float) -> str:
    s = f"{x:.2f}".rstrip("0")
    return s + "0" if s.endswith(".") else s


def _pct(share: float) -> int:
    return max(0, min(100, round(share * 100)))


def _modifiers(items: list[LineItem], skip: tuple[str, ...]) -> list[str]:
    return [li.label for li in items if li.label and not li.label.lower().startswith(skip)]


def render_line_items(score: ScoreResult) -> list[str]:
    """One readable line per term; every term in the formula appears here (SPEC §8.3)."""
    by_term: dict[str, list[LineItem]] = {}
    for li in score.line_items:
        by_term.setdefault(li.term, []).append(li)
    lines = [
        f"reach {_num(score.reach)} (blast radius {_pct(score.blast_radius)}% of estate, "
        f"{score.high_sensitivity_reached} high-sensitivity resources)"
    ]
    expl = _modifiers(by_term.get("exploitability", []), ("base", "exploitability", "total"))
    lines.append(_term_line("exploitability", score.exploitability, expl))
    comp = _modifiers(by_term.get("compensating", []), ("compensating", "controls", "total", "none"))
    lines.append(_term_line("controls", 1.0 - score.compensating, comp))
    lines.append(f"formula {round(score.formula_score)}")
    lines.append(_floor_text(score, by_term.get("floor", [])))
    lines.append(f"final {score.score} ({score.severity})")
    return lines


def _term_line(term: str, value: float, modifiers: list[str]) -> str:
    """'exploitability 1.8 (departed +0.5, dormant +0.3)'; bare 'controls 1.0' when nothing applies."""
    return f"{term} {_num(value)} ({', '.join(modifiers)})" if modifiers else f"{term} {_num(value)}"


def _floor_text(score: ScoreResult, floor_items: list[LineItem]) -> str:
    if score.rule_floor <= 0:
        return "no floor"
    source = next((li.label for li in floor_items if li.label), "")
    source = re.sub(r"^floor\s+(from\s+)?", "", source, flags=re.IGNORECASE).strip()
    return f"floor from {source} = {score.rule_floor}" if source else f"floor = {score.rule_floor}"


def render_score_line(score: ScoreResult) -> str:
    """'reach 0.76 (…) × exploitability 1.8 (…) × controls 1.0 = 68 · floor from R3 = 75 → 75'."""
    reach, expl, controls, _formula, floor, _final = render_line_items(score)
    return f"{reach} × {expl} × {controls} = {round(score.formula_score)} · {floor} → {score.score}"


# --- evidence ----------------------------------------------------------------


def _as_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    if dataclasses.is_dataclass(row) and not isinstance(row, type):
        return dataclasses.asdict(row)
    return {}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _raw_snippets(grants: Sequence[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in (_as_dict(r) for r in grants):
        out.append(
            {
                "source_file": g.get("source_file") or p.UNKNOWN,
                "source_pointer": g.get("source_pointer") or p.UNKNOWN,
                "snippet": g.get("raw_snippet") if g.get("raw_snippet") is not None else {},
            }
        )
    return out


def _canonical_rows(grants: Sequence[Any]) -> list[dict[str, Any]]:
    return [{c: g.get(c) for c in CPM_COLUMNS} for g in (_as_dict(r) for r in grants)]


def _verify_mark(ref: str) -> str:
    return ref if "(verify)" in ref else f"{ref} (verify)"


def _rules_fired(rule_id: str) -> list[dict[str, Any]]:
    """Rule metadata from the registry when the rule module exists; catalogue text otherwise."""
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": rule_name(rule_id),
        "version": p.UNKNOWN,
        "severity": catalogue.rule_text(rule_id).get("severity") or p.UNKNOWN,
        "attack_techniques": [],
        "control_refs": [],
        "summary": rule_summary(rule_id),
    }
    try:
        from athar.detection.registry import get_rule

        spec = get_rule(rule_id)
    except Exception as exc:  # a rule module of another lane may be absent or broken; explain anyway
        log.warning("rule metadata unavailable", extra={"rule_id": rule_id, "error": type(exc).__name__})
        return [entry]
    entry.update(
        {
            "name": spec.name or entry["name"],
            "version": spec.version,
            "severity": spec.severity,
            "attack_techniques": [_verify_mark(t) for t in spec.attack_techniques],
            "control_refs": [_verify_mark(c) for c in spec.control_refs],
        }
    )
    return [entry]


def _chain(facts: dict[str, Any], path: Sequence[Any] | None, score: ScoreResult | None) -> list[str]:
    edges: Sequence[Any] = ()
    if path:
        edges = path
    elif isinstance(facts.get("path"), list):
        edges = facts["path"]
    elif score and score.escalation_paths:
        edges = score.escalation_paths[0]
    return [path_edge_text(e) for e in edges]


def _ledger(leaf: str | None, proof: Sequence[str] | None) -> dict[str, Any]:
    if not leaf:
        return {"leaf": None, "proof": [], "note": LEDGER_UNANCHORED_NOTE}
    return {"leaf": leaf, "proof": list(proof or []), "note": LEDGER_NOTE}


def _evidence_text(rule_id: str, sections: dict[str, Any]) -> str:
    lines = [f"EVIDENCE — {rule_id} {rule_name(rule_id)}", ""]

    lines.append("1. Raw provider snippets")
    for s in sections["raw_snippets"] or []:
        lines.append(f"  - {s['source_file']} {s['source_pointer']}: {_json(s['snippet'])}")
    lines.extend(["  (none)"] if not sections["raw_snippets"] else [])

    lines.extend(["", "2. Canonical rows (CPM)", f"  columns: {' | '.join(CPM_COLUMNS)}"])
    for row in sections["canonical_rows"] or []:
        lines.append(
            "  - " + " | ".join(str(row.get(c) if row.get(c) is not None else "-") for c in CPM_COLUMNS)
        )

    lines.extend(["", "3. Rules fired"])
    for r in sections["rules_fired"]:
        lines.append(
            f"  - {r['id']} {r['name']} v{r['version']} — severity {r['severity']} — "
            f"ATT&CK {', '.join(r['attack_techniques']) or 'none'} — controls {', '.join(r['control_refs']) or 'none'}"
        )

    lines.extend(["", "4. Score line items"])
    lines.extend(f"  - {li}" for li in sections["score_line_items"] or ["not scored"])

    lines.extend(["", "5. Escalation chain"])
    lines.extend(f"  - {e}" for e in sections["escalation_chain"] or ["(none)"])

    lines.extend(["", "6. Remediation diff"])
    diff = sections["remediation_diff"]
    lines.append(f"  {_json(diff)}" if diff else "  (no plan proposed)")

    ledger = sections["ledger"]
    lines.extend(["", "7. Ledger", f"  leaf: {ledger['leaf'] or '-'}"])
    lines.append(f"  proof: {', '.join(ledger['proof']) if ledger['proof'] else '-'}")
    lines.append(f"  {ledger['note']}")

    lines.extend(["", "8. Causal history"])
    lines.extend(
        f"  - month {c['month']} [{c['kind']}/{c['trigger']}] {c['description']}"
        for c in sections["causal"] or []
    )
    lines.extend(["  (none recorded)"] if not sections["causal"] else [])
    return "\n".join(lines)


def render_evidence(
    rule_id: str,
    facts: dict[str, Any],
    evidence_refs: Sequence[Any] = (),
    grants: Sequence[Any] = (),
    score: ScoreResult | None = None,
    path: Sequence[Any] | None = None,
    policy_diff: dict[str, Any] | None = None,
    leaf: str | None = None,
    proof: Sequence[str] | None = None,
    causal: Sequence[CausalStep] = (),
) -> dict[str, Any]:
    """Security-engineer altitude: ordered sections plus a plain-text 'text' rendering."""
    facts = facts if isinstance(facts, dict) else {}
    score_lines = render_line_items(score) if score else []
    if score:
        score_lines.append(render_score_line(score))
    sections: dict[str, Any] = {
        "evidence_refs": [_as_dict(r) for r in evidence_refs],
        "raw_snippets": _raw_snippets(grants),
        "canonical_rows": _canonical_rows(grants),
        "rules_fired": _rules_fired(rule_id),
        "score_line_items": score_lines,
        "escalation_chain": _chain(facts, path, score),
        "remediation_diff": policy_diff,
        "ledger": _ledger(leaf, proof),
        "causal": causal_steps_json(causal),
    }
    sections["text"] = _evidence_text(rule_id, sections)
    return sections


# --- all three ----------------------------------------------------------------


def render_all(
    rule_id: str,
    facts: dict[str, Any],
    *,
    score: ScoreResult | None = None,
    causal: Sequence[CausalStep] = (),
    first_seen_month: int | None = None,
    thresholds: dict[str, Any] | None = None,
    evidence_refs: Sequence[Any] = (),
    grants: Sequence[Any] = (),
    path: Sequence[Any] | None = None,
    policy_diff: dict[str, Any] | None = None,
    leaf: str | None = None,
    proof: Sequence[str] | None = None,
) -> Altitudes:
    return Altitudes(
        headline=render_headline(rule_id, facts),
        explanation=render_explanation(rule_id, facts, score, causal, first_seen_month, thresholds),
        evidence=render_evidence(
            rule_id, facts, evidence_refs, grants, score, path, policy_diff, leaf, proof, causal
        ),
    )


# --- half-life (SPEC §9.3) -------------------------------------------------------

_TRIGGER_HALF_LIFE: dict[str, str] = {
    "all": "permission half-life",
    "departure": "offboarding half-life",
    "role_change": "role-change half-life",
}


def render_halflife_sentence(row: HalfLifeRow, window_months: int | None = None) -> str:
    """'Finance granted 34 permissions and revoked two in twelve months; offboarding half-life: Never (Broken).'"""
    if window_months is None:
        from athar.config import get_settings

        window_months = get_settings().athar_months
    granted = p.count_phrase(row.grants, "permission", "permissions")
    revoked = "none" if row.revocations == 0 else p.number_word(row.revocations)
    window = f"{p.number_word(window_months, below=21)} {'month' if window_months == 1 else 'months'}"
    label = _TRIGGER_HALF_LIFE.get(row.trigger, f"{row.trigger.replace('_', ' ')} half-life")
    if row.half_life_months is None:
        value = "Never"
    else:
        value = p.count_phrase(int(row.half_life_months), "month", "months")
        if row.half_life_months != int(row.half_life_months):
            value = f"{_num(row.half_life_months)} months"
    return f"{row.department} granted {granted} and revoked {revoked} in {window}; {label}: {value} ({row.label})."
