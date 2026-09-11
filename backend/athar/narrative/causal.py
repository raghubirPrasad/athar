"""Causal sentence for a finding's birth certificate (SPEC §9.2, §10.2). Pure.

Example output:
  "Became Critical in month 7 when a role change added GCP roles/owner on nda-analytics-prod.
   The AWS administrator grant from month 3 was never removed. Dormant since month 9;
   employee departed in month 11."
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from athar.drift.types import CausalStep
from athar.narrative import phrases as p

ADDING_KINDS: frozenset[str] = frozenset(
    {"grant", "role_change", "new_hire", "project_launch", "incident_response"}
)
REMOVING_KINDS: frozenset[str] = frozenset({"revoke", "remediation"})

_STATE_CLAUSES: dict[str, str] = {
    "activity_stop": "dormant since month {m}",
    "departure": "employee departed in month {m}",
    "mfa_lapse": "multi-factor authentication lapsed in month {m}",
    "project_retirement": "the project was retired in month {m}",
    "region_drift": "data moved outside approved regions in month {m}",
    "revoke": "a grant was revoked in month {m}",
    "remediation": "remediation was applied in month {m}",
}


def delta_label(item: Any) -> str:
    """Human label for one grant_delta entry (string or dict)."""
    if isinstance(item, dict):
        cloud = item.get("cloud")
        body = next(
            (str(item[k]) for k in ("label", "role", "raw_action", "scope_ref", "grant_id") if item.get(k)),
            "a grant",
        )
        return f"{p.cloud_name(cloud)} {body}" if cloud else body
    return str(item)


def _added(step: CausalStep) -> list[str]:
    added = step.grant_delta.get("added") if isinstance(step.grant_delta, dict) else None
    return [delta_label(i) for i in added] if isinstance(added, list) else []


def _removed(step: CausalStep) -> list[str]:
    removed = step.grant_delta.get("removed") if isinstance(step.grant_delta, dict) else None
    return [delta_label(i) for i in removed] if isinstance(removed, list) else []


def _sorted(steps: Sequence[CausalStep]) -> list[CausalStep]:
    return sorted(steps, key=lambda s: (s.month, s.event_id))


def _birth(steps: list[CausalStep], first_seen_month: int | None) -> CausalStep:
    """The step that completed the finding: last adding step at or before first_seen_month."""
    window = [s for s in steps if first_seen_month is None or s.month <= first_seen_month] or steps
    adding = [s for s in window if s.kind in ADDING_KINDS]
    return (adding or window)[-1]


def _added_clause(step: CausalStep) -> str:
    added = _added(step)
    if added:
        return f"added {p.join_and(added)}"
    return step.description.strip() or "changed this identity's access"


def _capitalise(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def render_causal(steps: Sequence[CausalStep], severity: str, first_seen_month: int | None = None) -> str:
    """Deterministic causal sentence; empty string when there are no steps."""
    ordered = _sorted(steps)
    if not ordered:
        return ""
    birth = _birth(ordered, first_seen_month)
    became_month = first_seen_month if first_seen_month is not None else birth.month
    sentences = [
        f"Became {severity or 'a finding'} in month {became_month} when "
        f"{p.trigger_phrase(birth.trigger)} {_added_clause(birth)}."
    ]

    removed_later = {label for s in ordered if s.kind in REMOVING_KINDS for label in _removed(s)}
    for s in ordered:
        if s is birth or s.kind not in ADDING_KINDS:
            continue
        if (s.month, s.event_id) < (birth.month, birth.event_id):
            kept = [a for a in _added(s) if a not in removed_later]
            if kept:
                sentences.append(f"The {p.join_and(kept)} grant from month {s.month} was never removed.")
            elif not _added(s):
                sentences.append(f"The change from month {s.month} ({s.description}) was never reversed.")

    clauses: list[str] = []
    for s in ordered:
        if s is birth:
            continue
        if s.kind in ADDING_KINDS:
            if (s.month, s.event_id) > (birth.month, birth.event_id):
                clauses.append(f"{p.trigger_phrase(s.trigger)} {_added_clause(s)} in month {s.month}")
            continue
        template = _STATE_CLAUSES.get(s.kind)
        if template:
            clauses.append(template.format(m=s.month))
        elif s.description:
            clauses.append(f"{s.description} in month {s.month}")
    if clauses:
        sentences.append(_capitalise("; ".join(clauses)) + ".")
    return " ".join(sentences)


def causal_steps_json(steps: Sequence[CausalStep]) -> list[dict[str, Any]]:
    return [s.as_dict() for s in _sorted(steps)]
