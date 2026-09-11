"""Causal history per finding (SPEC §9.2). Pure.

The ordered list of events that produced a finding's evidence rows: the events the rule
cited (`FindingDraft.causal_event_ids`) plus the identity's departure / role-change /
project-retirement / MFA-lapse events, and a synthetic `activity_stop` step when the
rule's facts carry `last_activity_at` (R2-style). Each step has a deterministic
description phrase; the narrative layer (`narrative/causal.py`) turns steps into prose.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from athar.clock import month_of
from athar.detection.base import FindingDraft
from athar.domain import EstateView, EventRow
from athar.drift.types import CausalStep

STATE_KINDS: tuple[str, ...] = ("departure", "role_change", "project_retirement", "mfa_lapse")
ACTIVITY_STOP = "activity_stop"
UNKNOWN_TRIGGER = "unknown"

_CLOUD_NAMES: dict[str, str] = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
_TRIGGER_PHRASES: dict[str, str] = {
    "role_change": "role change",
    "departure": "departure",
    "new_hire": "new hire",
    "project_launch": "project launch",
    "project_retirement": "project retirement",
    "incident_response": "incident response",
    "mfa_lapse": "MFA lapse",
    "region_drift": "region drift",
    "remediation": "remediation",
    "grant": "grant",
    "revoke": "revocation",
}
_KIND_PHRASES: dict[str, str] = {
    "departure": "HR status changed to departed",
    "new_hire": "joined; baseline access granted",
    "role_change": "role changed",
    "project_launch": "project launched; service accounts created",
    "project_retirement": "project retired; service accounts kept",
    "incident_response": "emergency access granted during incident response",
    "region_drift": "resource created outside the approved regions",
    "mfa_lapse": "multi-factor authentication flag turned off",
    "remediation": "remediation applied",
    "grant": "access granted",
    "revoke": "access revoked",
}
_ADDED_KEYS: tuple[str, ...] = ("added", "grants_added")
_REMOVED_KEYS: tuple[str, ...] = ("removed", "grants_removed")


def cloud_name(cloud: str | None) -> str:
    return _CLOUD_NAMES.get(str(cloud).lower(), str(cloud)) if cloud else ""


def trigger_phrase(trigger: str | None) -> str:
    if not trigger or trigger == UNKNOWN_TRIGGER:
        return UNKNOWN_TRIGGER
    return _TRIGGER_PHRASES.get(trigger, trigger.replace("_", " "))


def _entries(delta: Any, keys: tuple[str, ...]) -> list[Any]:
    if not isinstance(delta, dict):
        return []
    out: list[Any] = []
    for key in keys:
        value = delta.get(key)
        if isinstance(value, list):
            out.extend(value)
    return out


def entry_label(entry: Any, cloud: str | None) -> str:
    """'GCP roles/owner on nda-analytics-prod' from a delta entry (dict or string)."""
    if isinstance(entry, dict):
        name = next(
            (str(entry[k]) for k in ("label", "role", "raw_action") if entry.get(k)),
            " ".join(str(entry[k]) for k in ("verb", "service_category") if entry.get(k)) or "a grant",
        )
        scope = entry.get("scope_ref")
        body = f"{name} on {scope}" if scope else name
        prefix = cloud_name(entry.get("cloud") or cloud)
        return f"{prefix} {body}".strip()
    return str(entry)


def describe(evt: EventRow) -> str:
    """Deterministic phrase per event kind, naming the grants it added / removed."""
    added = [entry_label(e, evt.cloud) for e in _entries(evt.grant_delta, _ADDED_KEYS)]
    removed = [entry_label(e, evt.cloud) for e in _entries(evt.grant_delta, _REMOVED_KEYS)]
    trigger = trigger_phrase(evt.trigger)
    suffix = f" ({trigger})" if trigger != UNKNOWN_TRIGGER and trigger != trigger_phrase(evt.kind) else ""
    parts: list[str] = []
    if added:
        parts.append(f"{', '.join(added)} added")
    if removed:
        parts.append(f"{', '.join(removed)} removed")
    if not parts:
        parts.append(_KIND_PHRASES.get(evt.kind, evt.kind.replace("_", " ")))
    elif evt.kind not in ("grant", "revoke"):
        parts.insert(0, _KIND_PHRASES.get(evt.kind, evt.kind.replace("_", " ")))
    return "; ".join(parts) + suffix


def step_from_event(evt: EventRow) -> CausalStep:
    return CausalStep(
        month=evt.month,
        event_id=evt.event_id,
        kind=evt.kind,
        trigger=evt.trigger or UNKNOWN_TRIGGER,
        cloud=evt.cloud,
        description=describe(evt),
        grant_delta=dict(evt.grant_delta or {}),
    )


def _last_activity(facts: dict[str, Any]) -> date | None:
    raw = facts.get("last_activity_at")
    if isinstance(raw, date):
        return raw
    if isinstance(raw, str) and raw:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None
    return None


def activity_stop_step(identity_id: str, last: date) -> CausalStep:
    """Synthetic step for the last recorded activity (dormancy starts here)."""
    month = max(1, month_of(last))
    return CausalStep(
        month=month,
        event_id=f"activity-stop-{identity_id}-{last.isoformat()}",
        kind=ACTIVITY_STOP,
        trigger=UNKNOWN_TRIGGER,
        cloud=None,
        description=f"last activity recorded on {last.isoformat()}",
        grant_delta={},
    )


def causal_history(estate: EstateView, draft: FindingDraft) -> list[CausalStep]:
    """Cited events + state-changing events for the identity (+ activity stop), in (month, event_id) order."""
    cited = set(draft.causal_event_ids)
    steps: dict[str, CausalStep] = {}
    for evt in estate.events_for(draft.identity_id):
        if evt.month > estate.month:
            continue
        if evt.event_id in cited or evt.kind in STATE_KINDS:
            steps.setdefault(evt.event_id, step_from_event(evt))
    last = _last_activity(draft.facts)
    if last is not None:
        stop = activity_stop_step(draft.identity_id, last)
        steps.setdefault(stop.event_id, stop)
    return sorted(steps.values(), key=lambda s: (s.month, s.event_id))
