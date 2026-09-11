"""Snapshot diff (SPEC §9.1). Pure.

Compares the canonical grant rows of month N−1 and month N and emits `grant` / `revoke`
events joined to the generator's `events.jsonl` triggers when the ingest is of generated
data; a real ingest leaves `trigger="unknown"`. Rows are compared on the natural key
minus `snapshot_month` (SPEC §5.1 UNIQUE constraint), so re-ingesting the same month is
a no-op and the event ids (`diff-<month>-<grant_id>`) are deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from athar.domain import EventRow, GrantRow

KIND_GRANT = "grant"
KIND_REVOKE = "revoke"
UNKNOWN_TRIGGER = "unknown"

NaturalKey = tuple[str, str, str, str, str, str]

_ADDED_KEYS: tuple[str, ...] = ("added", "grants_added")
_REMOVED_KEYS: tuple[str, ...] = ("removed", "grants_removed")


def natural_key(g: GrantRow) -> NaturalKey:
    """The UNIQUE constraint of `grants` without `snapshot_month`."""
    return (g.principal_ref, g.cloud, g.service_category, g.verb, g.scope_ref, g.granted_via)


def delta_entry(g: GrantRow) -> dict[str, Any]:
    """The JSON-serialisable description of one grant carried in `grant_delta`."""
    return {
        "grant_id": g.grant_id,
        "principal_ref": g.principal_ref,
        "cloud": g.cloud,
        "verb": g.verb,
        "service_category": g.service_category,
        "scope_level": g.scope_level,
        "scope_ref": g.scope_ref,
        "granted_via": g.granted_via,
        "effect": g.effect,
    }


def event_id_for(month: int, grant_id: str) -> str:
    return f"diff-{month}-{grant_id}"


def _present(rows: Iterable[GrantRow]) -> dict[NaturalKey, GrantRow]:
    """Active rows keyed by natural key; on duplicates the lowest grant_id wins (deterministic)."""
    out: dict[NaturalKey, GrantRow] = {}
    for g in sorted(rows, key=lambda x: x.grant_id):
        if g.active:
            out.setdefault(natural_key(g), g)
    return out


def _delta_entries(delta: Any, keys: tuple[str, ...]) -> list[Any]:
    if not isinstance(delta, dict):
        return []
    entries: list[Any] = []
    for key in keys:
        value = delta.get(key)
        if isinstance(value, list):
            entries.extend(value)
    return entries


def _entry_matches(entry: Any, g: GrantRow) -> bool:
    """A generator delta entry names this grant: same grant_id, or same principal/scope (+ any other keys present)."""
    if isinstance(entry, str):
        return entry in (g.grant_id, g.scope_ref, g.principal_ref)
    if not isinstance(entry, dict):
        return False
    gid = entry.get("grant_id")
    if gid:
        return bool(gid == g.grant_id)
    keys = [
        k
        for k in ("principal_ref", "scope_ref", "cloud", "verb", "service_category", "granted_via")
        if k in entry
    ]
    if "principal_ref" not in keys and "scope_ref" not in keys:
        return False
    return all(entry[k] == getattr(g, k) for k in keys)


def _trigger_of(evt: EventRow) -> str:
    if evt.trigger and evt.trigger != UNKNOWN_TRIGGER:
        return evt.trigger
    return evt.kind or UNKNOWN_TRIGGER


def join_trigger(g: GrantRow, month: int, generator_events: Iterable[EventRow], *, removed: bool) -> str:
    """Trigger of the generator event (same identity, same month) whose delta names the grant, else 'unknown'."""
    keys = _REMOVED_KEYS if removed else _ADDED_KEYS
    for evt in sorted(generator_events, key=lambda e: (e.month, e.event_id)):
        if evt.month != month or evt.identity_id != g.identity_id:
            continue
        if any(_entry_matches(entry, g) for entry in _delta_entries(evt.grant_delta, keys)):
            return _trigger_of(evt)
    return UNKNOWN_TRIGGER


def diff_snapshots(
    prev: list[GrantRow] | None,
    curr: list[GrantRow],
    generator_events: list[EventRow],
    month: int,
) -> list[EventRow]:
    """`grant` events for rows in `curr` but not `prev`, `revoke` events for the reverse.

    `prev=None` means there is no earlier snapshot: every active row in `curr` is a grant.
    Output is sorted by event_id so two runs over the same rows are byte-identical.
    """
    before = _present(prev or [])
    after = _present(curr)
    same_month = [e for e in generator_events if e.month == month]
    events: list[EventRow] = []
    for key in sorted(after.keys() - before.keys()):
        g = after[key]
        events.append(
            EventRow(
                event_id=event_id_for(month, g.grant_id),
                month=month,
                kind=KIND_GRANT,
                identity_id=g.identity_id,
                cloud=g.cloud,
                grant_delta={"added": [delta_entry(g)], "removed": []},
                trigger=join_trigger(g, month, same_month, removed=False),
                note=f"{g.cloud} {g.verb} {g.service_category}@{g.scope_level} {g.scope_ref} added",
            )
        )
    for key in sorted(before.keys() - after.keys()):
        g = before[key]
        events.append(
            EventRow(
                event_id=event_id_for(month, g.grant_id),
                month=month,
                kind=KIND_REVOKE,
                identity_id=g.identity_id,
                cloud=g.cloud,
                grant_delta={"added": [], "removed": [delta_entry(g)]},
                trigger=join_trigger(g, month, same_month, removed=True),
                note=f"{g.cloud} {g.verb} {g.service_category}@{g.scope_level} {g.scope_ref} removed",
            )
        )
    return sorted(events, key=lambda e: e.event_id)
