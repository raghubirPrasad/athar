"""Permission Half-Life (SPEC §9.3). Pure.

Per department over the window: grants `G`, revocations `R`,
`half_life = median(revoke_month − grant_month)` over revoked grants, pairing each revoke
to the earliest unmatched grant of the same natural key; `None` ("Never") when `G == 0`
or `R/G < 0.10`. Label: Healthy (≤ 4 months), Slow (4–8), Broken (> 8 or Never).
Also per trigger: `G` is the department's grant pool, `R` the revocations the trigger
caused — "offboarding half-life" (trigger `departure`) is the headline number.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from statistics import median
from typing import Any

from athar.domain import EventRow, IdentityRow
from athar.drift.diff import KIND_GRANT, KIND_REVOKE
from athar.drift.types import HalfLifeRow

TRIGGER_ALL = "all"
TRIGGERS: tuple[str, ...] = (
    TRIGGER_ALL,
    "departure",
    "role_change",
    "project_retirement",
    "incident_response",
)
ALL_DEPARTMENTS = "all"

NEVER_RATIO = 0.10
HEALTHY_MAX_MONTHS = 4.0
SLOW_MAX_MONTHS = 8.0

LABEL_HEALTHY = "Healthy"
LABEL_SLOW = "Slow"
LABEL_BROKEN = "Broken"

_ADDED_KEYS: tuple[str, ...] = ("added", "grants_added")
_REMOVED_KEYS: tuple[str, ...] = ("removed", "grants_removed")
#: The provider grant behind a canonical row: one role assignment, one attached policy, one
#: binding. Half-life counts these, not the rows they expand into (see `_entry_key`).
_NATIVE_KEY_FIELDS: tuple[str, ...] = ("principal_ref", "cloud", "scope_ref", "granted_via")


def label_for(half_life: float | None) -> str:
    if half_life is None:
        return LABEL_BROKEN
    if half_life <= HEALTHY_MAX_MONTHS:
        return LABEL_HEALTHY
    if half_life <= SLOW_MAX_MONTHS:
        return LABEL_SLOW
    return LABEL_BROKEN


def _entries(delta: Any, keys: tuple[str, ...]) -> list[Any]:
    if not isinstance(delta, dict):
        return []
    out: list[Any] = []
    for key in keys:
        value = delta.get(key)
        if isinstance(value, list):
            out.extend(value)
    return out


def _entry_key(entry: Any) -> tuple[Any, ...]:
    """The PROVIDER grant a delta entry belongs to; falls back to grant_id, then to the raw string.

    Half-life counts permissions as an administrator grants and revokes them: one role assignment,
    one attached policy, one binding. The canonical model expands each of those into a row per verb
    and category, and counting rows inflated the pool non-uniformly — an Owner assignment became
    dozens, a narrow role a couple — so both the `R/G` gate and the median interval moved, and the
    measured table disagreed with the generator's own expectation in seven of eight departments.
    The key is therefore the native grant: principal, what granted it, and at what scope.
    """
    if isinstance(entry, dict):
        if entry.get("principal_ref") and entry.get("scope_ref"):
            return tuple(entry.get(k) for k in _NATIVE_KEY_FIELDS)
        return ("grant_id", entry.get("grant_id") or entry.get("scope_ref") or repr(sorted(entry.items())))
    return ("raw", str(entry))


def _native_keys(delta: Any, keys: tuple[str, ...]) -> list[tuple[Any, ...]]:
    """Distinct provider grants in a delta, in first-seen order.

    One event can carry many canonical rows of the same native grant; each counts once.
    """
    out: list[tuple[Any, ...]] = []
    seen: set[tuple[Any, ...]] = set()
    for entry in _entries(delta, keys):
        key = _entry_key(entry)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _half_life(grants: int, revocations: int, intervals: list[int]) -> float | None:
    if grants == 0 or revocations / grants < NEVER_RATIO or not intervals:
        # SPEC? revocations whose grant predates the window carry no interval; with none left, "Never".
        return None
    return float(median(intervals))


class _Tally:
    """Grant pool, revocations and revoke intervals for one (department, trigger) cell."""

    def __init__(self) -> None:
        self.grants = 0
        self.revocations = 0
        self.intervals: list[int] = []

    def row(self, department: str, trigger: str) -> HalfLifeRow:
        hl = _half_life(self.grants, self.revocations, self.intervals)
        return HalfLifeRow(department, trigger, self.grants, self.revocations, hl, label_for(hl))


def _department_of(identities: Mapping[str, IdentityRow], identity_id: str | None) -> str | None:
    if identity_id is None:
        return None
    row = identities.get(identity_id)
    return row.department if row is not None else None


def _tally(
    events: Iterable[EventRow],
    identities: Mapping[str, IdentityRow],
    up_to_month: int,
    department_of: Any,
) -> dict[tuple[str, str], _Tally]:
    """Walk grant / revoke events in (month, event_id) order and pair revokes to earliest unmatched grants."""
    cells: dict[tuple[str, str], _Tally] = defaultdict(_Tally)
    open_grants: dict[tuple[str, tuple[Any, ...]], deque[int]] = defaultdict(deque)
    ordered = sorted(
        (e for e in events if e.month <= up_to_month and e.kind in (KIND_GRANT, KIND_REVOKE)),
        key=lambda e: (e.month, e.event_id),
    )

    # One provider grant appears in as many diff events as it has canonical rows — an Owner
    # assignment in dozens. Collapse to one move per (month, kind, department, native grant)
    # before tallying, or the pool is inflated non-uniformly and both the R/G gate and the
    # median interval are meaningless.
    moves: list[tuple[int, str, str, tuple[Any, ...], str]] = []
    seen: set[tuple[int, str, str, tuple[Any, ...]]] = set()
    for evt in ordered:
        department = department_of(identities, evt.identity_id)
        if department is None:
            continue  # SPEC? events of identities outside the HR feed belong to no department
        keys = _ADDED_KEYS if evt.kind == KIND_GRANT else _REMOVED_KEYS
        for key in _native_keys(evt.grant_delta, keys):
            marker = (evt.month, evt.kind, department, key)
            if marker in seen:
                continue
            seen.add(marker)
            moves.append((evt.month, evt.kind, department, key, evt.trigger))

    for month, kind, department, key, trigger in moves:
        if kind == KIND_GRANT:
            open_grants[(department, key)].append(month)
            for name in TRIGGERS:
                cells[(department, name)].grants += 1
            continue
        queue = open_grants.get((department, key))
        interval = month - queue.popleft() if queue else None
        for cell in [TRIGGER_ALL] + ([trigger] if trigger in TRIGGERS[1:] else []):
            tally = cells[(department, cell)]
            tally.revocations += 1
            if interval is not None:
                tally.intervals.append(interval)
    return cells


def halflife_by_department(
    events: list[EventRow], identities: dict[str, IdentityRow], up_to_month: int
) -> list[HalfLifeRow]:
    """One row per (department, trigger) for every department seen in `identities`, sorted."""
    cells = _tally(events, identities, up_to_month, _department_of)
    departments = sorted({row.department for row in identities.values()})
    return [cells[(d, t)].row(d, t) for d in departments for t in TRIGGERS]


def halflife_overall(
    events: list[EventRow], identities: dict[str, IdentityRow], up_to_month: int
) -> list[HalfLifeRow]:
    """The same cells across all departments (department == 'all'), from the raw intervals."""

    def everyone(ids: Mapping[str, IdentityRow], identity_id: str | None) -> str | None:
        return ALL_DEPARTMENTS if identity_id is not None and identity_id in ids else None

    cells = _tally(events, identities, up_to_month, everyone)
    return [cells[(ALL_DEPARTMENTS, t)].row(ALL_DEPARTMENTS, t) for t in TRIGGERS]


def offboarding_headline(rows: list[HalfLifeRow]) -> HalfLifeRow:
    """The `departure` row across all departments.

    Uses the department == 'all' row when present (exact, from `halflife_overall`); otherwise
    aggregates the department rows: G and R are summed and the half-life is the
    revocation-weighted median of the department half-lives (an approximation, since medians
    do not combine).
    """
    exact = next((r for r in rows if r.trigger == "departure" and r.department == ALL_DEPARTMENTS), None)
    if exact is not None:
        return exact
    parts = [r for r in rows if r.trigger == "departure" and r.department != ALL_DEPARTMENTS]
    grants = sum(r.grants for r in parts)
    revocations = sum(r.revocations for r in parts)
    weighted: list[float] = []
    for r in sorted(parts, key=lambda x: x.department):
        if r.half_life_months is not None:
            weighted.extend([r.half_life_months] * max(1, r.revocations))
    hl = (
        None if grants == 0 or revocations / grants < NEVER_RATIO or not weighted else float(median(weighted))
    )
    return HalfLifeRow(ALL_DEPARTMENTS, "departure", grants, revocations, hl, label_for(hl))


def half_life_map(rows: Iterable[HalfLifeRow], trigger: str = TRIGGER_ALL) -> dict[str, float | None]:
    """department -> half-life months (None = Never) for one trigger; the timeline's `half_life` field."""
    return {
        r.department: r.half_life_months
        for r in sorted(rows, key=lambda r: r.department)
        if r.trigger == trigger
    }
