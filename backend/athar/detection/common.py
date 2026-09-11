"""Shared helpers for detection rules R0–R10 (SPEC §7). Pure functions over EstateView.

Everything here is side-effect free. Rules use these helpers to (a) select rows,
(b) turn rows into EvidenceRef citations, (c) find the estate events that caused
those rows (SPEC §9.2), and (d) consult the governance exception register
(SPEC §4.3) — the ONLY source of exceptions. Cloud-side tags are never read here.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from typing import Any

from athar.clock import days_between, month_start
from athar.detection.base import EvidenceRef, FindingDraft
from athar.domain import (
    SCOPE_RANK,
    EstateView,
    EventRow,
    ExceptionRow,
    GrantRow,
    PrincipalRow,
    scope_at_least,
)
from athar.normaliser.types import UNMAPPED_ACTIONS_KEY  # the key the pipeline writes; pure data

VERIFY_SUFFIX = " (verify)"

# Keys under which provider snippets carry the raw action / role string (SPEC §4.6).
_ACTION_KEYS: tuple[str, ...] = (
    "raw_action",
    "Action",
    "action",
    "actions",
    "NotAction",
    "role",
    "Role",
    "roleDefinitionName",
    "PolicyName",
)
_WILDCARD_ACTIONS: frozenset[str] = frozenset({"*", "*:*"})


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------


def verify(*refs: str) -> tuple[str, ...]:
    """Suffix ATT&CK / control identifiers with ' (verify)' until docs/MAPPINGS.md confirms them."""
    return tuple(f"{r}{VERIFY_SUFFIX}" for r in refs)


# ---------------------------------------------------------------------------
# Row selection
# ---------------------------------------------------------------------------


def identity_ids(estate: EstateView) -> list[str]:
    """Every identity id the estate knows about: identity rows plus grant holders. Sorted."""
    ids = set(estate.identities)
    ids.update(g.identity_id for g in estate.grants if g.identity_id)
    return sorted(ids)


def active_allow_grants(estate: EstateView, identity_id: str) -> list[GrantRow]:
    """Active `allow` grants for an identity, sorted by grant_id.

    # SPEC? §5.2 says scoring treats a deny at equal/higher scope as cancelling an allow;
    # rules take the simpler reading and only consider allow rows as evidence of privilege.
    """
    rows = [g for g in estate.grants_for(identity_id) if g.effect == "allow"]
    return sorted(rows, key=lambda g: g.grant_id)


def own_principals(estate: EstateView, identity_id: str) -> list[PrincipalRow]:
    """Principal rows linked to the identity, sorted by principal_ref."""
    rows = [p for p in estate.principals.values() if p.identity_id == identity_id]
    return sorted(rows, key=lambda p: p.principal_ref)


def worst_grant(grants: Iterable[GrantRow]) -> GrantRow:
    """Highest scope first, `admin` before other verbs, then grant_id for a stable pick."""
    return sorted(
        grants,
        key=lambda g: (-SCOPE_RANK.get(g.scope_level, -1), g.verb != "admin", g.grant_id),
    )[0]


def present_days(estate: EstateView, identity_id: str) -> int:
    """Days the identity has been present in the estate up to the snapshot's month-end."""
    row = estate.identities.get(identity_id)
    start_month = (row.first_seen_month or row.hire_month or 1) if row else 1
    return days_between(month_start(start_month), estate.as_of)


# ---------------------------------------------------------------------------
# Raw snippets and scopes
# ---------------------------------------------------------------------------


def raw_actions(snippet: Any) -> list[str]:
    """Every raw action / role string found in a provider snippet (recursive, order preserved)."""
    found: list[str] = []
    _collect_actions(snippet, found, under_action_key=False)
    return found


def _collect_actions(node: Any, out: list[str], *, under_action_key: bool) -> None:
    if isinstance(node, str):
        if under_action_key:
            out.append(node)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _collect_actions(value, out, under_action_key=key in _ACTION_KEYS)
        return
    if isinstance(node, list):
        for item in node:
            _collect_actions(item, out, under_action_key=under_action_key)


def unmapped_actions(snippet: Any) -> list[str]:
    """The raw actions that actually failed to map on a `verb: unknown` row (SPEC §5.3).

    The normaliser records them under `UNMAPPED_ACTIONS_KEY` because a single statement may mix
    mapped and unmapped actions, and only the unmapped ones explain the `unknown` verb. Snippets
    written before that record existed — and hand-built rows in tests — fall back to every raw
    action in the snippet, which is the best the row can say.
    """
    if isinstance(snippet, dict):
        recorded = snippet.get(UNMAPPED_ACTIONS_KEY)
        if isinstance(recorded, list):
            found = [a for a in recorded if isinstance(a, str) and a]
            if found:
                return found
    return raw_actions(snippet)


def has_wildcard(grant: GrantRow) -> bool:
    """True when the raw snippet still shows an unexpanded full wildcard (`*` / `*:*`)."""
    return any(a in _WILDCARD_ACTIONS for a in raw_actions(grant.raw_snippet))


def scope_root(cloud: str, scope_ref: str) -> str:
    """Account / subscription / project prefix of a scope_ref (SPEC §5.2 scope mapping)."""
    if cloud == "aws" and scope_ref.startswith("arn:"):
        parts = scope_ref.split(":")
        return parts[4] if len(parts) > 4 and parts[4] else scope_ref
    if cloud == "azure" and scope_ref.startswith("/subscriptions/"):
        return "/".join(scope_ref.split("/")[:3])
    if cloud == "gcp":
        if scope_ref.startswith("projects/"):
            return "/".join(scope_ref.split("/")[:2])
        return scope_ref.split("/")[0]
    return scope_ref


def project_ref_matches(cloud: str, scope_ref: str, project_ref: str | None) -> bool:
    """True when `project_ref` names the account / subscription / project that `scope_ref` sits in.

    Exact ref, exact root, or the root's last path segment (`projects/p` ↔ `p`); never a bare
    substring, so a short project ref cannot match an unrelated scope.
    """
    if not project_ref:
        return False
    root = scope_root(cloud, scope_ref)
    return project_ref in (scope_ref, root) or root.endswith(f"/{project_ref}")


def scopes_overlap(a: GrantRow, b: GrantRow) -> bool:
    """Same scope_ref, one a prefix of the other, a global scope, or the same
    account/subscription/project root when either side is at scope ≥ project."""
    if a.cloud != b.cloud:
        return False
    if a.scope_ref == b.scope_ref or "global" in (a.scope_level, b.scope_level):
        return True
    sa, sb = a.scope_ref.rstrip("*"), b.scope_ref.rstrip("*")
    if sa and sb and (sa.startswith(sb) or sb.startswith(sa)):
        return True
    if scope_at_least(a.scope_level, "project") or scope_at_least(b.scope_level, "project"):
        return scope_root(a.cloud, a.scope_ref) == scope_root(b.cloud, b.scope_ref)
    return False


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def grant_ids(grants: Iterable[GrantRow]) -> list[str]:
    return sorted({g.grant_id for g in grants})


def grant_refs(grants: Iterable[GrantRow]) -> list[EvidenceRef]:
    return [
        EvidenceRef("grant", g.grant_id, f"{g.cloud} {g.verb} {g.service_category}@{g.scope_level}")
        for g in grants
    ]


def activity_key(identity_id: str, cloud: str, category: str, month: int) -> str:
    return f"{identity_id}|{cloud}|{category}|{month}"


def activity_refs(estate: EstateView, identity_id: str) -> list[EvidenceRef]:
    return [
        EvidenceRef(
            "activity",
            activity_key(a.identity_id, a.cloud, a.service_category, a.snapshot_month),
            f"last activity {a.last_activity_at.isoformat() if a.last_activity_at else 'never'}",
        )
        for a in estate.activity_for(identity_id)
    ]


def sort_evidence(evidence: Iterable[EvidenceRef]) -> list[EvidenceRef]:
    """Deduplicated, ordered by (kind, ref) so drafts are byte-stable across runs."""
    return sorted(set(evidence), key=lambda e: (e.kind, e.ref, e.note))


def iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


# ---------------------------------------------------------------------------
# Causal events (SPEC §9.2)
# ---------------------------------------------------------------------------


def _delta_entries(evt: EventRow) -> list[dict[str, Any]]:
    delta = evt.grant_delta or {}
    entries: list[Any] = []
    for key in ("added", "grants_added"):
        value = delta.get(key)
        if isinstance(value, list):
            entries.extend(value)
    return [e for e in entries if isinstance(e, dict)]


def _delta_matches(entry: dict[str, Any], grant: GrantRow) -> bool:
    gid = entry.get("grant_id")
    if gid:
        return bool(gid == grant.grant_id)
    keys = [k for k in ("principal_ref", "scope_ref", "granted_via", "cloud") if k in entry]
    if "principal_ref" not in keys and "scope_ref" not in keys:
        return False
    return all(entry[k] == getattr(grant, k) for k in keys)


def events_of_kind(estate: EstateView, identity_id: str, *kinds: str) -> list[EventRow]:
    return [e for e in estate.events_for(identity_id) if e.kind in kinds]


def causal_event_ids(
    estate: EstateView, identity_id: str, grants: Iterable[GrantRow], *kinds: str
) -> list[str]:
    """Ids of events that added any of the cited grants, plus events of the given causal kinds."""
    cited = list(grants)
    ids: set[str] = set()
    for evt in estate.events_for(identity_id):
        if evt.kind in kinds:
            ids.add(evt.event_id)
            continue
        if any(_delta_matches(entry, g) for entry in _delta_entries(evt) for g in cited):
            ids.add(evt.event_id)
    return sorted(ids)


def delta_values(evt: EventRow, key: str) -> list[str]:
    """String values of `key` in every dict entry under any list in the event's grant_delta."""
    delta = evt.grant_delta or {}
    values: list[str] = []
    for value in delta.values():
        if not isinstance(value, list):
            continue
        for entry in value:
            if isinstance(entry, dict) and isinstance(entry.get(key), str):
                values.append(entry[key])
    return values


def causal_event_ids_for_refs(
    estate: EstateView, identity_id: str, key: str, refs: Iterable[str]
) -> list[str]:
    """Ids of the identity's events whose grant_delta entries carry one of `refs` under `key`."""
    wanted = set(refs)
    return sorted(
        evt.event_id for evt in estate.events_for(identity_id) if wanted.intersection(delta_values(evt, key))
    )


def event_refs(events: Iterable[EventRow]) -> list[EvidenceRef]:
    return [EvidenceRef("event", e.event_id, f"{e.kind} in month {e.month}") for e in events]


# ---------------------------------------------------------------------------
# Governance exception register (SPEC §4.3) — never cloud tags
# ---------------------------------------------------------------------------


def expired_on(exc: ExceptionRow, as_of: date) -> date | None:
    """The earliest of review_date / expires_on that has passed by `as_of`."""
    passed = [d for d in (exc.review_date, exc.expires_on) if d is not None and d < as_of]
    return min(passed) if passed else None


def register_exception(
    estate: EstateView, identity_id: str, *types: str
) -> tuple[bool, str | None, list[EvidenceRef]]:
    """Consult the register: (suppressed, exception_expired_on ISO or None, evidence).

    A valid entry of one of `types` suppresses the rule. An expired entry does not
    suppress; it is cited as evidence and its expiry date is returned for the narrative.
    """
    if estate.valid_exception(identity_id, *types) is not None:
        return True, None, []
    exc = estate.expired_exception(identity_id, *types)
    if exc is None:
        return False, None, []
    when = expired_on(exc, estate.as_of)
    note = f"{exc.exception_type} expired on {iso(when)}"
    return False, iso(when), [EvidenceRef("exception", exc.exception_id, note)]


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


def common_facts(
    estate: EstateView,
    identity_id: str,
    *,
    principal: PrincipalRow | None = None,
    extra_clouds: Iterable[str] = (),
) -> dict[str, Any]:
    """The slots every rule provides (athar.detection.facts.COMMON_SLOTS)."""
    row = estate.identities.get(identity_id)
    clouds = set(estate.clouds_for(identity_id))
    clouds.update(extra_clouds)
    if row is not None:
        return {
            "identity_id": identity_id,
            "display_name": row.display_name,
            "department": row.department,
            "identity_type": row.identity_type,
            "clouds": sorted(clouds),
        }
    identity_type = "unknown"
    if principal is not None:
        identity_type = "human" if principal.principal_type == "user" else "service"
    # Not in the HR feed (e.g. an unlinked principal): no department to report.
    return {
        "identity_id": identity_id,
        "display_name": principal.principal_ref if principal else identity_id,
        "department": None,
        "identity_type": identity_type,
        "clouds": sorted(clouds),
    }


def draft(
    rule_id: str,
    identity_id: str,
    severity: str,
    evidence: Iterable[EvidenceRef],
    causal: Iterable[str],
    facts: dict[str, Any],
) -> FindingDraft:
    return FindingDraft(
        rule_id=rule_id,
        identity_id=identity_id,
        severity=severity,
        evidence=sort_evidence(evidence),
        causal_event_ids=sorted(set(causal)),
        facts=facts,
    )
