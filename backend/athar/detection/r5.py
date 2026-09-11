"""R5 Toxic combination / self-escalation (SPEC §7, §8.1). High.

Three combinations, in canonical terms:
  write_identity+grant  `write` on `identity` ∧ `grant` at an overlapping scope
  impersonate+admin     `impersonate` whose target principal holds `admin`
  grant_self            a `grant` whose scope reaches the identity's own principal
The rule fires ONLY when the access graph (lane B, `athar.scoring.graph`) shows a
self-escalation path of ≤ 3 hops; that path is the evidence. `owns` edges (identity →
its own principal) cost nothing and are kept in the cited path for readability.

An unexpired `break-glass` or `approved-privileged-role` entry in the governance register
suppresses the finding, exactly as it does for R1: an administrator sanctioned under SPEC §4.3
necessarily holds both halves of the combination, so without this every approved administrator
would be a false positive. An expired entry does not suppress; the date is reported in
`exception_expired_on`. Cloud tags are never consulted (CLAUDE.md non-negotiable 9).
"""

from __future__ import annotations

from typing import Any

from athar.detection import common
from athar.detection.base import EvidenceRef, FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, GrantRow, Thresholds, scope_at_least
from athar.scoring import graph as access_graph
from athar.scoring.types import PathEdge

RULE_ID = "R5"
SEVERITY = "High"
MAX_PATH_LEN = 3
OWNS = "owns"
EXCEPTION_TYPES: tuple[str, ...] = ("break-glass", "approved-privileged-role")
COMBINATIONS: tuple[str, ...] = ("write_identity+grant", "impersonate+admin", "grant_self")


def _write_identity_and_grant(grants: list[GrantRow]) -> list[GrantRow]:
    writes = [g for g in grants if g.verb == "write" and g.service_category == "identity"]
    assigns = [g for g in grants if g.verb == "grant"]
    cited: list[GrantRow] = []
    for w in writes:
        for a in assigns:
            if common.scopes_overlap(w, a):
                cited.extend((w, a))
    return cited


def _impersonate_admin(estate: EstateView, grants: list[GrantRow]) -> list[GrantRow]:
    admin_by_principal: dict[str, list[GrantRow]] = {}
    for g in estate.grants:
        if g.active and g.effect == "allow" and g.verb == "admin":
            admin_by_principal.setdefault(g.principal_ref, []).append(g)
    cited: list[GrantRow] = []
    for imp in (g for g in grants if g.verb == "impersonate"):
        target = imp.scope_ref
        prefix = target[:-1] if target.endswith("*") else None
        for principal_ref in sorted(admin_by_principal):
            if principal_ref == target or (prefix is not None and principal_ref.startswith(prefix)):
                cited.append(imp)
                cited.extend(admin_by_principal[principal_ref])
    return cited


def _grant_self(estate: EstateView, identity_id: str, grants: list[GrantRow]) -> list[GrantRow]:
    own_refs = {p.principal_ref for p in common.own_principals(estate, identity_id)}
    own_refs.update(g.principal_ref for g in grants)
    own_clouds = {g.cloud for g in grants}
    cited: list[GrantRow] = []
    for g in (g for g in grants if g.verb == "grant"):
        stripped = g.scope_ref.rstrip("*")
        covers_own_ref = g.scope_ref in own_refs or any(
            stripped and ref.startswith(stripped) for ref in own_refs
        )
        # SPEC? a `grant` at project scope or above in a cloud where the identity has a
        # principal is read as "can grant to itself"; the graph path is the real gate.
        wide_same_cloud = scope_at_least(g.scope_level, "project") and g.cloud in own_clouds
        if covers_own_ref or wide_same_cloud:
            cited.append(g)
    return cited


def _combination(
    estate: EstateView, identity_id: str, grants: list[GrantRow]
) -> tuple[str, list[GrantRow]] | None:
    for name in COMBINATIONS:
        if name == "write_identity+grant":
            cited = _write_identity_and_grant(grants)
        elif name == "impersonate+admin":
            cited = _impersonate_admin(estate, grants)
        else:
            cited = _grant_self(estate, identity_id, grants)
        if cited:
            return name, cited
    return None


def hops(path: list[PathEdge]) -> int:
    """Edges that cost a hop; `owns` is free (SPEC §8.1, graph contract)."""
    return sum(1 for e in path if e.verb != OWNS)


def path_ref(path: list[PathEdge]) -> str:
    return "->".join([path[0].src, *(e.dst for e in path)])


def _shortest(paths: list[list[PathEdge]]) -> list[PathEdge]:
    return sorted(paths, key=lambda p: (hops(p), path_ref(p)))[0]


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    candidates: list[tuple[str, str, list[GrantRow]]] = []
    for identity_id in common.identity_ids(estate):
        grants = common.active_allow_grants(estate, identity_id)
        combo = _combination(estate, identity_id, grants)
        if combo is not None:
            candidates.append((identity_id, combo[0], combo[1]))
    if not candidates:
        return []
    graph = access_graph.build_graph(estate)

    grants_by_id = {g.grant_id: g for g in estate.grants}
    drafts: list[FindingDraft] = []
    for identity_id, combination, cited in candidates:
        suppressed, expired_on, exc_evidence = common.register_exception(
            estate, identity_id, *EXCEPTION_TYPES
        )
        if suppressed:
            continue
        paths = graph.escalation_paths(identity_id, max_len=MAX_PATH_LEN)
        paths = [p for p in paths if 0 < hops(p) <= MAX_PATH_LEN]
        if not paths:
            continue
        path = _shortest(paths)
        path_grants = [grants_by_id[e.grant_id] for e in path if e.grant_id and e.grant_id in grants_by_id]
        all_grants = {g.grant_id: g for g in [*cited, *path_grants]}.values()
        facts: dict[str, Any] = common.common_facts(estate, identity_id)
        facts.update(
            combination=combination,
            path=[e.as_dict() for e in path],
            path_len=hops(path),
            grant_ids=common.grant_ids(all_grants),
            exception_expired_on=expired_on,
        )
        evidence = [
            EvidenceRef("path", path_ref(path), f"{combination}; {hops(path)} hop(s)"),
            *common.grant_refs(all_grants),
            *exc_evidence,
        ]
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY,
                evidence,
                common.causal_event_ids(estate, identity_id, all_grants),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Toxic combination",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1098", "T1548"),
        control_refs=common.verify("ISO 27001:2022 A.5.15", "ISO 27001:2022 A.8.2"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="Permissions that combine into a self-escalation path of at most three hops.",
    )
)
