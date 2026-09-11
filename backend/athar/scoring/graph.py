"""Access graph (SPEC §8.1). INTERFACE CONTRACT — implemented in lane B (scoring).

Nodes: identities (`id:<identity_id>`), cloud principals (`p:<principal_ref>`), resources (`r:<resource_ref>`).
Edges (attribute `verb`, optional `grant_id`):
  principal --verb--> resource       for verb ∈ {write, delete, admin, grant, billing}
  identity  --impersonate--> principal   (PassRole / actAs / assume-role trust)
  identity  --grant--> principal         every principal at the grant's scope (can rewrite their permissions)
  identity  --grant-self--> resource     any resource at scope, if the identity can grant to itself
  identity  --owns--> principal          the identity's own principals (traversal only, weight 0)
Reachability = BFS depth ≤ 4; the path is retained for the evidence altitude.

Implementation notes (lane C2):
  * Parallel edges between the same pair are folded into one networkx edge whose `verbs`
    attribute is a sorted tuple of `(verb, grant_id)`; `verb`/`grant_id` hold the first pair.
  * The principal that *holds* an impersonate/grant grant also gets `principal --verb--> principal`
    edges to the same targets, so chains (A impersonates P, P can rewrite Q, Q is admin) compose
    within the depth limit. Identity nodes have no incoming edges.
  * Membership: a grant reaches every resource of its `service_category` inside its scope
    (`admin` ignores category — it is unrestricted control). SPEC? §8.1 names no category
    filter; the narrower reading is kept so a storage write cannot "reach" a compute
    instance. `project` scope reaches the
    resources whose `project_ref` sits in the same account / subscription / project as the
    scope_ref (see `scope_container`); `org`/`global` reach the whole cloud; `resource` scope
    matches `resource_ref` equal to or prefixed by the scope_ref stripped of a trailing `*`/`/*`.
  * An explicit deny at equal or higher scope on the same principal/category/verb cancels the
    allow before any edge is drawn (`cancel_by_deny`, SPEC §5.2 `effect`).
  * `owns` edges cost 0 hops; every other edge costs 1. Traversal runs at the principal layer
    over a precomputed chain adjacency (grant / impersonate edges only) and unions per-principal
    resource sets, so 500 identities × 1500 grants × 300 resources build and score in well
    under two seconds.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from athar.domain import CONTROL_VERBS, SCOPE_RANK, EstateView, GrantRow, scope_at_least
from athar.scoring.types import PathEdge

MAX_DEPTH = 4
ESCALATION_MAX_LEN = 3

OWNS = "owns"
GRANT = "grant"
GRANT_SELF = "grant-self"
IMPERSONATE = "impersonate"
ADMIN = "admin"

# verbs that mean "control over a resource" when they end a path (grant-self ⊇ grant)
REACH_VERBS: frozenset[str] = frozenset(CONTROL_VERBS | {GRANT_SELF})
# verbs that let a path continue from one principal to another
_CHAIN_VERBS: frozenset[str] = frozenset({GRANT, IMPERSONATE})

# hard caps that keep path enumeration bounded on adversarial estates; traversal is
# deterministic so the caps never change which paths come first
PATH_LIMIT = 10
ESCALATION_LIMIT = 25
_EXPANSION_BUDGET = 20_000

_AWS_ACCOUNT = re.compile(r"^\d{12}$")
_AZURE_SUB = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)
_GCP_PROJECT_PATH = re.compile(r"(?:^|/)projects/([^/]+)")
_GCP_SA_EMAIL = re.compile(r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com$", re.IGNORECASE)
_GCP_MEMBER_PREFIX = re.compile(r"^(?:user|serviceAccount|group|domain|deleted):", re.IGNORECASE)

# raw principal keys that may name the principal's account / subscription / project
_RAW_CONTAINER_KEYS: tuple[str, ...] = (
    "scope",
    "subscriptionId",
    "subscription",
    "project",
    "projectId",
    "account",
    "accountId",
)

ChainEdge = tuple[str, str | None, str]  # (verb, grant_id, dst node)


def identity_node(identity_id: str) -> str:
    return f"id:{identity_id}"


def principal_node(principal_ref: str) -> str:
    return f"p:{principal_ref}"


def resource_node(resource_ref: str) -> str:
    return f"r:{resource_ref}"


def _is_identity(node: str) -> bool:
    return node.startswith("id:")


def _is_principal(node: str) -> bool:
    return node.startswith("p:")


def _is_resource(node: str) -> bool:
    return node.startswith("r:")


def _ref_of(node: str) -> str:
    """Strip the node prefix (`id:` / `p:` / `r:`)."""
    return node.split(":", 1)[1]


# ---------------------------------------------------------------------------
# Scope helpers (pure)
# ---------------------------------------------------------------------------


def strip_wildcard(ref: str) -> str:
    """`arn:aws:s3:::bucket/*` → `arn:aws:s3:::bucket`, `nda-*` → `nda-`; `*` → ``."""
    out = ref.strip()
    while out.endswith("*"):
        out = out[:-1]
        if out.endswith("/"):
            out = out[:-1]
    return out


def ref_matches(candidate: str, scope_ref: str) -> bool:
    """Exact match, or `candidate` starts with the scope_ref stripped of its trailing wildcard."""
    if candidate == scope_ref:
        return True
    prefix = strip_wildcard(scope_ref)
    if prefix == "":
        return scope_ref.endswith("*")  # a bare wildcard matches everything, an empty ref nothing
    return candidate.startswith(prefix)


def scope_container(cloud: str, ref: str | None) -> str | None:
    """The account / subscription / project a ref belongs to, or None when it names no container.

    aws:   `arn:aws:iam::123456789012:role/x` → `123456789012`; a bare 12-digit account id → itself
    azure: `/subscriptions/<sub>/resourceGroups/rg` → `/subscriptions/<sub>` (case-insensitive)
    gcp:   `projects/p/…`, `//…/projects/p`, `sa@p.iam.gserviceaccount.com`, bare `p` → `p`
    `*`, `/`, org / management-group / folder refs and user emails → None.
    """
    if not ref:
        return None
    ref = ref.strip()
    if ref in ("*", "/"):
        return None
    if cloud == "aws":
        if _AWS_ACCOUNT.match(ref):
            return ref
        if ref.startswith("arn:"):
            parts = ref.split(":", 5)
            if len(parts) >= 5 and _AWS_ACCOUNT.match(parts[4]):
                return parts[4]
        return None
    if cloud == "azure":
        m = _AZURE_SUB.match(ref)
        return f"/subscriptions/{m.group(1).lower()}" if m else None
    if cloud == "gcp":
        m = _GCP_PROJECT_PATH.search(ref)
        if m:
            return m.group(1)
        m = _GCP_SA_EMAIL.search(ref)
        if m:
            return m.group(1).lower()
        if _GCP_MEMBER_PREFIX.match(ref) or "@" in ref or "/" in ref or ":" in ref:
            return None
        return ref
    return None


def _norm_project(cloud: str, project_ref: str | None) -> str | None:
    """Resources carry `project_ref` in whichever form the normaliser chose; compare containers."""
    if project_ref is None:
        return None
    return scope_container(cloud, project_ref) or project_ref


def _deny_covers(deny: GrantRow, allow: GrantRow) -> bool:
    if deny.scope_level not in SCOPE_RANK or allow.scope_level not in SCOPE_RANK:
        return False
    if SCOPE_RANK[deny.scope_level] < SCOPE_RANK[allow.scope_level]:
        return False
    if deny.scope_level in ("org", "global"):
        return True
    if deny.scope_level == "project":
        # an S3 ARN carries no account: fall back to the holder's own container (same principal)
        target = scope_container(allow.cloud, allow.scope_ref) or scope_container(
            allow.cloud, allow.principal_ref
        )
        container = scope_container(deny.cloud, deny.scope_ref) or scope_container(
            deny.cloud, deny.principal_ref
        )
        return target is not None and target == container
    return ref_matches(allow.scope_ref, deny.scope_ref)


def cancel_by_deny(grants: list[GrantRow]) -> list[GrantRow]:
    """Active allow grants that no active explicit deny cancels (SPEC §5.2, `effect`).

    A deny cancels an allow on the same principal, cloud, service_category and verb when its
    scope is equal or higher and contains the allow's scope. Deny rows are never returned.
    """
    denies: dict[tuple[str, str, str, str], list[GrantRow]] = defaultdict(list)
    for g in grants:
        if g.active and g.effect == "deny":
            denies[(g.principal_ref, g.cloud, g.service_category, g.verb)].append(g)
    kept: list[GrantRow] = []
    for g in grants:
        if not g.active or g.effect != "allow":
            continue
        candidates = denies.get((g.principal_ref, g.cloud, g.service_category, g.verb), [])
        if any(_deny_covers(d, g) for d in candidates):
            continue
        kept.append(g)
    return kept


# ---------------------------------------------------------------------------
# Scope index: precomputed membership per (cloud, level, ref[, category])
# ---------------------------------------------------------------------------


class _ScopeIndex:
    """Resource and principal membership per scope, computed once per estate."""

    def __init__(self, estate: EstateView, grants: list[GrantRow]) -> None:
        self._resources: dict[str, list[tuple[str, str, str | None]]] = defaultdict(list)
        for r in sorted(estate.resources.values(), key=lambda x: x.resource_ref):
            self._resources[r.cloud].append(
                (r.resource_ref, r.service_category, _norm_project(r.cloud, r.project_ref))
            )

        clouds: dict[str, str] = {}
        raw: dict[str, dict[str, Any]] = {}
        for p in estate.principals.values():
            clouds[p.principal_ref] = p.cloud
            raw[p.principal_ref] = p.raw
        containers: dict[str, set[str]] = defaultdict(set)
        for g in grants:
            clouds.setdefault(g.principal_ref, g.cloud)
            c = scope_container(g.cloud, g.scope_ref)
            if c:
                containers[g.principal_ref].add(c)
        for ref, cloud in clouds.items():
            c = scope_container(cloud, ref)
            if c:
                containers[ref].add(c)
            for key in _RAW_CONTAINER_KEYS:
                val = raw.get(ref, {}).get(key)
                if isinstance(val, str):
                    c = scope_container(cloud, val)
                    if c:
                        containers[ref].add(c)
        self.principal_cloud: dict[str, str] = clouds
        self._principals: dict[str, list[str]] = defaultdict(list)
        for ref in sorted(clouds):
            self._principals[clouds[ref]].append(ref)
        self._containers: dict[str, frozenset[str]] = {
            ref: frozenset(containers.get(ref, ())) for ref in clouds
        }
        self._res_cache: dict[tuple[str, str, str, str | None], tuple[str, ...]] = {}
        self._pr_cache: dict[tuple[str, str, str], tuple[str, ...]] = {}

    def containers_of(self, principal_ref: str) -> frozenset[str]:
        return self._containers.get(principal_ref, frozenset())

    def resources_in_scope(self, cloud: str, level: str, ref: str, category: str | None) -> tuple[str, ...]:
        key = (cloud, level, ref, category)
        hit = self._res_cache.get(key)
        if hit is not None:
            return hit
        rows = self._resources.get(cloud, [])
        if level in ("org", "global"):
            out = [r for r, cat, _ in rows if category is None or cat == category]
        elif level == "project":
            container = scope_container(cloud, ref)
            out = [
                r
                for r, cat, prj in rows
                if prj is not None and prj == container and (category is None or cat == category)
            ]
        else:
            out = [r for r, cat, _ in rows if (category is None or cat == category) and ref_matches(r, ref)]
        result = tuple(out)
        self._res_cache[key] = result
        return result

    def resources_in_container(
        self, cloud: str, container: str | None, category: str | None
    ) -> tuple[str, ...]:
        if container is None:
            return ()
        return self.resources_in_scope(cloud, "project", container, category)

    def principals_in_scope(self, cloud: str, level: str, ref: str) -> tuple[str, ...]:
        key = (cloud, level, ref)
        hit = self._pr_cache.get(key)
        if hit is not None:
            return hit
        refs = self._principals.get(cloud, [])
        if level in ("org", "global"):
            out = list(refs)
        elif level == "project":
            container = scope_container(cloud, ref)
            out = [p for p in refs if container is not None and container in self._containers[p]]
        else:
            out = [p for p in refs if _principal_ref_matches(p, ref)]
        result = tuple(out)
        self._pr_cache[key] = result
        return result

    def principals_in_container(self, cloud: str, container: str | None) -> tuple[str, ...]:
        if container is None:
            return ()
        return self.principals_in_scope(cloud, "project", container)


def _principal_ref_matches(principal_ref: str, scope_ref: str) -> bool:
    """Equality / wildcard prefix, tolerant of GCP `serviceAccount:` member prefixes."""
    if ref_matches(principal_ref, scope_ref):
        return True
    bare_p = _GCP_MEMBER_PREFIX.sub("", principal_ref)
    bare_s = _GCP_MEMBER_PREFIX.sub("", scope_ref)
    stripped = bare_p != principal_ref or bare_s != scope_ref
    return stripped and ref_matches(bare_p, bare_s)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


@dataclass
class AccessGraph:
    g: nx.DiGraph
    estate: EstateView
    _reach_cache: dict[str, tuple[set[str], list[list[PathEdge]]]] = field(default_factory=dict, repr=False)
    _esc_cache: dict[str, list[list[PathEdge]]] = field(default_factory=dict, repr=False)
    _principal_resources: dict[str, frozenset[str]] = field(default_factory=dict, repr=False)
    _chain_adj: dict[str, tuple[ChainEdge, ...]] = field(default_factory=dict, repr=False)
    _self_adj: dict[str, tuple[tuple[str | None, str], ...]] = field(default_factory=dict, repr=False)
    _own: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _admin: frozenset[str] = field(default_factory=frozenset, repr=False)
    _indexed: bool = field(default=False, repr=False)

    # -- private index -------------------------------------------------------
    def _ensure_index(self) -> None:
        """Per-node adjacency split by edge role, computed once: resource sets, chain edges, grant-self."""
        if self._indexed:
            return
        for node in self.g.nodes:
            if _is_resource(node):
                continue
            chain: list[ChainEdge] = []
            resources: set[str] = set()
            self_edges: list[tuple[str | None, str]] = []
            owned: list[str] = []
            for dst, attrs in self.g.adj[node].items():
                if _is_resource(dst):
                    if _is_principal(node):
                        resources.add(_ref_of(dst))
                    else:
                        self_edges.extend((gid, dst) for v, gid in attrs["verbs"] if v == GRANT_SELF)
                    continue
                for verb, gid in attrs["verbs"]:
                    if verb == OWNS:
                        owned.append(dst)
                    elif verb in _CHAIN_VERBS:
                        chain.append((verb, gid, dst))
            self._chain_adj[node] = tuple(
                sorted(chain, key=lambda e: (_verb_priority(e[0]), e[2], e[1] or ""))
            )
            if _is_principal(node):
                self._principal_resources[node] = frozenset(resources)
            else:
                self._self_adj[node] = tuple(sorted(self_edges, key=lambda e: (e[1], e[0] or "")))
                self._own[_ref_of(node)] = tuple(sorted(owned))
        self._admin = frozenset(n for n in self._principal_resources if self.g.nodes[n].get("admin"))
        self._indexed = True

    def own_principals(self, identity_id: str) -> tuple[str, ...]:
        """Principal nodes the identity owns (sorted)."""
        self._ensure_index()
        return self._own.get(identity_id, ())

    def is_admin(self, principal_node_id: str) -> bool:
        """True when the principal holds `admin` at scope ≥ project (after deny cancellation)."""
        return bool(self.g.nodes[principal_node_id].get("admin")) if principal_node_id in self.g else False

    def _explore(self, identity_id: str, max_depth: int) -> tuple[dict[str, int], dict[str, PathEdge]]:
        """BFS at the principal layer: depth (hops, owns = 0) and predecessor edge per reached principal."""
        self._ensure_index()
        start = identity_node(identity_id)
        depth: dict[str, int] = {}
        pred: dict[str, PathEdge] = {}
        if start not in self.g:
            return depth, pred
        queue: deque[str] = deque()
        for dst in self._own.get(identity_id, ()):
            depth[dst] = 0
            pred[dst] = PathEdge(start, OWNS, dst, None)
            queue.append(dst)
        for verb, gid, dst in self._chain_adj.get(start, ()):
            if dst in depth:
                continue  # owned principals are already at depth 0
            depth[dst] = 1
            pred[dst] = PathEdge(start, verb, dst, gid)
            queue.append(dst)
        while queue:
            node = queue.popleft()
            d = depth[node]
            if d >= max_depth:
                continue
            for verb, gid, dst in self._chain_adj.get(node, ()):
                if dst in depth:
                    continue
                depth[dst] = d + 1
                pred[dst] = PathEdge(node, verb, dst, gid)
                queue.append(dst)
        return depth, pred

    def _chain(self, pred: dict[str, PathEdge], node: str) -> list[PathEdge]:
        path: list[PathEdge] = []
        cur = node
        while cur in pred:
            edge = pred[cur]
            path.append(edge)
            cur = edge.src
        path.reverse()
        return path

    def _reach(self, identity_id: str, max_depth: int) -> tuple[set[str], list[list[PathEdge]]]:
        key = f"{identity_id}|{max_depth}"
        hit = self._reach_cache.get(key)
        if hit is not None:
            return hit
        depth, pred = self._explore(identity_id, max_depth)
        start = identity_node(identity_id)
        reached: set[str] = set()
        direct: dict[str, PathEdge] = {}
        for gid, dst in self._self_adj.get(start, ()):
            direct.setdefault(_ref_of(dst), PathEdge(start, GRANT_SELF, dst, gid))
        reached.update(direct)
        ordered = sorted(depth, key=lambda n: (depth[n], n))
        for p in ordered:
            if depth[p] + 1 <= max_depth:
                reached |= self._principal_resources.get(p, frozenset())
        samples = self._sample_paths(reached, direct, ordered, depth, pred, max_depth)
        result = (reached, samples)
        self._reach_cache[key] = result
        return result

    def _sample_paths(
        self,
        reached: set[str],
        direct: dict[str, PathEdge],
        ordered: list[str],
        depth: dict[str, int],
        pred: dict[str, PathEdge],
        max_depth: int,
        limit: int = 3,
    ) -> list[list[PathEdge]]:
        """One shortest path each for a few reached resources (high sensitivity first)."""
        resources = self.estate.resources
        picks = sorted(
            reached, key=lambda r: (0 if r in resources and resources[r].sensitivity == "high" else 1, r)
        )
        out: list[list[PathEdge]] = []
        for ref in picks[:limit]:
            if ref in direct:
                out.append([direct[ref]])
                continue
            for p in ordered:
                if depth[p] + 1 <= max_depth and ref in self._principal_resources.get(p, frozenset()):
                    verb, gid = self.g.edges[p, resource_node(ref)]["verbs"][0]
                    out.append([*self._chain(pred, p), PathEdge(p, verb, resource_node(ref), gid)])
                    break
        return out

    # -- public interface ---------------------------------------------------
    def reachable_resources(self, identity_id: str, max_depth: int = MAX_DEPTH) -> set[str]:
        """resource_refs reachable from the identity with a control verb within max_depth hops."""
        return set(self._reach(identity_id, max_depth)[0])

    def sample_paths(self, identity_id: str, max_depth: int = MAX_DEPTH) -> list[list[PathEdge]]:
        """Shortest paths to a few reached resources (high-sensitivity first); evidence altitude."""
        return [list(p) for p in self._reach(identity_id, max_depth)[1]]

    def escalation_paths(self, identity_id: str, max_len: int = ESCALATION_MAX_LEN) -> list[list[PathEdge]]:
        """Paths of length ≤ max_len by which the identity can raise its own privilege:
        identity →grant→ principal(admin) ; identity →impersonate→ principal(admin) ; identity →grant-self→ resource.
        Empty list when none. Deterministic order (sorted by path string)."""
        key = f"{identity_id}|{max_len}"
        hit = self._esc_cache.get(key)
        if hit is not None:
            return [list(p) for p in hit]
        self._ensure_index()
        start = identity_node(identity_id)
        result: list[list[PathEdge]] = []
        if start in self.g and max_len > 0:
            # Iterative deepening: every path with d hops sorts before any path with d+1 hops, so
            # once the cap is met at depth d the deeper levels cannot change the returned list.
            # This is what keeps a dense estate (org-level `grant` → hundreds of principals) cheap.
            found: list[list[PathEdge]] = []
            for hops in range(1, max_len + 1):
                found.extend(self._escalations_at(identity_id, hops))
                result = _dedupe_paths(found)
                if len(result) >= ESCALATION_LIMIT:
                    break
            result = result[:ESCALATION_LIMIT]
        self._esc_cache[key] = result
        return [list(p) for p in result]

    def _escalations_at(self, identity_id: str, target: int) -> list[list[PathEdge]]:
        """Escalation paths with exactly `target` non-owns hops (owns edges cost nothing).

        A path ends in a `grant-self` edge (only identity nodes carry them) or in a chain edge
        whose target is an admin principal the identity does not already own.
        """
        start = identity_node(identity_id)
        own = set(self._own.get(identity_id, ()))
        admin = self._admin
        found: list[list[PathEdge]] = []
        budget = [_EXPANSION_BUDGET]

        def visit(
            node: str, path: list[PathEdge], hops: int, seen: frozenset[str], from_identity: bool
        ) -> None:
            last = hops + 1 == target
            if last:
                for gid, dst in self._self_adj.get(node, ()):
                    found.append([*path, PathEdge(node, GRANT_SELF, dst, gid)])
            for verb, gid, dst in self._chain_adj.get(node, ()):
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                if last:
                    if dst not in own and dst in admin:
                        found.append([*path, PathEdge(node, verb, dst, gid)])
                elif dst not in seen and not (from_identity and dst in own):
                    visit(dst, [*path, PathEdge(node, verb, dst, gid)], hops + 1, seen | {dst}, False)

        visit(start, [], 0, frozenset({start}), True)
        for p in self._own.get(identity_id, ()):
            visit(p, [PathEdge(start, OWNS, p, None)], 0, frozenset({start, p}), False)
        return found

    def paths_to(
        self, identity_id: str, resource_ref: str, max_depth: int = MAX_DEPTH
    ) -> list[list[PathEdge]]:
        """Simple paths (≤ max_depth hops, owns free) from the identity to the resource; sorted, capped."""
        self._ensure_index()
        start = identity_node(identity_id)
        target = resource_node(resource_ref)
        found: list[list[PathEdge]] = []
        if start not in self.g or target not in self.g or max_depth <= 0:
            return found
        budget = [_EXPANSION_BUDGET]

        def visit(node: str, path: list[PathEdge], hops: int, seen: frozenset[str]) -> None:
            direct = self.g.adj[node].get(target)
            if direct is not None:
                found.extend(
                    [*path, PathEdge(node, verb, target, gid)]
                    for verb, gid in direct["verbs"]
                    if verb != OWNS
                )
            for verb, gid, dst in self._chain_adj.get(node, ()):
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                if hops + 1 < max_depth and dst not in seen:
                    visit(dst, [*path, PathEdge(node, verb, dst, gid)], hops + 1, seen | {dst})

        visit(start, [], 0, frozenset({start}))
        for p in self._own.get(identity_id, ()):
            visit(p, [PathEdge(start, OWNS, p, None)], 0, frozenset({start, p}))
        return _dedupe_paths(found)[:PATH_LIMIT]


def path_string(path: list[PathEdge]) -> str:
    return " ; ".join(f"{e.src} -{e.verb}-> {e.dst}" for e in path)


def _hops(path: list[PathEdge]) -> int:
    return sum(1 for e in path if e.verb != OWNS)


def _dedupe_paths(paths: list[list[PathEdge]]) -> list[list[PathEdge]]:
    """Keep the shortest path per (verb, dst, grant_id) sequence (owns edges ignored); sort deterministically."""
    best: dict[tuple[tuple[str, str, str | None], ...], list[PathEdge]] = {}
    for p in paths:
        key = tuple((e.verb, e.dst, e.grant_id) for e in p if e.verb != OWNS)
        cur = best.get(key)
        if cur is None or (_hops(p), path_string(p)) < (_hops(cur), path_string(cur)):
            best[key] = p
    return sorted(best.values(), key=lambda p: (_hops(p), path_string(p)))


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def _verb_priority(verb: str) -> tuple[int, str]:
    order = {
        ADMIN: 0,
        GRANT: 1,
        GRANT_SELF: 2,
        IMPERSONATE: 3,
        "write": 4,
        "delete": 5,
        "billing": 6,
        OWNS: 9,
    }
    return (order.get(verb, 7), verb)


def _scope_resources(index: _ScopeIndex, g: GrantRow, category: str | None) -> tuple[str, ...]:
    """Resources inside the grant's scope; a project scope that names no container falls back to
    the holder's own account / subscription / project (SPEC? — the normaliser may emit `*`)."""
    if g.scope_level == "project" and scope_container(g.cloud, g.scope_ref) is None:
        out: list[str] = []
        for container in sorted(index.containers_of(g.principal_ref)):
            out.extend(index.resources_in_container(g.cloud, container, category))
        return tuple(sorted(set(out)))
    return index.resources_in_scope(g.cloud, g.scope_level, g.scope_ref, category)


def _scope_principals(index: _ScopeIndex, g: GrantRow) -> tuple[str, ...]:
    """Principals inside the grant's scope, with the same project-scope fallback as resources."""
    if g.scope_level == "project" and scope_container(g.cloud, g.scope_ref) is None:
        out: list[str] = []
        for container in sorted(index.containers_of(g.principal_ref)):
            out.extend(index.principals_in_container(g.cloud, container))
        return tuple(sorted(set(out)))
    return index.principals_in_scope(g.cloud, g.scope_level, g.scope_ref)


def build_graph(estate: EstateView) -> AccessGraph:
    """Build the graph for one snapshot. Pure; deterministic node/edge insertion order."""
    grants = cancel_by_deny(sorted(estate.grants, key=lambda x: x.grant_id))
    index = _ScopeIndex(estate, grants)

    admin_refs: set[str] = set()
    for g in grants:
        if g.verb == ADMIN and scope_at_least(g.scope_level, "project"):
            admin_refs.add(g.principal_ref)

    edges: dict[tuple[str, str], set[tuple[str, str | None]]] = defaultdict(set)

    for g in grants:
        ident = identity_node(g.identity_id)
        holder = principal_node(g.principal_ref)
        edges[(ident, holder)].add((OWNS, None))

        if g.verb in CONTROL_VERBS:
            category = None if g.verb == ADMIN else g.service_category
            for r in _scope_resources(index, g, category):
                edges[(holder, resource_node(r))].add((g.verb, g.grant_id))

        if g.verb in _CHAIN_VERBS:
            targets = _scope_principals(index, g)
            for t in targets:
                if t == g.principal_ref:
                    continue  # holding a grant/impersonate over oneself is not a hop
                tnode = principal_node(t)
                edges[(ident, tnode)].add((g.verb, g.grant_id))
                edges[(holder, tnode)].add((g.verb, g.grant_id))
            if g.verb == GRANT and g.principal_ref in targets:
                # can grant to itself → any resource at scope (all categories) is reachable
                own_scope = _scope_resources(index, g, None)
                if not own_scope and g.scope_level == "resource":
                    # the scope names the principal itself; "at scope" means its account/project
                    own_scope = index.resources_in_container(
                        g.cloud, scope_container(g.cloud, g.principal_ref), None
                    )
                for r in own_scope:
                    edges[(ident, resource_node(r))].add((GRANT_SELF, g.grant_id))

    for p in estate.principals.values():
        if p.identity_id:
            edges[(identity_node(p.identity_id), principal_node(p.principal_ref))].add((OWNS, None))

    graph = nx.DiGraph()
    for identity_id in sorted(estate.identities):
        graph.add_node(identity_node(identity_id), kind="identity")
    for ref in sorted(index.principal_cloud):
        graph.add_node(
            principal_node(ref), kind="principal", cloud=index.principal_cloud[ref], admin=ref in admin_refs
        )
    for ref in sorted(estate.resources):
        row = estate.resources[ref]
        graph.add_node(
            resource_node(ref),
            kind="resource",
            cloud=row.cloud,
            category=row.service_category,
            sensitivity=row.sensitivity,
        )
    # identities referenced only by grants (e.g. unlinked synthetic identities) still get a node
    for src, _dst in sorted(edges):
        if _is_identity(src) and src not in graph:
            graph.add_node(src, kind="identity")

    for src, dst in sorted(edges):
        verbs = tuple(sorted(edges[(src, dst)], key=lambda vg: (_verb_priority(vg[0]), vg[1] or "")))
        graph.add_edge(
            src,
            dst,
            verbs=verbs,
            verb_set=frozenset(v for v, _ in verbs),
            verb=verbs[0][0],
            grant_id=verbs[0][1],
        )

    return AccessGraph(g=graph, estate=estate)
