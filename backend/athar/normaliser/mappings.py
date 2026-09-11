"""Loader for the provider mapping YAML files (SPEC §5.3). Pure, cached, read-only.

`mappings/{aws,azure,gcp}.yaml` are the ONLY place provider actions / roles are mapped to
canonical (service_category, verb) pairs; `mappings/canonical.yaml` holds the dimension
vocabulary. Python never special-cases a provider action (CLAUDE.md conventions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from athar.domain import CATEGORIES, VERBS

MAPPINGS_DIR = Path(__file__).resolve().parent / "mappings"
UNKNOWN = "unknown"
Pair = tuple[str, str]


class MappingError(ValueError):
    """A mapping file is malformed (raised at load time, never during normalisation of data)."""


@dataclass(frozen=True)
class Canonical:
    verbs: tuple[str, ...]
    categories: dict[str, tuple[str, ...]]  # category → wildcard verb set


@dataclass(frozen=True)
class MappingEntry:
    key: str  # action / permission / role name as written in the YAML
    pairs: frozenset[Pair]
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderMapping:
    cloud: str
    services: dict[str, str]  # namespace / provider / permission prefix → category (lower-cased keys)
    actions: dict[str, MappingEntry]  # exact keys, lower-cased
    action_globs: tuple[tuple[str, MappingEntry], ...]  # keys containing "*" or "?", lower-cased
    roles: dict[str, MappingEntry]  # managed policies / built-in roles / predefined roles, lower-cased
    role_scope: dict[str, str]  # default scope_level per role (AWS managed policies → global)
    verb_inference: dict[str, str]  # lower-cased leading word → verb
    verb_suffixes: dict[str, str]  # lower-cased last segment → verb
    scope_levels: tuple[tuple[re.Pattern[str], str], ...]


# ---------------------------------------------------------------------------
# Canonical vocabulary and "category:verb" shorthand
# ---------------------------------------------------------------------------


def _read_yaml(name: str) -> dict[str, Any]:
    path = MAPPINGS_DIR / name
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise MappingError(f"{name}: top level must be a mapping")
    return data


@lru_cache(maxsize=1)
def canonical() -> Canonical:
    data = _read_yaml("canonical.yaml")
    verbs = tuple(str(v) for v in data.get("verbs", []))
    cats: dict[str, tuple[str, ...]] = {}
    for cat, vs in dict(data.get("categories", {})).items():
        cats[str(cat)] = tuple(str(v) for v in vs)
    if set(verbs) != set(VERBS) or set(cats) != set(CATEGORIES):
        raise MappingError("canonical.yaml disagrees with athar.domain vocabulary")
    for cat, vs in cats.items():
        bad = set(vs) - set(verbs)
        if bad:
            raise MappingError(f"canonical.yaml: {cat} lists unknown verbs {sorted(bad)}")
    return Canonical(verbs=verbs, categories=cats)


def resolve_maps(maps: list[str] | tuple[str, ...]) -> frozenset[Pair]:
    """Expand "category:verb" shorthand: "*" as category = every category; "*" as verb = the
    category's wildcard verb set (canonical.yaml); "*:*" = every category × its wildcard set."""
    canon = canonical()
    out: set[Pair] = set()
    for item in maps:
        cat, _, verb = str(item).partition(":")
        if not verb:
            raise MappingError(f"maps entry {item!r} is not category:verb")
        cats = list(canon.categories) if cat == "*" else [cat]
        for c in cats:
            if c not in canon.categories:
                raise MappingError(f"maps entry {item!r}: unknown category {c!r}")
            verbs = canon.categories[c] if verb == "*" else (verb,)
            for v in verbs:
                if v not in canon.verbs:
                    raise MappingError(f"maps entry {item!r}: unknown verb {v!r}")
                out.add((c, v))
    return frozenset(out)


def full_wildcard() -> frozenset[Pair]:
    """`*` / `*:*`: every category × its wildcard verbs — all seven verbs, all seven categories."""
    return resolve_maps(["*:*"])


# ---------------------------------------------------------------------------
# Provider mappings
# ---------------------------------------------------------------------------


def _entry(key: str, node: dict[str, Any]) -> MappingEntry:
    maps = node.get("maps")
    if not isinstance(maps, list) or not maps:
        raise MappingError(f"entry {key!r} has no maps")
    if any("*" in str(m) for m in maps) and not isinstance(node.get("expect"), list):
        raise MappingError(f"entry {key!r} uses a wildcard in maps but carries no explicit expect")
    return MappingEntry(key=key, pairs=resolve_maps(maps), raw=dict(node))


def _is_glob(key: str) -> bool:
    return "*" in key or "?" in key


@lru_cache(maxsize=3)
def load_mapping(cloud: str) -> ProviderMapping:
    if cloud not in ("aws", "azure", "gcp"):
        raise MappingError(f"no mapping for cloud {cloud!r}")
    data = _read_yaml(f"{cloud}.yaml")
    services = {str(k).lower(): str(v) for k, v in dict(data.get("services", {})).items()}
    for cat in services.values():
        if cat not in CATEGORIES:
            raise MappingError(f"{cloud}.yaml services: unknown category {cat!r}")

    actions: dict[str, MappingEntry] = {}
    globs: list[tuple[str, MappingEntry]] = []
    for node in list(data.get("actions", [])) + list(data.get("permissions", [])):
        key = str(node.get("action") or node.get("permission") or "")
        if not key:
            raise MappingError(f"{cloud}.yaml: action entry without key: {node}")
        entry = _entry(key, node)
        if _is_glob(key):
            globs.append((key.lower(), entry))
        else:
            actions[key.lower()] = entry

    roles: dict[str, MappingEntry] = {}
    role_scope: dict[str, str] = {}
    for node in list(data.get("managed_policies", [])) + list(data.get("roles", [])):
        names = [str(node[k]) for k in ("name", "arn", "id", "role") if node.get(k)]
        if not names:
            raise MappingError(f"{cloud}.yaml: role entry without name: {node}")
        entry = _entry(names[0], node)
        for n in names:
            roles[n.lower()] = entry
            if node.get("scope_level"):
                role_scope[n.lower()] = str(node["scope_level"])

    scope_levels = tuple(
        (re.compile(str(rule["pattern"]), re.IGNORECASE), str(rule["level"]))
        for rule in list(data.get("scope_levels", []))
    )
    return ProviderMapping(
        cloud=cloud,
        services=services,
        actions=actions,
        action_globs=tuple(globs),
        roles=roles,
        role_scope=role_scope,
        verb_inference={str(k).lower(): str(v) for k, v in dict(data.get("verb_inference", {})).items()},
        verb_suffixes={str(k).lower(): str(v) for k, v in dict(data.get("verb_suffixes", {})).items()},
        scope_levels=scope_levels,
    )


def raw_entries(cloud: str, section: str) -> list[dict[str, Any]]:
    """The YAML entries of a section, for data-driven tests."""
    return [dict(n) for n in list(_read_yaml(f"{cloud}.yaml").get(section, []))]


def scope_level(cloud: str, scope_ref: str) -> str:
    """SPEC §5.2 scope level of a provider scope string; first matching rule wins, else resource."""
    for pattern, level in load_mapping(cloud).scope_levels:
        if pattern.search(scope_ref.strip()):
            return level
    return "resource"


def category_for_service(cloud: str, service: str | None) -> str | None:
    """Namespace / provider / permission prefix → category; a canonical category name passes through."""
    if not service:
        return None
    key = service.strip()
    if key in CATEGORIES:
        return key
    return load_mapping(cloud).services.get(key.lower())


def role_pairs(cloud: str, role: str | None) -> frozenset[Pair] | None:
    """Pairs for a managed policy (name or ARN), an Azure built-in role (GUID or name) or a GCP
    predefined role; None when the YAML does not know it."""
    if not role:
        return None
    entry = load_mapping(cloud).roles.get(role.strip().lower())
    return entry.pairs if entry else None


def role_default_scope(cloud: str, role: str) -> str | None:
    return load_mapping(cloud).role_scope.get(role.strip().lower())
