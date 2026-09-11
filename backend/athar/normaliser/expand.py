"""Wildcard expansion of provider actions into canonical pairs (SPEC §5.3). Pure.

`expand_action(cloud, action)` → sorted list of `(service_category, verb)`:
  * `*` / `*:*`         → every category × its wildcard verb set (all verbs, all categories)
  * `s3:*`              → every wildcard verb on storage; `iam:*` → admin, grant, impersonate on identity
  * `s3:Get*`           → union of the listed s3 actions matching the glob, else inferred from the verb word
  * listed action       → its YAML pairs
  * unlisted action     → verb inferred from the leading word (AWS) / last segment (Azure, GCP) on the
                          service's category; an uninferrable verb yields `(category, "unknown")`
  * unknown service     → `[("unknown", "unknown")]` (finding R0, never a crash)
Deterministic, idempotent, property-tested in tests/unit/test_expand.py.
"""

from __future__ import annotations

import fnmatch
import re

from athar.normaliser.mappings import (
    UNKNOWN,
    Pair,
    ProviderMapping,
    canonical,
    full_wildcard,
    load_mapping,
)

_FULL_WILDCARDS: frozenset[str] = frozenset({"*", "*:*", "*/*"})
_LEADING_WORD = re.compile(r"^([A-Z][a-z]+)")


def _sorted(pairs: set[Pair] | frozenset[Pair]) -> list[Pair]:
    return sorted(pairs)


def _unknown() -> list[Pair]:
    return [(UNKNOWN, UNKNOWN)]


def _category_wildcard(category: str) -> set[Pair]:
    return {(category, v) for v in canonical().categories.get(category, ())}


def _listed(mapping: ProviderMapping, key: str) -> frozenset[Pair] | None:
    entry = mapping.actions.get(key)
    if entry is not None:
        return entry.pairs
    for pattern, glob_entry in mapping.action_globs:
        if pattern == key:
            return glob_entry.pairs
    return None


def _glob_union(mapping: ProviderMapping, key: str) -> set[Pair]:
    """Union of listed exact actions that the (lower-cased) glob matches."""
    out: set[Pair] = set()
    for listed_key, entry in mapping.actions.items():
        if fnmatch.fnmatchcase(listed_key, key):
            out |= entry.pairs
    return out


def _infer_aws(mapping: ProviderMapping, category: str, name: str) -> Pair:
    """`GetObject` → read, `CreateBucket` → write … via the YAML verb_inference table."""
    m = _LEADING_WORD.match(name)
    if m:
        verb = mapping.verb_inference.get(m.group(1).lower())
        if verb:
            return (category, verb)
    # longest-prefix pass for two-word keys such as BatchGet
    for word, verb in sorted(mapping.verb_inference.items(), key=lambda kv: -len(kv[0])):
        if name.lower().startswith(word):
            return (category, verb)
    return (category, UNKNOWN)


def _expand_aws(mapping: ProviderMapping, action: str) -> list[Pair]:
    service, sep, name = action.partition(":")
    if not sep or not name:
        return _unknown()
    category = mapping.services.get(service.lower())
    if category is None:
        return _unknown()
    key = action.lower()
    listed = _listed(mapping, key)
    if listed is not None:
        return _sorted(listed)
    if name == "*":
        return _sorted(_category_wildcard(category))
    if "*" in name or "?" in name:
        union = _glob_union(mapping, key)
        if union:
            return _sorted(union)
        stem = re.split(r"[*?]", name, maxsplit=1)[0]
        inferred = _infer_aws(mapping, category, stem) if stem else (category, UNKNOWN)
        return [inferred] if inferred[1] != UNKNOWN else _sorted(_category_wildcard(category))
    return [_infer_aws(mapping, category, name)]


def _specific_glob(pattern: str) -> bool:
    """Glob entries that describe concrete actions (`Microsoft.Security/*/read`), as opposed to a
    provider wildcard (`Microsoft.Storage/*`) or a cross-provider one (`*/read`), which only apply
    when a role definition literally contains that wildcard string."""
    head, _, tail = pattern.partition("/")
    return head != "*" and tail != "*"


def _expand_azure(mapping: ProviderMapping, action: str) -> list[Pair]:
    parts = [p for p in action.split("/") if p]
    if not parts:
        return _unknown()
    key = action.lower()
    listed = _listed(mapping, key)
    if listed is not None:
        return _sorted(listed)
    provider, last = parts[0], parts[-1].lower()
    if provider == "*":
        verb = mapping.verb_suffixes.get(last)
        return [(c, verb) for c in canonical().categories] if verb else _unknown()
    category = mapping.services.get(provider.lower())
    if category is None:
        return _unknown()
    if last == "*":
        return _sorted(_category_wildcard(category))
    if "*" not in key:
        for pattern, entry in mapping.action_globs:
            if _specific_glob(pattern) and fnmatch.fnmatchcase(key, pattern):
                return _sorted(entry.pairs)
    verb = mapping.verb_suffixes.get(last)
    return [(category, verb or UNKNOWN)]


def _expand_gcp(mapping: ProviderMapping, action: str) -> list[Pair]:
    if action.startswith("roles/"):
        entry = mapping.roles.get(action.lower())
        if entry is not None:
            return _sorted(entry.pairs)
        # roles/<service>.<name>: the service alone tells the category, never the verb
        service = action[len("roles/") :].split(".", 1)[0].lower()
        category = mapping.services.get(service)
        return [(category, UNKNOWN)] if category else _unknown()
    parts = action.split(".")
    if len(parts) < 2:
        return _unknown()
    key = action.lower()
    listed = _listed(mapping, key)
    if listed is not None:
        return _sorted(listed)
    for pattern, entry in mapping.action_globs:
        if fnmatch.fnmatchcase(key, pattern):
            return _sorted(entry.pairs)
    category = mapping.services.get(parts[0].lower())
    if category is None:
        return _unknown()
    last = parts[-1]
    if last == "*":
        return _sorted(_category_wildcard(category))
    verb = mapping.verb_suffixes.get(last.lower())
    if verb == "admin" and category == "identity":
        verb = "grant"  # setIamPolicy on an identity container = assign-role (SPEC §5.3)
    return [(category, verb or UNKNOWN)]


def expand_action(cloud: str, action: str) -> list[Pair]:
    """Canonical `(service_category, verb)` pairs for one provider action string. Sorted, deterministic."""
    text = (action or "").strip()
    if not text:
        return _unknown()
    if text in _FULL_WILDCARDS:
        return _sorted(full_wildcard())
    if cloud not in ("aws", "azure", "gcp"):
        return _unknown()
    mapping = load_mapping(cloud)
    if cloud == "aws":
        return _expand_aws(mapping, text)
    if cloud == "azure":
        return _expand_azure(mapping, text)
    return _expand_gcp(mapping, text)


def expand_actions(cloud: str, actions: list[str]) -> set[Pair]:
    out: set[Pair] = set()
    for a in actions:
        out.update(expand_action(cloud, a))
    return out


def subtract(allowed: set[Pair], excluded: set[Pair]) -> set[Pair]:
    """`NotAction` / `notActions` semantics: what remains after removing the excluded pairs."""
    return {p for p in allowed if p not in excluded}
