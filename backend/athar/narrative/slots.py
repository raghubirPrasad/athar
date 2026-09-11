"""Derived slots and the SafeDict used to fill templates (SPEC §10.2).

Rules provide the fact slots in athar.detection.facts; this module computes the
business phrasings the catalogue references. Missing or None facts never raise:
SafeDict renders "unknown" and logs a warning so the sentence still exists.
"""

from __future__ import annotations

import re
from typing import Any

from athar.domain import Thresholds
from athar.log import get_logger
from athar.narrative import phrases as p

log = get_logger(__name__)

_IDENTIFIER_LIKE = re.compile(
    r"(arn:|roles/|Microsoft\.|projects/|@|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}|AKIA[0-9A-Z]{8,}|://)"
)

COMMON_DERIVED: tuple[str, ...] = (
    "department_phrase",
    "identity_type_phrase",
    "clouds_list",
    "clouds_count_phrase",
    "grant_count",
    "grant_count_word",
    "grant_word",
    "threshold_dormant_days",
    "threshold_stale_key_days",
    "threshold_approved_regions",
)

RULE_DERIVED: dict[str, tuple[str, ...]] = {
    "R0": ("cloud_name",),
    "R1": ("cloud_name", "admin_phrase", "wildcard_headline_clause", "wildcard_clause"),
    "R2": ("dormant_months", "dormant_phrase", "last_activity_label", "clouds_with_write_phrase"),
    "R3": (
        "orphan_phrase",
        "orphan_explanation",
        "departed_label",
        "retired_label",
        "months_since_word",
    ),
    "R4": ("cross_cloud_phrase", "power_explanation", "per_cloud_phrase"),
    "R5": ("combination_phrase", "path_len_word", "step_word", "path_phrase"),
    "R6": ("cloud_name", "stale_phrase", "stale_months", "kind_phrase", "last_rotated_label"),
    "R7": (
        "outlier_phrase",
        "median_word",
        "categories_over_phrase",
        "category_word",
        "peer_categories_phrase",
    ),
    "R8": ("cloud_name", "residency_phrase", "approved_regions_phrase"),
    "R9": ("no_mfa_phrase", "verbs_phrase", "clouds_privileged_phrase"),
    "R10": ("cloud_name", "unowned_phrase", "principal_type_phrase", "link_attempts_phrase"),
}


def known_slots(rule_id: str) -> set[str]:
    return set(COMMON_DERIVED) | set(RULE_DERIVED.get(rule_id, ()))


class SafeDict(dict[str, Any]):
    """format_map source that never raises: missing or None → 'unknown' (logged once per slot)."""

    def __init__(self, data: dict[str, Any], rule_id: str = "") -> None:
        super().__init__(data)
        self.rule_id = rule_id
        self.missing: list[str] = []

    def __missing__(self, key: str) -> str:
        self._warn(key)
        return p.UNKNOWN

    def __getitem__(self, key: str) -> Any:
        value = super().__getitem__(key) if key in self else self.__missing__(key)
        if value is None:
            self._warn(key)
            return p.UNKNOWN
        return value

    def _warn(self, key: str) -> None:
        if key not in self.missing:
            self.missing.append(key)
            log.warning("narrative slot missing", extra={"rule_id": self.rule_id, "slot": key})


def safe_display_name(value: object) -> str:
    """Headlines carry no identifiers: an identifier-like display name is masked."""
    if not isinstance(value, str) or not value.strip():
        return "An unnamed identity"
    if _IDENTIFIER_LIKE.search(value):
        return "An unnamed account"
    return value


def path_edge_text(edge: Any) -> str:
    """'src --verb--> dst [grant_id]' from a dict or a PathEdge-like object."""
    get = edge.get if isinstance(edge, dict) else (lambda k, d=None: getattr(edge, k, d))
    src, verb, dst, grant_id = get("src"), get("verb"), get("dst"), get("grant_id")
    text = f"{src or p.UNKNOWN} --{verb or p.UNKNOWN}--> {dst or p.UNKNOWN}"
    return f"{text} [{grant_id}]" if grant_id else text


def _int(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else []


def _thresholds(thresholds: dict[str, Any] | None) -> dict[str, Any]:
    base = Thresholds().as_dict()
    if thresholds:
        base.update({k: v for k, v in thresholds.items() if v is not None})
    return base


def _common(facts: dict[str, Any], thresholds: dict[str, Any] | None) -> dict[str, Any]:
    department = facts.get("department")
    grant_ids = _list(facts.get("grant_ids"))
    n = _int(facts.get("grant_count"), len(grant_ids))  # R7 states its count; others carry grant_ids
    th = _thresholds(thresholds)
    return {
        "department_phrase": department if isinstance(department, str) and department else "no department",
        "identity_type_phrase": p.identity_type_phrase(facts.get("identity_type")),
        "clouds_list": p.clouds_list(facts.get("clouds")),
        "clouds_count_phrase": p.clouds_count_phrase(facts.get("clouds")),
        "grant_count": n,
        "grant_count_word": p.number_word(n),
        "grant_word": "grant" if n == 1 else "grants",
        "threshold_dormant_days": th.get("dormant_days"),
        "threshold_stale_key_days": th.get("stale_key_days"),
        "threshold_approved_regions": p.join_and([str(r) for r in _list(th.get("approved_regions"))]),
    }


def _r1(f: dict[str, Any]) -> dict[str, Any]:
    wildcard = bool(f.get("wildcard"))
    return {
        "cloud_name": p.cloud_name(f.get("cloud")),
        "admin_phrase": p.admin_phrase(f.get("scope_level")),
        "wildcard_headline_clause": " through an unrestricted wildcard permission" if wildcard else "",
        "wildcard_clause": " through an unexpanded wildcard action" if wildcard else "",
    }


def _r2(f: dict[str, Any]) -> dict[str, Any]:
    days = f.get("dormant_days")
    return {
        "dormant_months": p.months_from_days(days) if isinstance(days, int) else None,
        "dormant_phrase": p.dormant_phrase(days),
        "last_activity_label": p.format_date(f.get("last_activity_at"))
        if f.get("last_activity_at")
        else "the start of the window",
        "clouds_with_write_phrase": p.clouds_list(f.get("clouds_with_write")),
    }


def _r3(f: dict[str, Any], common: dict[str, Any]) -> dict[str, Any]:
    retired = f.get("orphan_kind") == "retired_project"
    departed_label = p.month_or_unknown(f.get("departure_month"))
    retired_label = p.month_or_unknown(f.get("retired_month"))
    months_since = p.number_word(_int(f.get("months_since_departure")))
    name, dept = f.get("display_name") or p.UNKNOWN, common["department_phrase"]
    n, word, clouds = common["grant_count_word"], common["grant_word"], common["clouds_list"]
    if retired:
        phrase = p.retired_project_phrase(f.get("retired_month"))
        explanation = (
            f"The service account {name} ({dept}) belongs to project {f.get('project_id') or p.UNKNOWN}, "
            f"retired in {retired_label}, yet {n} {word} remain active in {clouds}."
        )
    else:
        phrase = p.departed_phrase(f.get("departure_month"))
        explanation = (
            f"HR records {name} ({dept}) as departed since {departed_label} "
            f"({months_since} months ago), yet {n} {word} remain active in {clouds}."
        )
    return {
        "orphan_phrase": phrase,
        "orphan_explanation": explanation,
        "departed_label": departed_label,
        "retired_label": retired_label,
        "months_since_word": months_since,
    }


def _r4(f: dict[str, Any]) -> dict[str, Any]:
    raw = f.get("per_cloud")
    per_cloud: dict[Any, Any] = raw if isinstance(raw, dict) else {}
    parts = [
        f"{p.cloud_name(c)} ({p.count_phrase(len(_list(refs)), 'scope', 'scopes')})"
        for c, refs in sorted(per_cloud.items())
    ]
    power = f.get("power")
    return {
        "cross_cloud_phrase": p.cross_cloud_phrase(power),
        "power_explanation": "admin at project scope or above"
        if power == "admin"
        else "write and delete at project scope or above",
        "per_cloud_phrase": p.join_and(parts) if parts else "all three clouds",
    }


def _r5(f: dict[str, Any]) -> dict[str, Any]:
    path = _list(f.get("path"))
    n = _int(f.get("path_len"), len(path))
    return {
        "combination_phrase": p.combination_phrase(f.get("combination")),
        "path_len_word": p.number_word(n),
        "step_word": "step" if n == 1 else "steps",
        "path_phrase": "; ".join(path_edge_text(e) for e in path) if path else "path not recorded",
    }


def _r6(f: dict[str, Any]) -> dict[str, Any]:
    age = f.get("age_days")
    return {
        "cloud_name": p.cloud_name(f.get("cloud")),
        "stale_phrase": p.stale_key_phrase(age),
        "stale_months": p.months_phrase(p.months_from_days(age)) if isinstance(age, int) else "months",
        "kind_phrase": p.kind_phrase(f.get("kind")),
        "last_rotated_label": p.format_date(f.get("last_rotated_at")),
    }


def _r7(f: dict[str, Any]) -> dict[str, Any]:
    over = _int(f.get("categories_over"))
    peers = [str(c) for c in _list(f.get("peer_categories"))]
    median = f.get("department_median")
    return {
        "outlier_phrase": p.outlier_phrase(),
        "median_word": p.number_word(int(median)) if isinstance(median, int | float) else p.UNKNOWN,
        "categories_over_phrase": p.number_word(over),
        "category_word": "category" if over == 1 else "categories",
        "peer_categories_phrase": p.join_and(peers) if peers else "no recorded categories",
    }


def _r8(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "cloud_name": p.cloud_name(f.get("cloud")),
        "residency_phrase": p.residency_phrase(),
        "approved_regions_phrase": p.join_and([str(r) for r in _list(f.get("approved_regions"))]),
    }


def _r9(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "no_mfa_phrase": p.no_mfa_phrase(),
        "verbs_phrase": p.verbs_phrase(f.get("privileged_verbs")),
        "clouds_privileged_phrase": p.clouds_list(f.get("clouds_privileged")),
    }


def _r10(f: dict[str, Any]) -> dict[str, Any]:
    attempts = [str(a) for a in _list(f.get("link_attempts"))]
    return {
        "cloud_name": p.cloud_name(f.get("cloud")),
        "unowned_phrase": p.unowned_phrase(),
        "principal_type_phrase": p.principal_type_phrase(f.get("principal_type")),
        "link_attempts_phrase": f"tried {p.join_and(attempts)}" if attempts else "no link method matched",
    }


def derive_slots(
    rule_id: str, facts: dict[str, Any], thresholds: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Fact slots plus derived slots for one rule. Never raises on odd input."""
    facts = facts if isinstance(facts, dict) else {}
    common = _common(facts, thresholds)
    derived: dict[str, Any]
    match rule_id:
        case "R0":
            derived = {"cloud_name": p.cloud_name(facts.get("cloud"))}
        case "R1":
            derived = _r1(facts)
        case "R2":
            derived = _r2(facts)
        case "R3":
            derived = _r3(facts, common)
        case "R4":
            derived = _r4(facts)
        case "R5":
            derived = _r5(facts)
        case "R6":
            derived = _r6(facts)
        case "R7":
            derived = _r7(facts)
        case "R8":
            derived = _r8(facts)
        case "R9":
            derived = _r9(facts)
        case "R10":
            derived = _r10(facts)
        case _:
            derived = {}
    return {**facts, **common, **derived}
