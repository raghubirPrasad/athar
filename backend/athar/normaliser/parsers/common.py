"""Helpers shared by the provider parsers. Pure; tolerant of missing and odd values."""

from __future__ import annotations

import csv
import io
import math
from datetime import date, datetime
from typing import Any

from athar.domain import CATEGORIES
from athar.normaliser.expand import expand_action
from athar.normaliser.mappings import UNKNOWN, category_for_service
from athar.normaliser.types import UNKNOWN_PAIR, Pair

_MISSING_TOKENS: frozenset[str] = frozenset(
    {"", "n/a", "na", "nan", "none", "null", "not_supported", "no_information", "-"}
)


def text(value: Any) -> str:
    """A string for any JSON/CSV scalar; None / NaN / non-scalars become ''."""
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, (dict, list)):
        return ""
    return str(value).strip()


def text_or_none(value: Any) -> str | None:
    s = text(value)
    return None if s.lower() in _MISSING_TOKENS else s


def parse_date(value: Any) -> date | None:
    """ISO-8601 date or timestamp (`Z`, offset, fractional seconds) → date; anything else → None."""
    s = text_or_none(value)
    if s is None:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    s = text(value).lower()
    if s in ("true", "1", "yes", "y", "enabled", "active"):
        return True
    if s in ("false", "0", "no", "n", "disabled", "inactive"):
        return False
    return None


def parse_int(value: Any) -> int:
    s = text_or_none(value)
    if s is None:
        return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def lower_tags(tags: Any) -> dict[str, str]:
    """AWS `[{Key, Value}]`, Azure/GCP `{k: v}` → lower-cased-key dict of strings (evidence only)."""
    out: dict[str, str] = {}
    if isinstance(tags, dict):
        for k, v in tags.items():
            out[text(k).lower()] = text(v)
    elif isinstance(tags, list):
        for item in tags:
            if isinstance(item, dict):
                key = text(item.get("Key", item.get("key")))
                if key:
                    out[key.lower()] = text(item.get("Value", item.get("value")))
    return out


def max_date(a: date | None, b: date | None) -> date | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def read_csv_rows(data: str) -> tuple[list[str], list[dict[str, str]]]:
    """CSV → (header, rows). Lines starting with `#` (the SYNTHETIC marker, SPEC §4.1) and blank
    lines are skipped; a UTF-8 BOM is stripped; header names are lower-cased and trimmed."""
    lines = [
        ln for ln in data.lstrip("\ufeff").splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not lines:
        return [], []
    reader = csv.reader(io.StringIO("\n".join(lines)))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        return [], []
    rows: list[dict[str, str]] = []
    for values in reader:
        if not any(v.strip() for v in values):
            continue
        row = {header[i]: (values[i].strip() if i < len(values) else "") for i in range(len(header))}
        rows.append(row)
    return header, rows


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def expand_many(cloud: str, actions: list[str]) -> tuple[set[Pair], list[str]]:
    """Canonical pairs for a list of raw actions plus the actions the mapping does not know."""
    pairs: set[Pair] = set()
    unmapped: list[str] = []
    for action in actions:
        got = expand_action(cloud, action)
        if got == [UNKNOWN_PAIR]:
            unmapped.append(action)
        pairs.update(got)
    return pairs, unmapped


def sorted_pairs(pairs: set[Pair]) -> tuple[Pair, ...]:
    return tuple(sorted(pairs))


def category_of_ref_service(cloud: str, service: str | None, fallback: str = UNKNOWN) -> str:
    cat = category_for_service(cloud, service)
    if cat in CATEGORIES:
        return cat
    return fallback


def dominant_category(pairs: tuple[Pair, ...]) -> str:
    """The single category of a pair set, else `unknown` (used only for derived resources)."""
    cats = sorted({c for c, _ in pairs if c in CATEGORIES})
    return cats[0] if len(cats) == 1 else UNKNOWN
