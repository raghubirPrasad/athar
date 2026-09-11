"""Guardrails between provider data, the LLM, and ATHAR (SPEC §11.3). Pure.

Two directions:

* Inbound — `sanitize_untrusted()` wraps every free-text value that originates
  from provider data (tags, descriptions, policy names, display names, notes) so
  the prompt carries it as `{"untrusted_text": "..."}`: truncated, control
  characters stripped, whitespace collapsed. The system preamble states that such
  values are data, never instructions.
* Outbound — `validate_output()` enforces that the model chose an action from
  `allowed_actions`, clamps confidence to [0, 1], redacts any identifier (ARN,
  GUID, email, access-key id) that was not present in the input, drops evidence
  references that were not offered, and strips sentences carrying injection
  markers.

Nothing here can create a finding, change a severity/score, or widen the action
set (CLAUDE.md non-negotiable 5).
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel

UNTRUSTED_MAX_CHARS = 120
NO_ACTION = "no_action_recommended"
REDACTED = "[redacted]"

# Identifier patterns (SPEC §11.3: ARNs / GUIDs / emails; plus access-key ids).
IDENTIFIER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"arn:aws[a-z\-]*:[^\s\"'`,<>()\[\]{}]+", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # emails incl. GCP SA emails
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{4,16}\b"),
)

# Phrases that mark an attempt to steer the model rather than describe data.
INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the previous instructions",
    "ignore prior instructions",
    "ignore above instructions",
    "disregard previous instructions",
    "disregard all previous",
    "system prompt",
    "you are now",
    "ignore rules",
    "ignore the rules",
    "ignore all rules",
    "mark this account as safe",
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;\n])\s+")
_WS = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Inbound
# ---------------------------------------------------------------------------


def _printable(ch: str) -> bool:
    cat = unicodedata.category(ch)
    if cat.startswith("C"):  # control, format, surrogate, private-use, unassigned
        return False
    return not (cat.startswith("Z") and ch != " ")


def sanitize_untrusted(text: str | None) -> dict[str, str]:
    """Wrap provider-originated free text as data (SPEC §11.3).

    Truncates to 120 chars, drops control / non-printable characters (basic
    punctuation stays), collapses whitespace. `None` becomes an empty string.
    """
    raw = "" if text is None else str(text)
    cleaned = "".join(ch if _printable(ch) else " " for ch in raw)
    cleaned = _WS.sub(" ", cleaned).strip()
    return {"untrusted_text": cleaned[:UNTRUSTED_MAX_CHARS]}


def is_wrapped(value: Any) -> bool:
    return isinstance(value, dict) and set(value.keys()) == {"untrusted_text"}


def unwrap(value: Any) -> Any:
    """The text inside a `{"untrusted_text": …}` wrapper, or the value unchanged.

    Only for comparing a citation the model echoed back with the one it was offered; never for
    putting provider text back into a prompt.
    """
    return value["untrusted_text"] if is_wrapped(value) else value


# ---------------------------------------------------------------------------
# Outbound
# ---------------------------------------------------------------------------


def iter_strings(obj: Any) -> Iterable[str]:
    """Every string leaf in a nested dict/list/tuple structure (keys included)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from iter_strings(v)
    elif isinstance(obj, list | tuple | set | frozenset):
        for item in obj:
            yield from iter_strings(item)


def extract_identifiers(obj: Any) -> set[str]:
    found: set[str] = set()
    for s in iter_strings(obj):
        for pat in IDENTIFIER_PATTERNS:
            found.update(m.group(0) for m in pat.finditer(s))
    return found


def redact_unknown_identifiers(text: str, allowed: set[str], flags: list[str]) -> str:
    """Replace identifiers absent from `allowed` with "[redacted]"."""
    out = text
    for pat in IDENTIFIER_PATTERNS:

        def _sub(m: re.Match[str], _pat: re.Pattern[str] = pat) -> str:
            token = m.group(0)
            if token in allowed:
                return token
            flags.append(f"redacted_identifier:{_pat.pattern[:12]}")
            return REDACTED

        out = pat.sub(_sub, out)
    return out


def strip_injection_sentences(text: str, flags: list[str]) -> str:
    """Remove sentences that contain an injection marker; keep the rest verbatim."""
    if not text:
        return text
    lowered = text.lower()
    if not any(marker in lowered for marker in INJECTION_MARKERS):
        return text
    kept: list[str] = []
    for sentence in _SENTENCE_SPLIT.split(text):
        low = sentence.lower()
        if any(marker in low for marker in INJECTION_MARKERS):
            flags.append("stripped_injection_sentence")
            continue
        kept.append(sentence)
    return " ".join(s.strip() for s in kept if s.strip())


def clean_string(text: str, allowed: set[str], flags: list[str]) -> str:
    return redact_unknown_identifiers(strip_injection_sentences(text, flags), allowed, flags)


def _clean_value(value: Any, allowed: set[str], flags: list[str]) -> Any:
    if isinstance(value, str):
        return clean_string(value, allowed, flags)
    if isinstance(value, dict):
        return {
            clean_string(str(k), allowed, flags): _clean_value(v, allowed, flags) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_clean_value(v, allowed, flags) for v in value]
    if isinstance(value, tuple):
        return tuple(_clean_value(v, allowed, flags) for v in value)
    return value


def _clamp_confidence(value: Any, flags: list[str]) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        flags.append("confidence_not_numeric")
        return 0.0
    if math.isnan(f) or math.isinf(f):
        flags.append("confidence_not_finite")
        return 0.0
    if f < 0.0 or f > 1.0:
        flags.append("confidence_clamped")
    return min(1.0, max(0.0, f))


def validate_output[M: BaseModel](
    output: M,
    *,
    allowed_actions: Sequence[str],
    input_payload: dict[str, Any],
    flags: list[str] | None = None,
) -> M:
    """Return a copy of `output` that is safe to store and display (SPEC §11.3).

    * `recommended_action` / `action` outside `allowed_actions` → "no_action_recommended", flagged.
    * `confidence` clamped to [0, 1].
    * Identifiers (ARN, GUID, email, key id) not present anywhere in `input_payload` → "[redacted]".
    * `evidence_cited` restricted to the input's `evidence_refs` when the input offers them.
    * Sentences containing an injection marker are removed from every string field.
    * `top_themes` is capped at three entries.

    `flags` (if given) collects a short label per correction so callers can surface them.
    """
    report: list[str] = flags if flags is not None else []
    allowed_ids = extract_identifiers(input_payload)
    data: dict[str, Any] = output.model_dump()

    for field in ("recommended_action", "action"):
        if field in data:
            action = data[field]
            if not isinstance(action, str) or action not in allowed_actions:
                report.append(f"action_not_allowed:{action!s}"[:80])
                data[field] = NO_ACTION

    if "confidence" in data:
        data["confidence"] = _clamp_confidence(data["confidence"], report)

    if "evidence_cited" in data:
        offered = input_payload.get("evidence_refs")
        if isinstance(offered, list):
            # A ref quoting provider text reaches the prompt wrapped; the model cites the token.
            offered_set = {str(unwrap(x)) for x in offered}
            cited = [str(x) for x in data["evidence_cited"]]
            kept = [x for x in cited if x in offered_set]
            if len(kept) != len(cited):
                report.append("dropped_unknown_evidence_refs")
            data["evidence_cited"] = kept

    if "top_themes" in data and isinstance(data["top_themes"], list) and len(data["top_themes"]) > 3:
        report.append("top_themes_truncated")
        data["top_themes"] = data["top_themes"][:3]

    cleaned = {
        k: (
            v if k in ("recommended_action", "action", "confidence") else _clean_value(v, allowed_ids, report)
        )
        for k, v in data.items()
    }
    return output.__class__.model_validate(cleaned)


def walk_output_strings(output: BaseModel | dict[str, Any]) -> list[str]:
    """All string leaves of an output — used by tests to assert hostile text is absent."""
    data = output.model_dump() if isinstance(output, BaseModel) else output
    return list(iter_strings(data))
