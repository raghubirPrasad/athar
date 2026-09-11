"""Load and validate `catalogue.yaml` once (SPEC §10.2).

Validation runs on first load: every rule R0–R10 has headline / explanation /
remediation_effect and a rule_text entry (name, summary, declared severity per SPEC §7), every `{slot}` resolves to a fact slot
(athar.detection.facts) or a declared derived slot (athar.narrative.slots), and no
template uses a format spec or conversion (slots render as plain strings).
"""

from __future__ import annotations

import string
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from athar.detection.facts import RULE_SLOTS, required_slots
from athar.narrative.slots import known_slots

CATALOGUE_PATH = Path(__file__).with_name("catalogue.yaml")
ALTITUDE_KEYS: tuple[str, ...] = ("headline", "explanation", "remediation_effect")
RULE_IDS: tuple[str, ...] = tuple(sorted(RULE_SLOTS, key=lambda r: int(r[1:])))


class CatalogueError(ValueError):
    """The catalogue is malformed. Raised at load time, never at render time."""


def template_slots(template: str) -> list[str]:
    """Slot names referenced by a template, in order of appearance."""
    names: list[str] = []
    for _literal, field_name, spec, conversion in string.Formatter().parse(template):
        if field_name is None:
            continue
        if spec or conversion:
            raise CatalogueError(f"format spec or conversion not allowed in template: {template!r}")
        names.append(field_name)
    return names


def validate(doc: dict[str, Any]) -> None:
    rules = doc.get("rules")
    rule_text = doc.get("rule_text")
    if not isinstance(rules, dict) or not isinstance(rule_text, dict):
        raise CatalogueError("catalogue needs top-level 'rules' and 'rule_text' mappings")
    for rule_id in RULE_IDS:
        text = rule_text.get(rule_id)
        if not isinstance(text, dict) or not all(text.get(k) for k in ("name", "summary", "severity")):
            raise CatalogueError(f"rule_text.{rule_id} needs name, summary and severity")
        entry = rules.get(rule_id)
        if not isinstance(entry, dict):
            raise CatalogueError(f"rules.{rule_id} missing")
        allowed = set(required_slots(rule_id)) | known_slots(rule_id)
        for key in ALTITUDE_KEYS:
            template = entry.get(key)
            if not isinstance(template, str) or not template.strip():
                raise CatalogueError(f"rules.{rule_id}.{key} missing")
            unknown = [s for s in template_slots(template) if s not in allowed]
            if unknown:
                raise CatalogueError(f"rules.{rule_id}.{key} references unknown slots {unknown}")


@cache
def load() -> dict[str, Any]:
    with CATALOGUE_PATH.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise CatalogueError("catalogue.yaml is not a mapping")
    validate(doc)
    return doc


def template(rule_id: str, key: str) -> str | None:
    entry = load()["rules"].get(rule_id)
    return entry.get(key) if isinstance(entry, dict) else None


def rule_text(rule_id: str) -> dict[str, str]:
    entry = load()["rule_text"].get(rule_id)
    return dict(entry) if isinstance(entry, dict) else {}
