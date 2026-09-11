"""CSV formula-injection defence (SPEC §15.2, OWASP "CSV Injection"). Pure.

A spreadsheet treats a cell beginning with `=`, `+`, `-` or `@` as a formula, and some treat a
leading tab / CR / LF as a field-separator trick. Prefixing a single quote makes the cell literal
text in Excel, LibreOffice and Google Sheets. Leading whitespace before a trigger is neutralised
too, because some importers trim it before evaluating.
"""

from __future__ import annotations

FORMULA_TRIGGERS: frozenset[str] = frozenset("=+-@")
CONTROL_TRIGGERS: frozenset[str] = frozenset("\t\r\n")
_LEADING_WHITESPACE = " \t\r\n\x0b\x0c"
ESCAPE_PREFIX = "'"


def is_formula_like(value: str) -> bool:
    """True when a spreadsheet could interpret `value` as a formula or control sequence."""
    if not value:
        return False
    if value[0] in FORMULA_TRIGGERS or value[0] in CONTROL_TRIGGERS:
        return True
    stripped = value.lstrip(_LEADING_WHITESPACE)
    return bool(stripped) and stripped[0] in FORMULA_TRIGGERS


def escape_cell(value: str) -> str:
    """Return `value` prefixed with `'` when it is formula-like; unchanged otherwise. Idempotent."""
    if is_formula_like(value):
        return ESCAPE_PREFIX + value
    return value
