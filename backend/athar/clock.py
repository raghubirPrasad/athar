"""Simulated clock (SPEC §4.5). The only time source for generator and domain code.

Month 1 == 2025-09-01. Domain code never calls `datetime.now()`.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime, timedelta

EPOCH = date(2025, 9, 1)  # month 1


def month_start(month: int) -> date:
    if month < 1:
        raise ValueError("month must be >= 1")
    idx = (EPOCH.year * 12 + EPOCH.month - 1) + (month - 1)
    return date(idx // 12, idx % 12 + 1, 1)


def month_end(month: int) -> date:
    start = month_start(month)
    return date(start.year, start.month, calendar.monthrange(start.year, start.month)[1])


def month_label(month: int) -> str:
    """'September 2025' — used by narratives ("left the organisation in <Month YYYY>")."""
    return month_start(month).strftime("%B %Y")


def month_of(d: date) -> int:
    """Inverse of month_start for any date on/after the epoch."""
    return (d.year - EPOCH.year) * 12 + (d.month - EPOCH.month) + 1


def days_between(a: date, b: date) -> int:
    return (b - a).days


def date_in_month(month: int, day_fraction: float) -> date:
    """Deterministic date inside a month from a [0,1) fraction supplied by the seeded RNG."""
    start = month_start(month)
    days = (month_end(month) - start).days
    return start + timedelta(days=int(day_fraction * (days + 1)))


def iso_ts(d: date, hour: int = 9, minute: int = 0) -> str:
    """Provider-style ISO-8601 timestamp for a simulated date (UTC 'Z')."""
    return datetime(d.year, d.month, d.day, hour, minute, 0).strftime("%Y-%m-%dT%H:%M:%SZ")
