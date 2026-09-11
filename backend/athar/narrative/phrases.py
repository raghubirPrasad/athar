"""Phrase table for the three altitudes (SPEC §10.2). Pure functions; no time, no randomness.

Every canonical fact has one business phrasing so the same data always yields the same
sentence. Headline phrases never use cloud-provider terms; explanation helpers may.
"""

from __future__ import annotations

from datetime import date

from athar.clock import month_label

CLOUD_NAMES: dict[str, str] = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}

_NUMBER_WORDS: tuple[str, ...] = (
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
)
MAX_SIMULATED_MONTH = 1200  # a century; anything beyond is not a simulated month (SPEC §4.5)

_TRIGGER_PHRASES: dict[str, str] = {
    "role_change": "a role change",
    "departure": "a departure",
    "new_hire": "a new hire",
    "project_launch": "a project launch",
    "project_retirement": "a project retirement",
    "incident_response": "an incident response",
    "mfa_lapse": "a multi-factor authentication lapse",
    "region_drift": "a region change",
    "remediation": "a remediation",
    "activity_stop": "a stop in activity",
    "grant": "a grant",
    "revoke": "a revocation",
}

_VERB_PHRASES: dict[str, str] = {
    "admin": "administrative",
    "grant": "permission-granting",
    "impersonate": "impersonation",
    "write": "write",
    "delete": "delete",
    "billing": "billing",
    "read": "read",
}

SELF_GRANT_PHRASE = "can give themselves any permission they want"
UNKNOWN = "unknown"


# --- numbers and lists -------------------------------------------------------


def number_word(n: int, below: int = 10) -> str:
    """Numbers as words below `below` (default ten), digits from there ("two", "34").

    `below` may be raised to 21 for fixed small quantities such as the analysis window
    ("in twelve months", SPEC §9.3).
    """
    return _NUMBER_WORDS[n] if 0 <= n < min(below, len(_NUMBER_WORDS)) else str(n)


def count_phrase(n: int, singular: str, plural: str) -> str:
    return f"{number_word(n)} {singular if n == 1 else plural}"


def months_from_days(days: int) -> int:
    """dormant N days → N months, never below one."""
    return max(1, round(days / 30))


def months_phrase(months: int) -> str:
    return count_phrase(months, "month", "months")


def join_and(items: list[str]) -> str:
    if not items:
        return "none"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


# --- clouds ------------------------------------------------------------------


def cloud_name(cloud: object) -> str:
    return CLOUD_NAMES.get(str(cloud).lower(), str(cloud)) if cloud else UNKNOWN


def clouds_list(clouds: object) -> str:
    """'AWS, Azure and GCP' — explanation/evidence altitude only."""
    if not isinstance(clouds, list) or not clouds:
        return "no cloud"
    return join_and([cloud_name(c) for c in clouds])


def clouds_count_phrase(clouds: object) -> str:
    """Headline-safe: 'all three clouds' / 'two clouds' / 'one cloud'."""
    n = len(clouds) if isinstance(clouds, list) else 0
    if n >= 3:
        return "all three clouds"
    return count_phrase(n, "cloud", "clouds")


# --- dates -------------------------------------------------------------------


def format_date(value: object) -> str:
    """'12 March 2026' from a date or ISO string; 'an unknown date' otherwise."""
    d: date | None = None
    if isinstance(value, date):
        d = value
    elif isinstance(value, str):
        try:
            d = date.fromisoformat(value[:10])
        except ValueError:
            d = None
    if d is None:
        return "an unknown date"
    return f"{d.day} {d.strftime('%B %Y')}"


def month_or_unknown(month: object) -> str:
    """'May 2026' for a plausible simulated month number; 'unknown' for anything else."""
    if isinstance(month, bool) or not isinstance(month, int) or not 1 <= month <= MAX_SIMULATED_MONTH:
        return UNKNOWN
    return month_label(month)


# --- the phrase table (SPEC §10.2) -------------------------------------------


def scope_phrase(scope_level: object) -> str:
    level = str(scope_level)
    if level in ("org", "global"):
        return "everything in the account"
    if level == "project":
        return "an entire project"
    if level == "resource":
        return "a single resource"
    return "an unknown scope"


def admin_phrase(scope_level: object) -> str:
    """admin at org/global → 'unrestricted control over everything in the account'."""
    return f"unrestricted control over {scope_phrase(scope_level)}"


def delete_data_phrase() -> str:
    return "can permanently destroy production data"


def dormant_phrase(days: object) -> str:
    """dormant N days → 'has not been used in N months'."""
    if not isinstance(days, int):
        return "has not been used for an unknown period"
    return f"has not been used in {months_phrase(months_from_days(days))}"


def departed_phrase(month: object) -> str:
    return f"left the organisation in {month_or_unknown(month)}"


def retired_project_phrase(month: object) -> str:
    return f"belongs to a project retired in {month_or_unknown(month)}"


def exception_expired_phrase(value: object) -> str:
    return f"their exception expired on {format_date(value)}"


def cross_cloud_phrase(power: object) -> str:
    if power == "admin":
        return "holds the same power in all three clouds"
    return "can change and destroy resources in all three clouds"


def residency_phrase() -> str:
    return "reaches sensitive data held outside approved regions"


def stale_key_phrase(age_days: object) -> str:
    if not isinstance(age_days, int):
        return "uses a credential whose rotation date is unknown"
    return f"uses a credential that has not been rotated in {months_phrase(months_from_days(age_days))}"


def no_mfa_phrase() -> str:
    return "holds administrative power without multi-factor authentication"


def unowned_phrase() -> str:
    return "an account nobody in HR owns"


def combination_phrase(combination: object) -> str:
    """R5 combinations. Unknown vocabulary falls back to the self-grant phrasing."""
    key = str(combination).lower()
    if "impersonat" in key:
        return "can act as an administrator by impersonating a more powerful account"
    return SELF_GRANT_PHRASE


def outlier_phrase() -> str:
    return "holds far more access than colleagues in the same department"


def identity_type_phrase(identity_type: object) -> str:
    if identity_type == "human":
        return "employee"
    if identity_type == "service":
        return "service account"
    return "identity"


def verbs_phrase(verbs: object) -> str:
    """['admin','grant'] → 'administrative and permission-granting powers'."""
    if not isinstance(verbs, list) or not verbs:
        return "privileged powers"
    words = [_VERB_PHRASES.get(str(v), str(v)) for v in verbs]
    return f"{join_and(words)} {'power' if len(words) == 1 else 'powers'}"


def trigger_phrase(trigger: object) -> str:
    """Causal sentence: 'when a role change added …'."""
    return _TRIGGER_PHRASES.get(str(trigger), "an unrecorded change")


def kind_phrase(kind: object) -> str:
    return {"key": "access key", "password": "password", "sa_key": "service-account key"}.get(
        str(kind), "credential"
    )


def principal_type_phrase(principal_type: object) -> str:
    return {
        "user": "user",
        "role": "role",
        "group": "group",
        "service_account": "service account",
        "service_principal": "service principal",
        "managed_identity": "managed identity",
    }.get(str(principal_type), "principal")
