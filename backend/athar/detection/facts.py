"""Fact-slot contract between rules (producers) and narratives/agents (consumers).

Every FindingDraft.facts dict for a rule MUST contain the keys listed here (values are
JSON-serialisable: str, int, float, bool, list, dict, None). Extra keys are allowed.
Narrative templates (`narrative/catalogue.yaml`) reference these slots by name. If you
need a new slot, add it here first.

Common slots every rule provides (filled by the rule):
  identity_id, display_name, department, identity_type, clouds: list[str]
  `department` is None (not a string) for synthetic identities outside the HR feed, i.e. the
  "unlinked:<cloud>:<ref>" identities that R10 fires on; consumers must not assume str.
"""

from __future__ import annotations

COMMON_SLOTS: tuple[str, ...] = ("identity_id", "display_name", "department", "identity_type", "clouds")

RULE_SLOTS: dict[str, tuple[str, ...]] = {
    # mapping miss
    "R0": ("cloud", "raw_action", "principal_ref", "grant_ids"),
    # wildcard / admin privilege
    "R1": (
        "cloud",
        "scope_level",
        "scope_ref",
        "granted_via",
        "grant_ids",
        "wildcard",
        "exception_expired_on",
    ),
    # dormant access
    "R2": ("dormant_days", "last_activity_at", "clouds_with_write", "grant_ids", "exception_expired_on"),
    # orphaned identity
    "R3": (
        "orphan_kind",
        "departure_month",
        "months_since_departure",
        "project_id",
        "retired_month",
        "grant_ids",
    ),
    # cross-cloud superuser
    "R4": (
        "power",
        "per_cloud",
        "grant_ids",
    ),  # power ∈ {"admin","write_delete"}; per_cloud {cloud: [scope_ref]}
    # toxic combination / self-escalation
    # path: list[{src,verb,dst,grant_id}]; exception_expired_on is set when an expired
    # break-glass / approved-privileged-role entry was found (it does not suppress).
    "R5": ("combination", "path", "path_len", "grant_ids", "exception_expired_on"),
    # stale credential
    "R6": ("credential_ref", "cloud", "kind", "age_days", "last_rotated_at", "threshold_days"),
    # peer outlier
    "R7": (
        "grant_count",
        "department_median",
        "department_mad",
        "categories_over",
        "peer_categories",
        "grant_ids",
    ),
    # data-residency drift
    "R8": ("cloud", "region", "approved_regions", "resource_ref", "resource_sensitivity", "grant_ids"),
    # privileged human without MFA
    "R9": ("privileged_verbs", "clouds_privileged", "grant_ids"),
    # unowned principal
    "R10": ("cloud", "principal_ref", "principal_type", "link_attempts", "grant_ids"),
}

# allowed_actions per rule (SPEC §11.4) — the ONLY vocabulary agents may choose from
RULE_ALLOWED_ACTIONS: dict[str, tuple[str, ...]] = {
    "R0": ("no_action_recommended", "tag_as_exception"),
    "R1": ("downgrade_to_least_privilege", "revoke_grant", "tag_as_exception", "no_action_recommended"),
    "R2": (
        "revoke_grant",
        "downgrade_to_least_privilege",
        "disable_identity",
        "tag_as_exception",
        "no_action_recommended",
    ),
    "R3": ("disable_identity", "remove_cloud_access", "revoke_grant", "tag_as_exception"),
    "R4": (
        "downgrade_to_least_privilege",
        "remove_cloud_access",
        "revoke_grant",
        "tag_as_exception",
        "no_action_recommended",
    ),
    "R5": ("revoke_grant", "downgrade_to_least_privilege", "tag_as_exception", "no_action_recommended"),
    "R6": ("rotate_or_disable_credential", "disable_identity", "tag_as_exception", "no_action_recommended"),
    "R7": ("downgrade_to_least_privilege", "revoke_grant", "no_action_recommended", "tag_as_exception"),
    "R8": ("revoke_grant", "tag_as_exception", "no_action_recommended"),
    "R9": ("downgrade_to_least_privilege", "disable_identity", "tag_as_exception", "no_action_recommended"),
    "R10": ("remove_cloud_access", "disable_identity", "tag_as_exception", "no_action_recommended"),
}


def required_slots(rule_id: str) -> tuple[str, ...]:
    return COMMON_SLOTS + RULE_SLOTS[rule_id]


def missing_slots(rule_id: str, facts: dict[str, object]) -> list[str]:
    return [k for k in required_slots(rule_id) if k not in facts]
