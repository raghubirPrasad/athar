"""R4 Cross-cloud superuser (SPEC §7). Critical / High.

Critical when one identity holds `verb=admin` at `scope ≥ project` in all three clouds;
High when it holds `write ∧ delete` at `scope ≥ project` in all three (individually
acceptable roles — PowerUser / Contributor / Editor — that combine into control of
compute, storage and data everywhere). Admin in a cloud satisfies the High tier there.
"""

from __future__ import annotations

from athar.detection import common
from athar.detection.base import FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import CLOUDS, EstateView, GrantRow, Thresholds, scope_at_least

RULE_ID = "R4"
SEVERITY = "Critical"
SEVERITY_WRITE_DELETE = "High"


def _cloud_power(grants: list[GrantRow]) -> tuple[str, list[GrantRow]] | None:
    """('admin' | 'write_delete', cited grants) for one cloud's grants at scope ≥ project."""
    wide = [g for g in grants if scope_at_least(g.scope_level, "project")]
    admin = [g for g in wide if g.verb == "admin"]
    if admin:
        return "admin", admin
    writes = [g for g in wide if g.verb == "write"]
    deletes = [g for g in wide if g.verb == "delete"]
    if writes and deletes:
        return "write_delete", writes + deletes
    return None


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for identity_id in common.identity_ids(estate):
        grants = common.active_allow_grants(estate, identity_id)
        powers: dict[str, tuple[str, list[GrantRow]]] = {}
        for cloud in CLOUDS:
            power = _cloud_power([g for g in grants if g.cloud == cloud])
            if power is None:
                break
            powers[cloud] = power
        if len(powers) != len(CLOUDS):
            continue
        all_admin = all(p[0] == "admin" for p in powers.values())
        cited = [g for _, rows in powers.values() for g in rows]
        facts = common.common_facts(estate, identity_id)
        facts.update(
            power="admin" if all_admin else "write_delete",
            per_cloud={cloud: sorted({g.scope_ref for g in rows}) for cloud, (_, rows) in powers.items()},
            grant_ids=common.grant_ids(cited),
        )
        drafts.append(
            common.draft(
                RULE_ID,
                identity_id,
                SEVERITY if all_admin else SEVERITY_WRITE_DELETE,
                common.grant_refs(cited),
                common.causal_event_ids(estate, identity_id, cited),
                facts,
            )
        )
    return drafts


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Cross-cloud superuser",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=common.verify("T1078.004"),
        control_refs=common.verify("ISO 27001:2022 A.5.15"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="The same power across all three clouds: admin (Critical) or write and delete (High).",
    )
)
