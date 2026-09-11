"""R7 Peer outlier (SPEC §7). Low (heuristic).

An identity whose active grant count exceeds its department's median + 2·MAD and that
holds at least two service categories more than the department's median category count.
MAD is the median absolute deviation with scale factor 1.0 (1 when it is 0). Departments
with fewer than `MIN_PEERS` identities never fire. `peer_categories` lists the categories
held by at least half of the department (what a peer typically has).

# SPEC? §7's second term ("≥ 2 categories more than peers") is unsatisfiable on the estate the
# generator produces: almost every identity holds grants in all seven service categories, so the
# department median category count is already the maximum and `over` can never reach
# CATEGORY_MARGIN. Measured: R7 emits zero drafts in all twelve months of seed 42 and of seed 7.
# Reading "more than peers" as `len(categories - peer_categories)` instead does not rescue it
# (0–3 a month on seed 42, all of them the `unknown` mapping-miss category, which is R0's job).
# The statistical term on its own selects 29–50 identities a month, so dropping the category term
# would make R7 fire — but that changes what the rule means and needs a tuning pass on the tuning
# seed (§8.3, §17), so it is recorded in the README's known limitations and in PRD §7 rather than
# changed here. See tests/unit/test_rules_r7.py::test_saturated_department_cannot_fire.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import numpy as np

from athar.detection import common
from athar.detection.base import FindingDraft, RuleSpec
from athar.detection.facts import RULE_ALLOWED_ACTIONS
from athar.detection.registry import register
from athar.domain import EstateView, Thresholds

RULE_ID = "R7"
SEVERITY = "Low"
MIN_PEERS = 5
MAD_MULTIPLIER = 2.0
CATEGORY_MARGIN = 2


def median(values: list[int]) -> float:
    return float(np.median(np.asarray(values, dtype=float)))


def mad(values: list[int], centre: float) -> float:
    """Median absolute deviation, scale 1.0; 1.0 when every value equals the median."""
    spread = float(np.median(np.abs(np.asarray(values, dtype=float) - centre)))
    return spread if spread > 0 else 1.0


def _peer_categories(category_sets: list[set[str]]) -> list[str]:
    counts = Counter(c for cats in category_sets for c in cats)
    half = len(category_sets) / 2
    return sorted(c for c, n in counts.items() if n >= half)


def evaluate(estate: EstateView, thresholds: Thresholds) -> list[FindingDraft]:
    by_department: dict[str, list[str]] = defaultdict(list)
    for identity_id in sorted(estate.identities):
        by_department[estate.identities[identity_id].department].append(identity_id)

    drafts: list[FindingDraft] = []
    for department in sorted(by_department):
        members = by_department[department]
        if len(members) < MIN_PEERS:
            continue
        grants = {m: common.active_allow_grants(estate, m) for m in members}
        counts = {m: len(grants[m]) for m in members}
        categories = {m: {g.service_category for g in grants[m]} for m in members}
        centre = median(list(counts.values()))
        spread = mad(list(counts.values()), centre)
        median_categories = median([len(c) for c in categories.values()])
        threshold = centre + MAD_MULTIPLIER * spread
        peers = _peer_categories(list(categories.values()))
        for m in members:
            over = len(categories[m]) - median_categories
            if counts[m] <= threshold or over < CATEGORY_MARGIN:
                continue
            facts = common.common_facts(estate, m)
            facts.update(
                grant_count=counts[m],
                department_median=centre,
                department_mad=spread,
                categories_over=int(over),
                peer_categories=peers,
                peer_category_count=median_categories,
                grant_ids=common.grant_ids(grants[m]),
            )
            drafts.append(
                common.draft(
                    RULE_ID,
                    m,
                    SEVERITY,
                    common.grant_refs(grants[m]),
                    common.causal_event_ids(estate, m, grants[m]),
                    facts,
                )
            )
    return sorted(drafts, key=lambda d: d.identity_id)


RULE = register(
    RuleSpec(
        id=RULE_ID,
        name="Peer outlier",
        severity=SEVERITY,
        version="1.0",
        attack_techniques=(),
        control_refs=common.verify("ISO 27001:2022 A.5.18"),
        allowed_actions=RULE_ALLOWED_ACTIONS[RULE_ID],
        evaluate=evaluate,
        description="Far more grants and categories than departmental peers (statistical heuristic).",
    )
)
