"""Scoring constants (SPEC §8.3). The ONLY place these numbers live.

Tuning rule: constants are tuned only through the evaluation harness (SPEC §17) on the
tuning seed (`ATHAR_SEED`) and reported on the held-out seed (`ATHAR_EVAL_SEED`). Never
hand-tune against the demo's top three. Every constant here is rendered as a line item
in the score drill-down (transparency rule, §8.3), so a value that is not explainable
does not belong in this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from athar.domain import SEVERITY_FLOOR


@dataclass(frozen=True)
class ScoringConstants:
    """All tunable numbers of the risk score and blast radius (SPEC §8.2, §8.3)."""

    # reach = min(1, blast_radius / ref_share): reaching a quarter of the estate saturates
    ref_share: float = 0.25

    # exploitability increments (base 1.0)
    departed: float = 0.5
    dormant: float = 0.3  # R2 fired
    no_mfa: float = 0.3  # R9 fired and human
    external: float = 0.2  # external / contractor
    long_lived_key: float = 0.2  # service account with a key older than long_lived_key_days
    cross_cloud: float = 0.2  # R4 fired

    # compensating credits (subtracted from 1.0)
    break_glass_credit: float = 0.35  # unexpired break-glass register entry AND mfa_enforced
    time_boxed_credit: float = 0.20  # contract_end_month set and not yet passed
    approved_role_credit: float = 0.15  # unexpired approved-privileged-role or dr-failover entry

    # rule floors by severity (SPEC §8.3: Critical 75, High 50, Medium 25, Low 0)
    floors: dict[str, int] = field(default_factory=lambda: dict(SEVERITY_FLOOR))

    # a service-account key counts as long-lived after this many days without rotation
    long_lived_key_days: int = 180

    # blast radius weighting: sensitivity=high resources count this many times (SPEC §8.2)
    high_sensitivity_weight: float = 3.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref_share": self.ref_share,
            "exploitability": {
                "departed": self.departed,
                "dormant": self.dormant,
                "no_mfa": self.no_mfa,
                "external": self.external,
                "long_lived_key": self.long_lived_key,
                "cross_cloud": self.cross_cloud,
            },
            "compensating": {
                "break_glass": self.break_glass_credit,
                "time_boxed": self.time_boxed_credit,
                "approved_role": self.approved_role_credit,
            },
            "floors": dict(self.floors),
            "long_lived_key_days": self.long_lived_key_days,
            "high_sensitivity_weight": self.high_sensitivity_weight,
        }


DEFAULT = ScoringConstants()
