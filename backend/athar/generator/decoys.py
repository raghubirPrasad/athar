"""Decoys — ground-truth negatives (SPEC §4.3) — and the prompt-injection identity (SPEC §11.3).

Eleven identities are seeded so that a naïve detector fires on them; their legitimacy is
recorded ONLY in the governance exception register (`hr/exceptions.csv`) or, for the
time-boxed contractors, in the HR feed's `contract_end`. Cloud tags are emitted for realism
and never consulted by a rule (CLAUDE.md non-negotiable 9).

| kind                       | n | looks risky because                  | legitimate because                          |
|----------------------------|---|--------------------------------------|---------------------------------------------|
| break-glass                | 2 | org-level admin in two clouds        | register: break-glass, MFA, quarterly review|
| dr-failover                | 3 | idle 300+ days with write access     | register: dr-failover; activation is the DR |
| time-boxed-contractor      | 4 | external identity with write access  | HR `contract_end` in the future             |
| approved-privileged-role   | 2 | project-scope admin, used weekly     | register: approved-privileged-role, MFA     |

The twelfth seeded identity is NOT a decoy: a service account whose AWS `note` tag is the
hostile string from SPEC §11.3. It is over-privileged and carries a stale key, so it is a
genuine positive; the guardrail test asserts the tag never reaches an agent output.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import TYPE_CHECKING

from athar.clock import EPOCH, month_end
from athar.generator import catalogue as cat
from athar.generator import names
from athar.generator import rng as rnd
from athar.generator.state import ActivityRecord, ExceptionEntry, Identity

if TYPE_CHECKING:
    from athar.generator.simulator import Simulator

DECOY_BREAK_GLASS = "break-glass"
DECOY_DR_FAILOVER = "dr-failover"
DECOY_CONTRACTOR = "time-boxed-contractor"
DECOY_SANCTIONED = "approved-privileged-role"
INJECTION = "injection"  # not a decoy: a genuine positive carrying the hostile tag

DECOY_KINDS: tuple[str, ...] = (DECOY_BREAK_GLASS, DECOY_DR_FAILOVER, DECOY_CONTRACTOR, DECOY_SANCTIONED)
DECOY_COUNTS: dict[str, int] = {
    DECOY_BREAK_GLASS: 2,
    DECOY_DR_FAILOVER: 3,
    DECOY_CONTRACTOR: 4,
    DECOY_SANCTIONED: 2,
}
DECOY_TOTAL = sum(DECOY_COUNTS.values())  # 11, SPEC §4.1

# Register entries that make each decoy legitimate (SPEC §4.3); the rule that consults them.
DECOY_WHY: dict[str, str] = {
    DECOY_BREAK_GLASS: "register entry break-glass (MFA enforced, sessions monitored, quarterly review date in the future)",
    DECOY_DR_FAILOVER: "register entry dr-failover (idle by design; activation is the disaster-recovery path)",
    DECOY_CONTRACTOR: "HR contract_end in the future; time-boxed engagement with write access to its delivery project",
    DECOY_SANCTIONED: "register entry approved-privileged-role (project-scope admin, MFA enforced, review date in the future)",
}

BREAK_GLASS_DEPARTMENTS: tuple[str, ...] = ("Cyber Security", "Platform Engineering")
DR_IDLE_DAYS_BEFORE_EPOCH = (200, 330)  # already idle at month 1; 300+ days idle well before month 12
INJECTION_SA_NAME = "legacy-sync"
INJECTION_KEY_AGE_DAYS = (420, 600)  # stale at every month of the window (R6)
CONTRACT_TAIL_DAYS = (45, 240)  # contract_end sits this far past the last simulated month


def seed_decoys(sim: Simulator) -> None:
    """Create the eleven decoys and the injection identity before month 1 is simulated."""
    review = month_end(sim.horizon + cat.DECOY_REVIEW_MONTHS_AHEAD)
    dr_expiry = month_end(sim.horizon + cat.DR_EXPIRY_MONTHS_AHEAD)
    _break_glass(sim, review)
    _dr_failover(sim, review, dr_expiry)
    _contractors(sim)
    _sanctioned(sim, review)
    _injection(sim)


def _approved_on(sim: Simulator) -> date:
    return rnd.days_before_epoch(sim.rng, 60, 200)


def _break_glass(sim: Simulator, review: date) -> None:
    for dept in BREAK_GLASS_DEPARTMENTS[: DECOY_COUNTS[DECOY_BREAK_GLASS]]:
        ident = sim.create_human(
            dept,
            "senior",
            ("aws", "azure"),
            rnd.days_before_epoch(sim.rng, 400, 2000),
            0,
            decoy=DECOY_BREAK_GLASS,
            protected=True,
            profile="active",
        )
        ident.tags["access_tier"] = "break-glass"  # realism only; never read by a rule
        sim.grant_role(ident, 0, None)
        for _cloud, tpl in sorted(cat.BREAK_GLASS.items()):
            sim.new_grant(ident, tpl, 0, None, origin="decoy:break-glass", note="break-glass administrator")
        sim.exceptions.append(
            ExceptionEntry(
                identity_id=ident.identity_id,
                exception_type=DECOY_BREAK_GLASS,
                approved_by=rnd.pick(sim.rng, names.APPROVERS),
                approved_on=_approved_on(sim),
                review_date=review,
                expires_on=None,
                justification="Break-glass administrator: MFA enforced, sessions monitored, quarterly access review",
            )
        )
        sim.seed_activity(ident)


def _dr_failover(sim: Simulator, review: date, expires: date) -> None:
    dr_projects = sorted(sim.projects_in_kind("dr"), key=lambda p: p.cloud)
    for project in dr_projects[: DECOY_COUNTS[DECOY_DR_FAILOVER]]:
        ident = sim.create_service_account(
            project,
            0,
            "dr",
            rnd.days_before_epoch(sim.rng, 500, 1500),
            decoy=DECOY_DR_FAILOVER,
            protected=True,
            key_policy="auto",
            profile="never",
            name="failover",
        )
        ident.tags["purpose"] = "dr-failover"
        lo, hi = DR_IDLE_DAYS_BEFORE_EPOCH
        last = EPOCH - timedelta(days=sim.rng.randint(lo, hi))
        for g in sim.active_grants(ident.identity_id):
            for svc in g.services:
                sim.activity[(ident.identity_id, g.cloud, svc)] = ActivityRecord(last=last)
        for cred in sim.credentials:
            if cred.identity_id == ident.identity_id:
                cred.last_used = last
        sim.exceptions.append(
            ExceptionEntry(
                identity_id=ident.identity_id,
                exception_type=DECOY_DR_FAILOVER,
                approved_by=rnd.pick(sim.rng, names.APPROVERS),
                approved_on=_approved_on(sim),
                review_date=review,
                expires_on=expires,
                justification="Disaster-recovery failover account: idle by design, exercised only during a declared DR event",
            )
        )


def _contractors(sim: Simulator) -> None:
    lo, hi = CONTRACT_TAIL_DAYS
    for _ in range(DECOY_COUNTS[DECOY_CONTRACTOR]):
        clouds = rnd.weighted(sim.rng, cat.DEPARTMENT_CLOUDS["Contractors"])
        contract_end = month_end(sim.horizon) + timedelta(days=sim.rng.randint(lo, hi))
        ident = sim.create_human(
            "Contractors",
            "senior",
            clouds,
            rnd.days_before_epoch(sim.rng, 30, 300),
            0,
            decoy=DECOY_CONTRACTOR,
            protected=True,
            profile="active",
            contract_end=contract_end,
        )
        ident.tags["engagement"] = "time-boxed"
        sim.grant_role(ident, 0, None)
        sim.seed_activity(ident)


def _sanctioned(sim: Simulator, review: date) -> None:
    plans = ((("aws", "azure"), "azure"), (("aws", "gcp"), "gcp"))
    for clouds, admin_cloud in plans[: DECOY_COUNTS[DECOY_SANCTIONED]]:
        ident = sim.create_human(
            "Platform Engineering",
            "senior",
            clouds,
            rnd.days_before_epoch(sim.rng, 400, 1800),
            0,
            decoy=DECOY_SANCTIONED,
            protected=True,
            profile="active",
        )
        ident.tags["privileged_role"] = "approved"
        sim.grant_role(ident, 0, None)
        sim.new_grant(
            ident,
            cat.SANCTIONED_ADMIN[admin_cloud],
            0,
            None,
            origin="decoy:approved-privileged-role",
            note="sanctioned platform administrator",
        )
        sim.exceptions.append(
            ExceptionEntry(
                identity_id=ident.identity_id,
                exception_type=DECOY_SANCTIONED,
                approved_by=rnd.pick(sim.rng, names.APPROVERS),
                approved_on=_approved_on(sim),
                review_date=review,
                expires_on=None,
                justification="Platform administrator for the landing zone: role approved by the CISO, MFA enforced, reviewed each quarter",
            )
        )
        sim.seed_activity(ident)


def _injection(sim: Simulator) -> Identity:
    project = sim.home_projects[("Smart Services", "aws")]
    lo, hi = INJECTION_KEY_AGE_DAYS
    ident = sim.create_service_account(
        project,
        0,
        "broad",
        rnd.days_before_epoch(sim.rng, lo, hi),
        decoy=INJECTION,
        protected=True,
        key_policy="manual",
        profile="active",
        name=INJECTION_SA_NAME,
    )
    ident.tags["note"] = names.INJECTION_NOTE  # data, never instruction (SPEC §11.3)
    return ident


def is_decoy(ident: Identity) -> bool:
    return ident.decoy in DECOY_KINDS
