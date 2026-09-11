"""Risk score (SPEC §8.3). Pure; every term is a `LineItem`.

    reach          = min(1.0, blast_radius / REF_SHARE)
    exploitability = 1.0 + departed + dormant(R2) + no-MFA(R9, human) + external + long-lived key + cross-cloud(R4)
    compensating   = break-glass(register, MFA) + time-boxed contract + approved-role / dr-failover(register)
    formula_score  = 100 × reach × exploitability × (1 − compensating)
    rule_floor     = max over fired rules of the severity floor
    score          = clamp(round(max(formula_score, rule_floor)), 0, 100);  severity = band(score)

The floor applies to the *score*, not only the label, so a table sorted by score never
disagrees with its severity column. Constants live in `scoring/constants.py` only.
Exceptions come from the governance register (`EstateView.valid_exception`), never from tags.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from athar.clock import days_between
from athar.detection.base import FindingDraft
from athar.domain import SEVERITY_RANK, EstateView, IdentityRow, severity_band
from athar.scoring import blast_radius as br
from athar.scoring.constants import DEFAULT, ScoringConstants
from athar.scoring.graph import AccessGraph
from athar.scoring.types import LineItem, ScoreResult

DORMANT_RULE = "R2"
NO_MFA_RULE = "R9"
CROSS_CLOUD_RULE = "R4"
LONG_LIVED_KINDS: frozenset[str] = frozenset({"key", "sa_key"})

TERM_REACH = "reach"
TERM_EXPLOITABILITY = "exploitability"
TERM_COMPENSATING = "compensating"
TERM_FORMULA = "formula"
TERM_FLOOR = "floor"
TERM_FINAL = "final"


def _fmt(x: float) -> str:
    s = f"{x:.2f}".rstrip("0")
    return s + "0" if s.endswith(".") else s


def _reach(blast: br.BlastRadius, constants: ScoringConstants) -> tuple[float, LineItem]:
    reach = min(1.0, blast.share / constants.ref_share) if constants.ref_share > 0 else 1.0
    item = LineItem(
        TERM_REACH,
        f"blast radius {blast.percent}% of estate, {blast.high_sensitivity} high-sensitivity resources",
        round(reach, 4),
        {
            "blast_radius": round(blast.share, 4),
            "ref_share": constants.ref_share,
            "reachable": blast.reachable,
            "high_sensitivity": blast.high_sensitivity,
            "total_resources": blast.total,
            "saturated": blast.share >= constants.ref_share,
        },
    )
    return reach, item


def _long_lived_key(estate: EstateView, identity_id: str, constants: ScoringConstants) -> str | None:
    """credential_ref of an active key / SA key older than `long_lived_key_days`, else None.

    SPEC? "long-lived key" is read as age since `last_rotated_at` (fallback `created_at`) — the
    same reference R6 uses — so a rotated key stops counting against the account.
    """
    for cred in sorted(estate.credentials_for(identity_id), key=lambda c: c.credential_ref):
        if not cred.active or cred.kind not in LONG_LIVED_KINDS:
            continue
        since = cred.last_rotated_at or cred.created_at
        if since is not None and days_between(since, estate.as_of) >= constants.long_lived_key_days:
            return cred.credential_ref
    return None


def _exploitability(
    estate: EstateView,
    identity_id: str,
    row: IdentityRow | None,
    fired_ids: set[str],
    constants: ScoringConstants,
) -> tuple[float, list[LineItem]]:
    items: list[LineItem] = [LineItem(TERM_EXPLOITABILITY, "base", 1.0)]
    total = 1.0

    def add(label: str, value: float, **detail: object) -> None:
        nonlocal total
        total += value
        items.append(LineItem(TERM_EXPLOITABILITY, f"{label} +{_fmt(value)}", value, dict(detail)))

    if row is not None and row.employment_status == "departed":
        add("departed", constants.departed, departure_month=row.departure_month)
    if DORMANT_RULE in fired_ids:
        add("dormant", constants.dormant, rule=DORMANT_RULE)
    if NO_MFA_RULE in fired_ids and row is not None and row.identity_type == "human":
        add("no MFA", constants.no_mfa, rule=NO_MFA_RULE)
    if row is not None and (row.external or row.employment_type == "contractor"):
        add("external", constants.external, employment_type=row.employment_type, external=row.external)
    if row is not None and row.identity_type == "service":
        cred = _long_lived_key(estate, identity_id, constants)
        if cred is not None:
            add(
                "long-lived key",
                constants.long_lived_key,
                credential_ref=cred,
                threshold_days=constants.long_lived_key_days,
            )
    if CROSS_CLOUD_RULE in fired_ids:
        add("cross-cloud", constants.cross_cloud, rule=CROSS_CLOUD_RULE)
    items.append(
        LineItem(TERM_EXPLOITABILITY, f"exploitability {_fmt(total)}", round(total, 4), {"summary": True})
    )
    return total, items


def _compensating(
    estate: EstateView, identity_id: str, row: IdentityRow | None, constants: ScoringConstants
) -> tuple[float, list[LineItem]]:
    items: list[LineItem] = []
    total = 0.0

    def credit(label: str, value: float, **detail: object) -> None:
        nonlocal total
        total += value
        items.append(LineItem(TERM_COMPENSATING, f"{label} −{_fmt(value)}", value, dict(detail)))

    break_glass = estate.valid_exception(identity_id, "break-glass")
    if break_glass is not None and row is not None and row.mfa_enforced:
        credit(
            "break-glass (register, MFA enforced)",
            constants.break_glass_credit,
            exception_id=break_glass.exception_id,
            review_date=break_glass.review_date.isoformat() if break_glass.review_date else None,
        )
    if row is not None and row.contract_end_month is not None and row.contract_end_month >= estate.month:
        credit("time-boxed contract", constants.time_boxed_credit, contract_end_month=row.contract_end_month)
    approved = estate.valid_exception(identity_id, "approved-privileged-role", "dr-failover")
    if approved is not None:
        credit(
            f"{approved.exception_type} (register)",
            constants.approved_role_credit,
            exception_id=approved.exception_id,
            review_date=approved.review_date.isoformat() if approved.review_date else None,
        )
    if not items:
        items.append(LineItem(TERM_COMPENSATING, "none", 0.0))
    total = min(total, 1.0)
    items.append(
        LineItem(
            TERM_COMPENSATING,
            f"controls {_fmt(1.0 - total)}",
            round(total, 4),
            {"summary": True, "controls_multiplier": round(1.0 - total, 4)},
        )
    )
    return total, items


def _floor(fired: Iterable[FindingDraft], constants: ScoringConstants) -> tuple[int, LineItem]:
    """max over fired rules of the severity floor; label names the rule(s) that set it."""
    best = 0
    sources: list[str] = []
    for d in fired:
        value = int(constants.floors.get(d.severity, 0))
        if value > best:
            best, sources = value, [d.rule_id]
        elif value == best and value > 0 and d.rule_id not in sources:
            sources.append(d.rule_id)
    sources.sort(key=lambda r: (int(r[1:]) if r[1:].isdigit() else 99, r))
    fired_map = {d.rule_id: d.severity for d in sorted(fired, key=lambda d: d.rule_id)}
    label = ", ".join(sources) if sources else "none"
    return best, LineItem(TERM_FLOOR, label, float(best), {"rules": sources, "fired": fired_map})


def score_identity(
    estate: EstateView,
    identity_id: str,
    fired: list[FindingDraft],
    graph: AccessGraph,
    constants: ScoringConstants = DEFAULT,
) -> ScoreResult:
    """Score one identity from its blast radius, HR row, register entries and fired rules (SPEC §8.3)."""
    row = estate.identities.get(identity_id)
    fired_ids = {d.rule_id for d in fired if d.identity_id == identity_id}
    own = [d for d in fired if d.identity_id == identity_id]

    blast = br.compute(graph, identity_id, constants)
    reach, reach_item = _reach(blast, constants)
    exploitability, expl_items = _exploitability(estate, identity_id, row, fired_ids, constants)
    compensating, comp_items = _compensating(estate, identity_id, row, constants)
    formula = 100.0 * reach * exploitability * (1.0 - compensating)
    floor, floor_item = _floor(own, constants)
    raw = max(formula, float(floor))
    score = max(0, min(100, round(raw)))
    severity = severity_band(score)

    line_items = [
        reach_item,
        *expl_items,
        *comp_items,
        LineItem(
            TERM_FORMULA,
            "100 × reach × exploitability × controls",
            round(formula, 2),
            {
                "reach": round(reach, 4),
                "exploitability": round(exploitability, 4),
                "controls": round(1.0 - compensating, 4),
            },
        ),
        floor_item,
        LineItem(
            TERM_FINAL,
            severity,
            float(score),
            {"formula": round(formula, 2), "floor": floor, "floored": floor > formula, "clamped": raw > 100},
        ),
    ]
    return ScoreResult(
        identity_id=identity_id,
        blast_radius=round(blast.share, 6),
        reachable_resources=blast.reachable,
        high_sensitivity_reached=blast.high_sensitivity,
        reach=round(reach, 4),
        exploitability=round(exploitability, 4),
        compensating=round(compensating, 4),
        formula_score=round(formula, 2),
        rule_floor=floor,
        score=score,
        severity=severity,
        line_items=line_items,
        escalation_paths=graph.escalation_paths(identity_id),
    )


def score_all(
    estate: EstateView,
    drafts_by_identity: Mapping[str, list[FindingDraft]],
    graph: AccessGraph,
    constants: ScoringConstants = DEFAULT,
) -> dict[str, ScoreResult]:
    """Score every identity in the estate (plus any identity that only appears in drafts).

    Identities with no findings still get a blast-radius-based score. Sorted by identity_id.
    """
    ids = set(estate.identities) | set(drafts_by_identity)
    return {
        identity_id: score_identity(
            estate, identity_id, list(drafts_by_identity.get(identity_id, [])), graph, constants
        )
        for identity_id in sorted(ids)
    }


def sort_key(result: ScoreResult) -> tuple[int, int, str]:
    """Descending score, then severity rank, then identity id — the table order (SPEC §8.3)."""
    return (-result.score, -SEVERITY_RANK.get(result.severity, 0), result.identity_id)
