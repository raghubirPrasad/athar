"""Read side: SQL over the CPM and the derived tables (SPEC §13, §14). No writes, no LLM, no chain.

Everything the dashboard reads comes from here. Filters, sorting and pagination happen in SQL
(`ListFilters`, SPEC §13) so a 500-row identity table is one query plus a bounded number of
lookups for the page's rows; `Page.total` always ignores `limit`/`offset`.

Narratives are re-rendered from the stored `facts` (SPEC §10.2 templates are deterministic, so the
sentence an auditor signed is the sentence we render again); the committed instance is rebuilt with
`hashing.finding_instance` from the columns the scan committed; verification re-derives it from
the rows as they stand now, so an edit to a stored severity moves the root (SPEC §12.6).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from statistics import median
from typing import Any, cast

from sqlalchemy import Row, case, func, nulls_last, or_, select
from sqlalchemy.orm import Session

from athar.api.problem import InvalidInputError
from athar.api.schemas import Action as ActionLiteral
from athar.api.schemas import (
    ActivityOut,
    AltitudesOut,
    CausalStepOut,
    Cloud,
    CredentialOut,
    DecisionKind,
    DecisionLedgerStatus,
    DecisionOut,
    DepartmentRollup,
    EstateSummary,
    EvidenceKind,
    EvidenceRefOut,
    ExceptionOut,
    ExceptionSource,
    ExceptionType,
    FindingOut,
    FindingStatus,
    GrantOut,
    HalfLifeLabel,
    HalfLifeOut,
    HalfLifeTable,
    IdentityDetail,
    IdentityType,
    LedgerBadge,
    LedgerBadgeStatus,
    LedgerDecisionOut,
    LedgerScanOut,
    LineItemOut,
    ListFilters,
    Page,
    PathEdgeOut,
    PlanStatus,
    PolicyDiffOut,
    PolicyOperation,
    PrincipalOut,
    ProposedBy,
    RemediationPlanOut,
    RiskPoint,
    ScanLedgerStatus,
    ScanOut,
    ScoreOut,
    Severity,
    SummaryOut,
    TimelineOut,
    TimelinePoint,
)
from athar.api.schemas import EmploymentStatus as EmploymentStatusLiteral
from athar.api.schemas import GeneratedBy as GeneratedByLiteral
from athar.api.schemas import IdentityRow as IdentityRowOut
from athar.clock import month_end, month_label
from athar.db import models as m
from athar.detection.registry import get_rule
from athar.domain import CLOUDS, SEVERITIES, SEVERITY_RANK
from athar.domain import EstateView as DomainEstate
from athar.domain import EventRow as DomainEvent
from athar.domain import GrantRow as DomainGrant
from athar.domain import IdentityRow as DomainIdentity
from athar.drift.causal import causal_history
from athar.drift.halflife import halflife_by_department, halflife_overall, label_for
from athar.drift.timeline import MonthStats, risk_history, timeline_points
from athar.hashing import finding_instance, instance_hash, sha256_hex
from athar.ledger import merkle
from athar.ledger import verify as ledger_verify
from athar.log import get_logger
from athar.narrative import render_all
from athar.scoring.types import LineItem, PathEdge, ScoreResult

log = get_logger(__name__)

#: Ledger status of the newest scan → the badge the Overview shows (SPEC §14).
BADGE_FOR_SCAN: dict[str, LedgerBadgeStatus] = {
    "anchored": "anchored",
    "already_anchored": "anchored",
    "pending": "pending",
    "unanchored": "unanchored",
    "failed": "verification_failed",
}

_EVIDENCE_KINDS: frozenset[str] = frozenset(
    {
        "grant",
        "credential",
        "activity",
        "event",
        "principal",
        "exception",
        "identity",
        "resource",
        "path",
        "project",
    }
)
_FINDING_STATUSES: frozenset[str] = frozenset(
    {
        "open",
        "investigated",
        "remediation_proposed",
        "approved",
        "remediated",
        "rejected",
        "exception_granted",
    }
)
_PLAN_STATUSES: frozenset[str] = frozenset({"proposed", "approved", "rejected", "applied"})
_SCAN_LEDGER_STATUSES: frozenset[str] = frozenset(
    {"pending", "anchored", "unanchored", "already_anchored", "failed"}
)
_DECISION_LEDGER_STATUSES: frozenset[str] = frozenset({"pending", "anchored", "unanchored", "failed"})
_EXCEPTION_TYPES: frozenset[str] = frozenset(
    {"break-glass", "dr-failover", "approved-privileged-role", "time-boxed"}
)
_EMPLOYMENT_STATUSES: frozenset[str] = frozenset({"active", "departed", "on_leave"})


# ---------------------------------------------------------------------------
# coercion helpers — a surprising DB value must degrade, never 500 (non-negotiable 3)
# ---------------------------------------------------------------------------


def _severity(value: str | None) -> Severity:
    return cast(Severity, value) if value in SEVERITIES else "Low"


def _cloud(value: str | None) -> Cloud:
    return cast(Cloud, value) if value in CLOUDS else "aws"


def _clouds(values: Iterable[str]) -> list[Cloud]:
    seen = {v for v in values if v in CLOUDS}
    return [cast(Cloud, c) for c in CLOUDS if c in seen]


def _identity_type(value: str | None) -> IdentityType:
    return "service" if value == "service" else "human"


def _employment_status(value: str | None) -> EmploymentStatusLiteral:
    if value in _EMPLOYMENT_STATUSES:
        return cast(EmploymentStatusLiteral, value)
    return "active"


def _finding_status(value: str | None) -> FindingStatus:
    return cast(FindingStatus, value) if value in _FINDING_STATUSES else "open"


def _plan_status(value: str | None) -> PlanStatus:
    return cast(PlanStatus, value) if value in _PLAN_STATUSES else "proposed"


def _scan_ledger_status(value: str | None) -> ScanLedgerStatus:
    if value in _SCAN_LEDGER_STATUSES:
        return cast(ScanLedgerStatus, value)
    return "pending"


def _decision_ledger_status(value: str | None) -> DecisionLedgerStatus:
    if value in _DECISION_LEDGER_STATUSES:
        return cast(DecisionLedgerStatus, value)
    return "pending"


def _decision_kind(value: str | None) -> DecisionKind:
    if value in ledger_verify.DECISION_CODES:
        return cast(DecisionKind, value)
    return "approved"


def _exception_type(value: str | None) -> ExceptionType:
    if value in _EXCEPTION_TYPES:
        return cast(ExceptionType, value)
    return "time-boxed"


def _exception_source(value: str | None) -> ExceptionSource:
    return "workflow" if value == "workflow" else "register"


def _actions(values: Sequence[str]) -> list[ActionLiteral]:
    return [cast(ActionLiteral, v) for v in values]


def _proposed_by(value: str | None) -> ProposedBy:
    return "model" if value == "model" else "rule"


def _generated_by(value: str | None) -> GeneratedByLiteral:
    return "model" if value == "model" else "template"


def _half_life_label(value: str) -> HalfLifeLabel:
    return cast(HalfLifeLabel, value) if value in ("Healthy", "Slow", "Broken") else "Broken"


# ---------------------------------------------------------------------------
# sorting / paging
# ---------------------------------------------------------------------------


def _order_by(
    sort: str | None,
    allowed: Mapping[str, Any],
    default: str,
    tiebreak: Any,
    secondary: Any = None,
) -> list[Any]:
    """`sort` (optionally `-`-prefixed) → ORDER BY clauses; an unknown field is a 422 problem.

    `secondary` breaks a tie before the id does. On the identity table that is blast radius, so
    that among the identities whose score has saturated the one reaching more of the estate ranks
    first — otherwise "the top three by risk" would be three arbitrary ids.
    """
    spec = (sort or default).strip()
    descending = spec.startswith("-")
    name = spec[1:] if descending else spec
    column = allowed.get(name)
    if column is None:
        raise InvalidInputError("sort.unknown_field", f"Cannot sort by '{name}'; one of {sorted(allowed)}")
    clauses = [nulls_last(column.desc() if descending else column.asc())]
    if secondary is not None and secondary is not column:
        clauses.append(nulls_last(secondary.desc()))
    clauses.append(tiebreak.asc())
    return clauses


def _count(session: Session, entity: Any, *where: Any, join: Any = None, onclause: Any = None) -> int:
    stmt = select(func.count()).select_from(entity)
    if join is not None:
        stmt = stmt.outerjoin(join, onclause)
    return int(session.scalar(stmt.where(*where)) or 0)


def _like(value: str) -> str:
    """Escape the LIKE wildcards a user could type into `q` (they must match literally)."""
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------


def current_month(session: Session) -> int | None:
    """The simulated clock (SPEC §4.7); `None` before the first ingest."""
    row = session.get(m.EstateClock, 1)
    return row.current_month if row is not None and row.current_month > 0 else None


def latest_scan(session: Session) -> m.Scan | None:
    return session.scalars(select(m.Scan).order_by(m.Scan.scan_id.desc()).limit(1)).first()


def scan_for_month(session: Session, month: int | None = None) -> m.Scan | None:
    """The newest scan of `month`, or the newest scan overall when `month` is None."""
    if month is None:
        return latest_scan(session)
    return session.scalars(
        select(m.Scan).where(m.Scan.snapshot_month == month).order_by(m.Scan.scan_id.desc()).limit(1)
    ).first()


def scan_by_id(session: Session, scan_id: int) -> m.Scan | None:
    return session.get(m.Scan, scan_id)


def scan_out(row: m.Scan) -> ScanOut:
    return ScanOut(
        scan_id=row.scan_id,
        snapshot_month=row.snapshot_month,
        ruleset_hash=row.ruleset_hash,
        started_at=row.started_at,
        finished_at=row.finished_at,
        finding_count=row.finding_count,
        merkle_root=row.merkle_root,
        snapshot_hash=row.snapshot_hash,
        ledger_scan_index=row.ledger_scan_index,
        ledger_tx=row.ledger_tx,
        ledger_status=_scan_ledger_status(row.ledger_status),
    )


_SCAN_SORTS: dict[str, Any] = {
    "scan_id": m.Scan.scan_id,
    "snapshot_month": m.Scan.snapshot_month,
    "finding_count": m.Scan.finding_count,
    "started_at": m.Scan.started_at,
    "ledger_status": m.Scan.ledger_status,
}


def _scan_filters(filters: ListFilters) -> list[Any]:
    where: list[Any] = []
    if filters.month is not None:
        where.append(m.Scan.snapshot_month == filters.month)
    if filters.status is not None:
        where.append(m.Scan.ledger_status == filters.status)
    return where


def list_scans(session: Session, filters: ListFilters) -> Page[ScanOut]:
    where = _scan_filters(filters)
    order = _order_by(filters.sort, _SCAN_SORTS, "-scan_id", m.Scan.scan_id)
    rows = session.scalars(
        select(m.Scan).where(*where).order_by(*order).limit(filters.limit).offset(filters.offset)
    ).all()
    return Page[ScanOut](
        items=[scan_out(r) for r in rows],
        total=_count(session, m.Scan, *where),
        limit=filters.limit,
        offset=filters.offset,
    )


# ---------------------------------------------------------------------------
# identities
# ---------------------------------------------------------------------------


def _clouds_by_identity(session: Session, month: int, ids: Sequence[str]) -> dict[str, list[Cloud]]:
    if not ids:
        return {}
    rows = session.execute(
        select(m.Grant.identity_id, m.Grant.cloud)
        .where(m.Grant.snapshot_month == month, m.Grant.identity_id.in_(ids), m.Grant.active.is_(True))
        .distinct()
    ).all()
    grouped: dict[str, set[str]] = {}
    for identity_id, cloud in rows:
        grouped.setdefault(identity_id, set()).add(cloud)
    return {k: _clouds(v) for k, v in grouped.items()}


def _top_rule_by_identity(session: Session, scan_id: int, ids: Sequence[str]) -> dict[str, tuple[str, str]]:
    """identity → (rule_id, rule_name) of its worst finding (severity, then score)."""
    if not ids:
        return {}
    rows = session.execute(
        select(m.Finding.identity_id, m.Finding.rule_id, m.Finding.severity, m.Finding.score).where(
            m.Finding.scan_id == scan_id, m.Finding.identity_id.in_(ids)
        )
    ).all()
    best: dict[str, tuple[int, int, str]] = {}
    for identity_id, rule_id, severity, score in rows:
        key = (SEVERITY_RANK.get(severity, 0), int(score), rule_id)
        if identity_id not in best or key > best[identity_id]:
            best[identity_id] = key
    return {k: (v[2], _rule_name(v[2])) for k, v in best.items()}


def _rule_name(rule_id: str) -> str:
    try:
        return get_rule(rule_id).name
    except KeyError:
        return f"Rule {rule_id}"


_IDENTITY_SORTS_STATIC: dict[str, Any] = {
    "score": m.IdentityScore.score,
    "display_name": m.Identity.display_name,
    "department": m.Identity.department,
    "blast_radius_pct": m.IdentityScore.blast_radius,
    "identity_id": m.Identity.identity_id,
    "status": m.Identity.employment_status,
}


def list_identities(session: Session, filters: ListFilters) -> Page[IdentityRowOut]:
    """Table rows (SPEC §14 Identities): score, severity, clouds, top rule, blast radius, activity."""
    scan = scan_for_month(session, filters.month)
    month = scan.snapshot_month if scan is not None else (current_month(session) or 0)
    scan_id = scan.scan_id if scan is not None else -1

    finding_count = (
        select(func.count())
        .select_from(m.Finding)
        .where(m.Finding.scan_id == scan_id, m.Finding.identity_id == m.Identity.identity_id)
        .correlate(m.Identity)
        .scalar_subquery()
    )
    last_activity = (
        select(func.max(m.Activity.last_activity_at))
        .where(m.Activity.identity_id == m.Identity.identity_id, m.Activity.snapshot_month == month)
        .correlate(m.Identity)
        .scalar_subquery()
    )

    where: list[Any] = [m.Identity.first_seen_month <= month]
    if filters.cloud is not None:
        where.append(
            select(m.Grant.grant_id)
            .where(
                m.Grant.identity_id == m.Identity.identity_id,
                m.Grant.snapshot_month == month,
                m.Grant.cloud == filters.cloud,
                m.Grant.active.is_(True),
            )
            .correlate(m.Identity)
            .exists()
        )
    if filters.department is not None:
        where.append(func.lower(m.Identity.department) == filters.department.lower())
    if filters.rule is not None:
        where.append(
            select(m.Finding.finding_key)
            .where(
                m.Finding.identity_id == m.Identity.identity_id,
                m.Finding.scan_id == scan_id,
                m.Finding.rule_id == filters.rule,
            )
            .correlate(m.Identity)
            .exists()
        )
    if filters.severity is not None:
        where.append(m.IdentityScore.severity == filters.severity)
    if filters.status is not None:
        where.append(m.Identity.employment_status == filters.status)
    if filters.q:
        pattern = _like(filters.q)
        where.append(or_(m.Identity.display_name.ilike(pattern), m.Identity.identity_id.ilike(pattern)))

    join_on = (m.IdentityScore.identity_id == m.Identity.identity_id) & (m.IdentityScore.scan_id == scan_id)
    sorts = dict(_IDENTITY_SORTS_STATIC)
    sorts["severity"] = _severity_rank_column(m.IdentityScore.severity)
    sorts["finding_count"] = finding_count
    sorts["last_activity_at"] = last_activity
    order = _order_by(
        filters.sort, sorts, "-score", m.Identity.identity_id, secondary=m.IdentityScore.blast_radius
    )

    stmt = (
        select(m.Identity, m.IdentityScore, finding_count.label("findings"), last_activity.label("last_at"))
        .outerjoin(m.IdentityScore, join_on)
        .where(*where)
        .order_by(*order)
        .limit(filters.limit)
        .offset(filters.offset)
    )
    rows = session.execute(stmt).all()
    ids = [r[0].identity_id for r in rows]
    clouds = _clouds_by_identity(session, month, ids)
    top_rules = _top_rule_by_identity(session, scan_id, ids)

    items = [
        _identity_row(row, clouds.get(row[0].identity_id, []), top_rules.get(row[0].identity_id))
        for row in rows
    ]
    total = _count(session, m.Identity, *where, join=m.IdentityScore, onclause=join_on)
    return Page[IdentityRowOut](items=items, total=total, limit=filters.limit, offset=filters.offset)


def _severity_rank_column(column: Any) -> Any:
    """`case` over the severity text so ORDER BY follows Low < Medium < High < Critical."""
    return case(dict(SEVERITY_RANK), value=column, else_=0)


def _identity_row(row: Row[Any], clouds: list[Cloud], top_rule: tuple[str, str] | None) -> IdentityRowOut:
    ident: m.Identity = row[0]
    score: m.IdentityScore | None = row[1]
    return IdentityRowOut(
        identity_id=ident.identity_id,
        display_name=ident.display_name,
        identity_type=_identity_type(ident.identity_type),
        department=ident.department,
        clouds=clouds,
        score=max(0, min(100, score.score)) if score is not None else 0,
        severity=_severity(score.severity) if score is not None else _severity("Low"),
        top_rule=top_rule[0] if top_rule else None,
        top_rule_name=top_rule[1] if top_rule else None,
        blast_radius_pct=round((score.blast_radius if score is not None else 0.0) * 100, 1),
        last_activity_at=row[3],
        status=_employment_status(ident.employment_status),
        finding_count=int(row[2] or 0),
        external=bool(ident.external),
        mfa_enforced=bool(ident.mfa_enforced),
    )


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


@dataclass
class FindingContext:
    """Everything `_finding_out` needs, bulk-loaded once per request."""

    scan: m.Scan
    identities: dict[str, m.Identity] = field(default_factory=dict)
    scores: dict[str, m.IdentityScore] = field(default_factory=dict)
    clouds: dict[str, list[Cloud]] = field(default_factory=dict)
    estate: DomainEstate = field(default_factory=lambda: DomainEstate(month=0))
    plans: dict[str, m.RemediationPlan] = field(default_factory=dict)
    decisions: dict[str, list[m.Decision]] = field(default_factory=dict)
    exceptions: dict[str, list[m.GovernanceException]] = field(default_factory=dict)


def build_context(session: Session, scan: m.Scan, findings: Sequence[m.Finding]) -> FindingContext:
    ids = sorted({f.identity_id for f in findings})
    month = scan.snapshot_month
    ctx = FindingContext(scan=scan)
    if not ids:
        ctx.estate = DomainEstate(month=month)
        return ctx
    ctx.identities = {
        r.identity_id: r for r in session.scalars(select(m.Identity).where(m.Identity.identity_id.in_(ids)))
    }
    ctx.scores = {
        r.identity_id: r
        for r in session.scalars(
            select(m.IdentityScore).where(
                m.IdentityScore.scan_id == scan.scan_id, m.IdentityScore.identity_id.in_(ids)
            )
        )
    }
    ctx.clouds = _clouds_by_identity(session, month, ids)
    grants = [
        _domain_grant(g)
        for g in session.scalars(
            select(m.Grant)
            .where(m.Grant.snapshot_month == month, m.Grant.identity_id.in_(ids))
            .order_by(m.Grant.grant_id)
        )
    ]
    events = [
        _domain_event(e)
        for e in session.scalars(
            select(m.Event)
            .where(m.Event.month <= month, m.Event.identity_id.in_(ids))
            .order_by(m.Event.month, m.Event.event_id)
        )
    ]
    ctx.estate = DomainEstate(month=month, grants=grants, events=events)
    keys = sorted({f.finding_key for f in findings})
    for plan in session.scalars(
        select(m.RemediationPlan)
        .where(m.RemediationPlan.finding_key.in_(keys))
        .order_by(m.RemediationPlan.created_at)
    ):
        ctx.plans[plan.finding_key] = plan  # newest wins
    for decision in session.scalars(
        select(m.Decision).where(m.Decision.finding_key.in_(keys)).order_by(m.Decision.created_at)
    ):
        ctx.decisions.setdefault(decision.plan_id or decision.finding_key, []).append(decision)
    for exc in session.scalars(
        select(m.GovernanceException)
        .where(m.GovernanceException.identity_id.in_(ids))
        .order_by(m.GovernanceException.exception_id)
    ):
        ctx.exceptions.setdefault(exc.identity_id, []).append(exc)
    return ctx


def _domain_grant(row: m.Grant) -> DomainGrant:
    return DomainGrant(
        grant_id=row.grant_id,
        identity_id=row.identity_id,
        principal_ref=row.principal_ref,
        cloud=row.cloud,
        service_category=row.service_category,
        verb=row.verb,
        scope_level=row.scope_level,
        scope_ref=row.scope_ref,
        region=row.region,
        effect=row.effect,
        granted_via=row.granted_via,
        snapshot_month=row.snapshot_month,
        raw_snippet=dict(row.raw_snippet or {}),
        source_file=row.source_file,
        source_pointer=row.source_pointer,
        active=bool(row.active),
    )


def _domain_event(row: m.Event) -> DomainEvent:
    return DomainEvent(
        event_id=row.event_id,
        month=row.month,
        kind=row.kind,
        identity_id=row.identity_id,
        cloud=row.cloud,
        grant_delta=dict(row.grant_delta or {}),
        trigger=row.trigger,
        note=row.note,
    )


def domain_identity(row: m.Identity) -> DomainIdentity:
    return DomainIdentity(
        identity_id=row.identity_id,
        display_name=row.display_name,
        identity_type=row.identity_type,
        department=row.department,
        employment_type=row.employment_type,
        employment_status=row.employment_status,
        hire_month=row.hire_month,
        departure_month=row.departure_month,
        external=bool(row.external),
        mfa_enforced=bool(row.mfa_enforced),
        tags=dict(row.tags or {}),
        contract_end_month=row.contract_end_month,
        first_seen_month=row.first_seen_month,
        last_seen_month=row.last_seen_month,
    )


def _evidence_refs(values: Sequence[Any]) -> list[EvidenceRefOut]:
    out: list[EvidenceRefOut] = []
    for value in values:
        text = str(value)
        kind, _, ref = text.partition(":")
        if kind in _EVIDENCE_KINDS and ref:
            out.append(EvidenceRefOut(kind=cast(EvidenceKind, kind), ref=ref))
        else:
            out.append(EvidenceRefOut(kind="grant", ref=text))
    return out


def instance_of(row: m.Finding, snapshot_month: int) -> dict[str, Any]:
    """The committed instance (SPEC §10.1) rebuilt from the columns the scan wrote."""
    return finding_instance(
        finding_key=row.finding_key,
        identity_id=row.identity_id,
        rule_id=row.rule_id,
        severity=row.severity,
        score=row.score,
        snapshot_month=snapshot_month,
        first_seen_month=row.first_seen_month,
        evidence_refs=[str(e) for e in (row.evidence_refs or [])],
        causal_event_ids=[str(e) for e in (row.causal_event_ids or [])],
    )


def score_result(row: m.IdentityScore) -> ScoreResult:
    """The stored score as the pure `ScoreResult` the narrative and export layers expect."""
    items = [
        LineItem(
            term=str(li.get("term", "")),
            label=str(li.get("label", "")),
            value=float(li.get("value", 0.0) or 0.0),
            detail=dict(li.get("detail") or {}),
        )
        for li in (row.line_items or [])
        if isinstance(li, dict)
    ]
    detail = next((li.detail for li in items if li.term == "reach"), {})
    formula = next((li.value for li in items if li.term == "formula"), float(row.score))
    floor = next((li.value for li in items if li.term == "floor"), 0.0)
    paths = [
        [
            PathEdge(
                src=str(edge.get("src", "")),
                verb=str(edge.get("verb", "")),
                dst=str(edge.get("dst", "")),
                grant_id=edge.get("grant_id"),
            )
            for edge in path
            if isinstance(edge, dict)
        ]
        for path in (row.escalation_paths or [])
        if isinstance(path, list)
    ]
    return ScoreResult(
        identity_id=row.identity_id,
        blast_radius=row.blast_radius,
        reachable_resources=int(detail.get("reachable", 0) or 0),
        high_sensitivity_reached=int(detail.get("high_sensitivity", 0) or 0),
        reach=row.reach,
        exploitability=row.exploitability,
        compensating=row.compensating,
        formula_score=float(formula),
        rule_floor=int(floor),
        score=row.score,
        severity=row.severity,
        line_items=items,
        escalation_paths=paths,
    )


def score_out(row: m.IdentityScore) -> ScoreOut:
    result = score_result(row)
    return ScoreOut(
        blast_radius=result.blast_radius,
        reachable_resources=result.reachable_resources,
        high_sensitivity_reached=result.high_sensitivity_reached,
        reach=result.reach,
        exploitability=result.exploitability,
        compensating=result.compensating,
        formula_score=result.formula_score,
        rule_floor=result.rule_floor,
        score=max(0, min(100, result.score)),
        severity=_severity(result.severity),
        line_items=[
            LineItemOut(term=li.term, label=li.label, value=li.value, detail=li.detail)
            for li in result.line_items
        ],
        escalation_paths=[
            [PathEdgeOut(src=e.src, verb=e.verb, dst=e.dst, grant_id=e.grant_id) for e in path]
            for path in result.escalation_paths
        ],
    )


def exception_out(row: m.GovernanceException, as_of: date) -> ExceptionOut:
    valid = not (row.review_date is not None and row.review_date < as_of) and not (
        row.expires_on is not None and row.expires_on < as_of
    )
    return ExceptionOut(
        exception_id=row.exception_id,
        identity_id=row.identity_id,
        exception_type=_exception_type(row.exception_type),
        approved_by=row.approved_by,
        approved_on=row.approved_on,
        review_date=row.review_date,
        expires_on=row.expires_on,
        justification=row.justification,
        source=_exception_source(row.source),
        valid=valid,
    )


def decision_out(row: m.Decision, email: str | None = None) -> DecisionOut:
    return DecisionOut(
        decision_id=row.decision_id,
        plan_id=row.plan_id,
        finding_key=row.finding_key,
        scan_id=row.scan_id,
        decision=_decision_kind(row.decision),
        actor_user_id=row.actor_user_id,
        actor_email=email,
        evidence_hash=row.evidence_hash,
        ledger_tx=row.ledger_tx,
        ledger_status=_decision_ledger_status(row.ledger_status),
        created_at=row.created_at,
    )


def plan_out(
    row: m.RemediationPlan,
    identity: m.Identity | None,
    rule_id: str,
    decisions: Sequence[m.Decision] = (),
) -> RemediationPlanOut:
    diff = dict(row.policy_diff or {})
    operations = [
        PolicyOperation(
            op=str(op.get("op", "")), target=str(op.get("target", "")), detail=str(op.get("detail", ""))
        )
        for op in diff.get("operations", [])
        if isinstance(op, dict)
    ]
    cloud = diff.get("cloud")
    return RemediationPlanOut(
        plan_id=row.plan_id,
        finding_key=row.finding_key,
        scan_id=row.scan_id,
        identity_id=identity.identity_id if identity else "",
        display_name=identity.display_name if identity else "",
        rule_id=rule_id,
        action=cast(ActionLiteral, row.action),
        params=dict(row.params or {}),
        policy_diff=PolicyDiffOut(
            cloud=_cloud(cloud) if cloud in CLOUDS else None,
            before=dict(diff.get("before") or {}),
            after=dict(diff.get("after") or {}),
            operations=operations,
            summary=str(diff.get("summary", "")),
        ),
        keep=[str(k) for k in (row.keep or [])],
        drop=[str(d) for d in (row.drop or [])],
        privilege_reduction_pct=row.privilege_reduction_pct,
        expected_blast_radius_after=row.expected_blast_radius_after,
        proposed_by=_proposed_by(row.proposed_by),
        proposer_user_id=row.proposer_user_id,
        model_id=row.model_id,
        prompt_version=row.prompt_version,
        rationale=row.rationale,
        confidence=max(0.0, min(1.0, row.confidence)),
        status=_plan_status(row.status),
        created_at=row.created_at,
        decisions=[decision_out(d) for d in decisions],
    )


def altitudes_for(row: m.Finding, ctx: FindingContext) -> AltitudesOut:
    """Re-render the three altitudes from the stored facts (SPEC §10.2). Deterministic."""
    facts = dict(row.facts or {})
    score = ctx.scores.get(row.identity_id)
    leaf = merkle.to_hex(merkle.leaf_from_instance_hash(row.instance_hash)) if row.instance_hash else None
    proof = [str(p) for p in (row.leaf_proof or [])]
    steps = causal_history(ctx.estate, _draft_for(row))
    rendered = render_all(
        row.rule_id,
        facts,
        score=score_result(score) if score is not None else None,
        causal=steps,
        first_seen_month=row.first_seen_month,
        evidence_refs=[
            {"kind": e.kind, "ref": e.ref, "note": e.note} for e in _evidence_refs(row.evidence_refs or [])
        ],
        grants=ctx.estate.grants_for(row.identity_id),
        path=facts.get("path"),
        policy_diff=dict(ctx.plans[row.finding_key].policy_diff or {})
        if row.finding_key in ctx.plans
        else None,
        leaf=leaf,
        proof=proof,
    )
    return AltitudesOut(
        headline=rendered.headline, explanation=rendered.explanation, evidence=rendered.evidence
    )


def _draft_for(row: m.Finding) -> Any:
    """The rule's draft as `drift.causal` needs it (rule id, identity, cited events, facts)."""
    from athar.detection.base import FindingDraft

    return FindingDraft(
        rule_id=row.rule_id,
        identity_id=row.identity_id,
        severity=row.severity,
        evidence=[],
        causal_event_ids=[str(e) for e in (row.causal_event_ids or [])],
        facts=dict(row.facts or {}),
    )


def causal_steps(row: m.Finding, ctx: FindingContext) -> list[CausalStepOut]:
    return [
        CausalStepOut(
            month=s.month,
            event_id=s.event_id,
            kind=s.kind,
            trigger=s.trigger,
            cloud=_cloud(s.cloud) if s.cloud in CLOUDS else None,
            description=s.description,
            grant_delta=s.grant_delta,
        )
        for s in causal_history(ctx.estate, _draft_for(row))
    ]


_HEAVY_FACT_SLOTS: frozenset[str] = frozenset({"instance", "path", "grant_ids", "raw_snippets"})


def _summary_altitudes(row: m.Finding, ctx: FindingContext) -> AltitudesOut:
    """Headline and explanation only; the evidence altitude is a detail-view payload."""
    full = altitudes_for(row, ctx)
    return AltitudesOut(headline=full.headline, explanation=full.explanation, evidence={})


def finding_out(row: m.Finding, ctx: FindingContext, *, full: bool = True) -> FindingOut:
    """One finding for the API.

    `full=False` is the list view: the evidence altitude (raw provider snippets, canonical rows and
    the plain-text rendering) is dropped, and so are the committed instance and the per-grant facts
    it carries. A page of a hundred findings would otherwise be several megabytes of JSON that no
    list renders. Headline and explanation stay, and `GET /findings/{key}` returns everything.
    """
    ident = ctx.identities.get(row.identity_id)
    spec = _rule_spec(row.rule_id)
    facts = dict(row.facts or {})
    score = ctx.scores.get(row.identity_id)
    if score is not None:
        facts.setdefault("blast_radius_pct", round(score.blast_radius * 100, 1))
    if full:
        facts["instance"] = instance_of(row, ctx.scan.snapshot_month)
    else:
        facts = {k: v for k, v in facts.items() if k not in _HEAVY_FACT_SLOTS}
    leaf = merkle.to_hex(merkle.leaf_from_instance_hash(row.instance_hash)) if row.instance_hash else ""
    plan = ctx.plans.get(row.finding_key)
    status = _finding_status(row.status)
    as_of = month_end(ctx.scan.snapshot_month)
    exception = _exception_for(ctx.exceptions.get(row.identity_id, []), status, as_of)
    return FindingOut(
        finding_key=row.finding_key,
        scan_id=row.scan_id,
        snapshot_month=ctx.scan.snapshot_month,
        identity_id=row.identity_id,
        display_name=ident.display_name if ident else row.identity_id,
        identity_type=_identity_type(ident.identity_type if ident else "human"),
        department=ident.department if ident else "Unassigned",
        clouds=ctx.clouds.get(row.identity_id, []),
        rule_id=row.rule_id,
        rule_name=spec[0],
        severity=_severity(row.severity),
        score=max(0, min(100, row.score)),
        first_seen_month=max(1, row.first_seen_month),
        status=status,
        evidence_refs=_evidence_refs(row.evidence_refs or []),
        causal_event_ids=[str(e) for e in (row.causal_event_ids or [])],
        instance_hash=row.instance_hash,
        leaf=leaf,
        proof=[str(p) for p in (row.leaf_proof or [])],
        altitudes=altitudes_for(row, ctx) if full else _summary_altitudes(row, ctx),
        allowed_actions=_actions(spec[1]),
        attack_techniques=list(spec[2]),
        control_refs=list(spec[3]),
        facts=facts,
        plan=plan_out(plan, ident, row.rule_id, ctx.decisions.get(plan.plan_id, [])) if plan else None,
        investigation=None,  # agent output is not persisted; POST /agent/investigate returns it (cached)
        exception=exception,
    )


def _rule_spec(rule_id: str) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    try:
        spec = get_rule(rule_id)
    except KeyError:
        return (f"Rule {rule_id}", ("no_action_recommended",), (), ())
    return (spec.name, spec.allowed_actions, spec.attack_techniques, spec.control_refs)


def _exception_for(
    rows: Sequence[m.GovernanceException], status: FindingStatus, as_of: date
) -> ExceptionOut | None:
    """The register entry a reader needs to see: the workflow grant when one was made, else a valid one."""
    if not rows:
        return None
    outs = [exception_out(r, as_of) for r in rows]
    if status == "exception_granted":
        workflow = [e for e in outs if e.source == "workflow"]
        if workflow:
            return workflow[-1]
    valid = [e for e in outs if e.valid]
    return valid[0] if valid else None


_FINDING_SORTS: dict[str, Any] = {
    "score": m.Finding.score,
    "rule_id": m.Finding.rule_id,
    "first_seen_month": m.Finding.first_seen_month,
    "display_name": m.Identity.display_name,
    "department": m.Identity.department,
    "status": m.Finding.status,
    "finding_key": m.Finding.finding_key,
}


def _finding_where(scan: m.Scan | None, filters: ListFilters, scan_id: int) -> list[Any]:
    where: list[Any] = [m.Finding.scan_id == scan_id]
    month = scan.snapshot_month if scan is not None else 0
    if filters.department is not None:
        where.append(func.lower(m.Identity.department) == filters.department.lower())
    if filters.rule is not None:
        where.append(m.Finding.rule_id == filters.rule)
    if filters.severity is not None:
        where.append(m.Finding.severity == filters.severity)
    if filters.status is not None:
        where.append(m.Finding.status == filters.status)
    if filters.q:
        pattern = _like(filters.q)
        where.append(or_(m.Identity.display_name.ilike(pattern), m.Finding.identity_id.ilike(pattern)))
    if filters.cloud is not None:
        where.append(
            select(m.Grant.grant_id)
            .where(
                m.Grant.identity_id == m.Finding.identity_id,
                m.Grant.snapshot_month == month,
                m.Grant.cloud == filters.cloud,
                m.Grant.active.is_(True),
            )
            .correlate(m.Finding)
            .exists()
        )
    return where


def finding_rows(
    session: Session, filters: ListFilters, *, limit: int | None = None, offset: int | None = None
) -> tuple[m.Scan | None, list[m.Finding], int]:
    """The filtered, sorted, paginated finding rows plus the unpaginated total.

    `limit` / `offset` override the page window: the exports (SPEC §16) carry every row matching
    the filters, not just the current page, bounded by their own cap.
    """
    scan = scan_for_month(session, filters.month)
    scan_id = scan.scan_id if scan is not None else -1
    where = _finding_where(scan, filters, scan_id)
    sorts = dict(_FINDING_SORTS)
    sorts["severity"] = _severity_rank_column(m.Finding.severity)
    order = _order_by(filters.sort, sorts, "-score", m.Finding.finding_key)
    join_on = m.Identity.identity_id == m.Finding.identity_id
    rows = list(
        session.scalars(
            select(m.Finding)
            .outerjoin(m.Identity, join_on)
            .where(*where)
            .order_by(*order)
            .limit(filters.limit if limit is None else limit)
            .offset(filters.offset if offset is None else offset)
        )
    )
    total = _count(session, m.Finding, *where, join=m.Identity, onclause=join_on)
    return scan, rows, total


def list_findings(session: Session, filters: ListFilters) -> Page[FindingOut]:
    scan, rows, total = finding_rows(session, filters)
    if scan is None:
        return Page[FindingOut](items=[], total=0, limit=filters.limit, offset=filters.offset)
    ctx = build_context(session, scan, rows)
    return Page[FindingOut](
        items=[finding_out(r, ctx, full=False) for r in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


def find_finding(session: Session, finding_key: str) -> tuple[m.Scan, m.Finding] | None:
    """The newest scan's row for this finding key (SPEC §10.1: the key is stable across scans)."""
    row = session.execute(
        select(m.Finding, m.Scan)
        .join(m.Scan, m.Scan.scan_id == m.Finding.scan_id)
        .where(m.Finding.finding_key == finding_key)
        .order_by(m.Finding.scan_id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    return (row[1], row[0])


def finding(session: Session, finding_key: str) -> FindingOut | None:
    found = find_finding(session, finding_key)
    if found is None:
        return None
    scan, row = found
    return finding_out(row, build_context(session, scan, [row]))


# ---------------------------------------------------------------------------
# identity detail (SPEC §14 drill-down)
# ---------------------------------------------------------------------------


def identity_detail(session: Session, identity_id: str) -> IdentityDetail | None:
    ident = session.get(m.Identity, identity_id)
    if ident is None:
        return None
    scan = latest_scan(session)
    month = scan.snapshot_month if scan is not None else (current_month(session) or ident.last_seen_month)
    scan_id = scan.scan_id if scan is not None else -1
    as_of = month_end(max(1, month))

    findings = list(
        session.scalars(
            select(m.Finding)
            .where(m.Finding.scan_id == scan_id, m.Finding.identity_id == identity_id)
            .order_by(m.Finding.rule_id)
        )
    )
    ctx = build_context(session, scan, findings) if scan is not None else None
    if ctx is not None and identity_id not in ctx.identities:
        ctx.identities[identity_id] = ident
    ordered = sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), -f.score, f.rule_id))
    top = ordered[0] if ordered else None

    grants = list(
        session.scalars(
            select(m.Grant)
            .where(m.Grant.identity_id == identity_id, m.Grant.snapshot_month == month)
            .order_by(m.Grant.grant_id)
        )
    )
    activity = list(
        session.scalars(
            select(m.Activity)
            .where(m.Activity.identity_id == identity_id, m.Activity.snapshot_month == month)
            .order_by(m.Activity.cloud, m.Activity.service_category)
        )
    )
    credentials = list(
        session.scalars(
            select(m.Credential)
            .where(m.Credential.identity_id == identity_id, m.Credential.snapshot_month == month)
            .order_by(m.Credential.credential_ref)
        )
    )
    principals = list(
        session.scalars(
            select(m.Principal)
            .where(m.Principal.identity_id == identity_id)
            .order_by(m.Principal.principal_ref)
        )
    )
    exceptions = list(
        session.scalars(
            select(m.GovernanceException)
            .where(m.GovernanceException.identity_id == identity_id)
            .order_by(m.GovernanceException.exception_id)
        )
    )
    events = [
        _domain_event(e)
        for e in session.scalars(
            select(m.Event)
            .where(m.Event.identity_id == identity_id, m.Event.month <= month)
            .order_by(m.Event.month, m.Event.event_id)
        )
    ]
    score_row = session.get(m.IdentityScore, {"identity_id": identity_id, "scan_id": scan_id})
    clouds = _clouds_by_identity(session, month, [identity_id]).get(identity_id, [])
    last_activity = max((a.last_activity_at for a in activity if a.last_activity_at), default=None)

    return IdentityDetail(
        identity_id=ident.identity_id,
        display_name=ident.display_name,
        identity_type=_identity_type(ident.identity_type),
        department=ident.department,
        employment_type=ident.employment_type,
        employment_status=_employment_status(ident.employment_status),
        hire_month=ident.hire_month,
        departure_month=ident.departure_month,
        external=bool(ident.external),
        mfa_enforced=bool(ident.mfa_enforced),
        tags=dict(ident.tags or {}),
        contract_end_month=ident.contract_end_month,
        first_seen_month=ident.first_seen_month,
        last_seen_month=ident.last_seen_month,
        clouds=clouds,
        score=score_out(score_row) if score_row is not None else None,
        severity=_severity(score_row.severity) if score_row is not None else _severity("Low"),
        blast_radius_pct=round((score_row.blast_radius if score_row is not None else 0.0) * 100, 1),
        last_activity_at=last_activity,
        top_finding_key=top.finding_key if top is not None else None,
        grants=[_grant_out(g) for g in grants],
        activity=[_activity_out(a) for a in activity],
        credentials=[_credential_out(c, as_of) for c in credentials],
        findings=[finding_out(f, ctx) for f in ordered] if ctx is not None else [],
        causal_history=_causal_all(events, month),
        risk_history=_risk_history(session, identity_id, events, month),
        exceptions=[exception_out(e, as_of) for e in exceptions],
        altitudes=altitudes_for(top, ctx) if top is not None and ctx is not None else None,
        principals=[_principal_out(p) for p in principals],
    )


def _grant_out(row: m.Grant) -> GrantOut:
    return GrantOut(
        grant_id=row.grant_id,
        principal_ref=row.principal_ref,
        cloud=_cloud(row.cloud),
        service_category=row.service_category,
        verb=row.verb,
        scope_level=row.scope_level,
        scope_ref=row.scope_ref,
        region=row.region,
        effect=row.effect,
        granted_via=row.granted_via,
        snapshot_month=row.snapshot_month,
        raw_snippet=dict(row.raw_snippet or {}),
        source_file=row.source_file,
        source_pointer=row.source_pointer,
        active=bool(row.active),
    )


def _activity_out(row: m.Activity) -> ActivityOut:
    return ActivityOut(
        cloud=_cloud(row.cloud),
        service_category=row.service_category,
        snapshot_month=row.snapshot_month,
        last_activity_at=row.last_activity_at,
        operation_count=row.operation_count,
    )


def _credential_out(row: m.Credential, as_of: date) -> CredentialOut:
    since = row.last_rotated_at or row.created_at
    return CredentialOut(
        credential_ref=row.credential_ref,
        cloud=_cloud(row.cloud),
        kind=row.kind,
        created_at=row.created_at,
        last_rotated_at=row.last_rotated_at,
        last_used_at=row.last_used_at,
        active=bool(row.active),
        age_days=(as_of - since).days if since is not None else None,
    )


def _principal_out(row: m.Principal) -> PrincipalOut:
    return PrincipalOut(
        principal_ref=row.principal_ref,
        cloud=_cloud(row.cloud),
        principal_type=row.principal_type,
        link_method=row.link_method,
        link_confidence=row.link_confidence,
    )


def _causal_all(events: Sequence[DomainEvent], month: int) -> list[CausalStepOut]:
    from athar.drift.causal import step_from_event

    steps = [step_from_event(e) for e in events if e.month <= month]
    return [
        CausalStepOut(
            month=s.month,
            event_id=s.event_id,
            kind=s.kind,
            trigger=s.trigger,
            cloud=_cloud(s.cloud) if s.cloud in CLOUDS else None,
            description=s.description,
            grant_delta=s.grant_delta,
        )
        for s in sorted(steps, key=lambda s: (s.month, s.event_id))
    ]


def _risk_history(
    session: Session, identity_id: str, events: Sequence[DomainEvent], month: int
) -> list[RiskPoint]:
    """One point per scanned month from `identity_scores` (SPEC §9.4), annotated with the events."""
    from athar.drift.causal import step_from_event

    rows = session.execute(
        select(m.Scan.snapshot_month, m.IdentityScore.score)
        .join(m.IdentityScore, m.IdentityScore.scan_id == m.Scan.scan_id)
        .where(m.IdentityScore.identity_id == identity_id, m.Scan.snapshot_month <= month)
        .order_by(m.Scan.snapshot_month, m.Scan.scan_id)
    ).all()
    by_month: dict[int, int] = {int(snapshot_month): int(score) for snapshot_month, score in rows}
    if not by_month:
        return []
    steps = [step_from_event(e) for e in events]
    points = risk_history(by_month, steps)
    return [
        RiskPoint(
            month=int(p["month"]),
            score=max(0, min(100, int(p["score"]))),
            severity=_severity(str(p["severity"])),
            events=[
                CausalStepOut(
                    month=int(e["month"]),
                    event_id=str(e["event_id"]),
                    kind=str(e["kind"]),
                    trigger=str(e["trigger"]),
                    cloud=_cloud(e["cloud"]) if e.get("cloud") in CLOUDS else None,
                    description=str(e["description"]),
                    grant_delta=dict(e.get("grant_delta") or {}),
                )
                for e in p["events"]
            ],
        )
        for p in points
    ]


# ---------------------------------------------------------------------------
# drift: half-life and timeline (SPEC §9.3, §9.4)
# ---------------------------------------------------------------------------


def _identities_at(session: Session, month: int) -> dict[str, DomainIdentity]:
    return {
        r.identity_id: domain_identity(r)
        for r in session.scalars(
            select(m.Identity).where(m.Identity.first_seen_month <= month).order_by(m.Identity.identity_id)
        )
    }


def _events_up_to(session: Session, month: int) -> list[DomainEvent]:
    return [
        _domain_event(e)
        for e in session.scalars(
            select(m.Event).where(m.Event.month <= month).order_by(m.Event.month, m.Event.event_id)
        )
    ]


def _halflife_rows(session: Session, month: int) -> list[Any]:
    """Per (department, trigger) plus the `all` department rows (SPEC §9.3). Domain rows."""
    if month <= 0:
        return []
    identities = _identities_at(session, month)
    events = _events_up_to(session, month)
    return halflife_by_department(events, identities, month) + halflife_overall(events, identities, month)


def halflife(session: Session, month: int | None = None) -> HalfLifeTable:
    target = month if month is not None else (current_month(session) or 0)
    if target <= 0:
        return HalfLifeTable(month=0, rows=[])
    rows = _halflife_rows(session, target)
    return HalfLifeTable(
        month=target,
        rows=[
            HalfLifeOut(
                department=r.department,
                trigger=r.trigger,
                grants=r.grants,
                revocations=r.revocations,
                half_life_months=r.half_life_months,
                label=_half_life_label(r.label),
            )
            for r in rows
        ],
    )


def timeline(session: Session) -> TimelineOut:
    month = current_month(session) or 0
    scans = list(session.scalars(select(m.Scan).order_by(m.Scan.snapshot_month, m.Scan.scan_id)))
    if not scans:
        return TimelineOut(current_month=month, points=[])
    newest: dict[int, m.Scan] = {s.snapshot_month: s for s in scans}  # last scan of each month wins
    identities = _identities_at(session, max(newest))
    events = _events_up_to(session, max(newest))
    severities = _severities_by_scan(session, [s.scan_id for s in newest.values()])
    scores = _scores_by_scan(session, [s.scan_id for s in newest.values()])
    stats: list[MonthStats] = []
    for snapshot_month, scan in sorted(newest.items()):
        stats.append(
            MonthStats(
                month=snapshot_month,
                identity_count=sum(1 for i in identities.values() if i.first_seen_month <= snapshot_month),
                findings=severities.get(scan.scan_id, []),
                scores=scores.get(scan.scan_id, []),
                halflife=halflife_by_department(events, identities, snapshot_month),
            )
        )
    points = [
        TimelinePoint(
            month=p.month,
            month_label=month_label(p.month),
            identity_count=p.identity_count,
            findings_by_severity={_severity(s): n for s, n in p.findings_by_severity.items()},
            median_score=p.median_score,
            half_life=p.half_life,
        )
        for p in timeline_points(stats)
    ]
    return TimelineOut(current_month=month or (max(newest) if newest else 0), points=points)


def _severities_by_scan(session: Session, scan_ids: Sequence[int]) -> dict[int, list[str]]:
    if not scan_ids:
        return {}
    rows = session.execute(
        select(m.Finding.scan_id, m.Finding.severity, func.count())
        .where(m.Finding.scan_id.in_(scan_ids))
        .group_by(m.Finding.scan_id, m.Finding.severity)
    ).all()
    out: dict[int, list[str]] = {}
    for scan_id, severity, count in rows:
        out.setdefault(int(scan_id), []).extend([str(severity)] * int(count))
    return out


def _scores_by_scan(session: Session, scan_ids: Sequence[int]) -> dict[int, list[int]]:
    if not scan_ids:
        return {}
    rows = session.execute(
        select(m.IdentityScore.scan_id, m.IdentityScore.score).where(m.IdentityScore.scan_id.in_(scan_ids))
    ).all()
    out: dict[int, list[int]] = {}
    for scan_id, score in rows:
        out.setdefault(int(scan_id), []).append(int(score))
    return out


# ---------------------------------------------------------------------------
# overview (SPEC §14 Overview page)
# ---------------------------------------------------------------------------


def department_rollup(session: Session, scan: m.Scan | None) -> list[DepartmentRollup]:
    month = scan.snapshot_month if scan is not None else (current_month(session) or 0)
    scan_id = scan.scan_id if scan is not None else -1
    identity_counts = {
        str(dept): int(count)
        for dept, count in session.execute(
            select(m.Identity.department, func.count())
            .where(m.Identity.first_seen_month <= month)
            .group_by(m.Identity.department)
        ).all()
    }
    counts: dict[str, dict[str, int]] = {}
    for dept, severity, count in session.execute(
        select(m.Identity.department, m.Finding.severity, func.count())
        .join(m.Finding, m.Finding.identity_id == m.Identity.identity_id)
        .where(m.Finding.scan_id == scan_id)
        .group_by(m.Identity.department, m.Finding.severity)
    ).all():
        counts.setdefault(str(dept), {})[str(severity)] = int(count)
    offboarding = _offboarding_map(session, month)
    out: list[DepartmentRollup] = []
    for dept in sorted(set(identity_counts) | set(counts)):
        per_severity = counts.get(dept, {})
        hl = offboarding.get(dept)
        out.append(
            DepartmentRollup(
                department=dept,
                identities=identity_counts.get(dept, 0),
                findings=sum(per_severity.values()),
                critical=per_severity.get("Critical", 0),
                high=per_severity.get("High", 0),
                medium=per_severity.get("Medium", 0),
                low=per_severity.get("Low", 0),
                offboarding_half_life=hl,
                half_life_label=_half_life_label(label_for(hl)),
            )
        )
    return out


def _offboarding_map(session: Session, month: int) -> dict[str, float | None]:
    """department → offboarding (trigger `departure`) half-life in months; None means Never."""
    if month <= 0:
        return {}
    identities = _identities_at(session, month)
    events = _events_up_to(session, month)
    rows = halflife_by_department(events, identities, month)
    return {r.department: r.half_life_months for r in rows if r.trigger == "departure"}


def template_summary(session: Session, scan: m.Scan, rollups: Sequence[DepartmentRollup]) -> SummaryOut:
    """The executive paragraph from aggregate counts only — templated, no model (SPEC §11.4).

    This is what the Overview shows until an analyst runs `/agent/summary`; the two paths use the
    same template, so the page is never empty and never waits on a provider.
    """
    from athar.agents.inputs import build_summary_input
    from athar.agents.prompts import SUMMARY_PROMPT_VERSION
    from athar.agents.summarise import template_summary as render

    per_rule: dict[str, int] = {}
    per_severity: dict[str, int] = {}
    for rule_id, severity, count in session.execute(
        select(m.Finding.rule_id, m.Finding.severity, func.count())
        .where(m.Finding.scan_id == scan.scan_id)
        .group_by(m.Finding.rule_id, m.Finding.severity)
    ).all():
        per_rule[str(rule_id)] = per_rule.get(str(rule_id), 0) + int(count)
        per_severity[str(severity)] = per_severity.get(str(severity), 0) + int(count)
    top = session.execute(
        select(m.Finding.rule_id, m.Finding.severity)
        .where(m.Finding.scan_id == scan.scan_id)
        .order_by(m.Finding.score.desc(), m.Finding.finding_key)
        .limit(3)
    ).all()
    inp = build_summary_input(
        month=scan.snapshot_month,
        counts_per_rule=per_rule,
        counts_per_department={r.department: r.findings for r in rollups if r.findings},
        counts_per_severity=per_severity,
        halflife_table=_halflife_rows(session, scan.snapshot_month),
        top_headlines=[f"{_rule_name(str(r))} ({s})" for r, s in top],
        rule_names={r: _rule_name(r) for r in per_rule},
    )
    output = render(inp)
    return SummaryOut(
        summary_paragraph=output.summary_paragraph,
        top_themes=list(output.top_themes)[:3],
        model_id=None,
        prompt_version=SUMMARY_PROMPT_VERSION,
        cached=False,
        generated_by="template",
    )


def ledger_badge(session: Session, enabled: bool) -> LedgerBadge:
    """The badge on every page (SPEC §14), including the red state a tamper must produce (§12.6).

    An anchored scan is re-verified here rather than trusted: the leaves are recomputed from the
    findings as they stand and compared with the root the scan committed. Editing a stored severity
    therefore turns the badge red on the next page load, which is what §12.6 and docs/DEPLOY.md
    promise and what the demo's tamper beat shows. It costs a few milliseconds and no chain call —
    the comparison against the chain itself stays in the explicit Verify action, which is the one
    that can tell an edited database from an edited commit.
    """
    scan = latest_scan(session)
    meta = session.get(m.LedgerMeta, 1)
    if not enabled:
        return LedgerBadge(
            status="disabled",
            last_scan_id=scan.scan_id if scan else None,
            last_root=scan.merkle_root if scan else None,
        )
    if scan is None:
        return LedgerBadge(status="pending", chain_id=meta.chain_id if meta else None)
    status = BADGE_FOR_SCAN.get(scan.ledger_status, "unanchored")
    if status == "anchored" and scan.merkle_root and not _findings_match_root(session, scan):
        status = "verification_failed"
    return LedgerBadge(
        status=status,
        last_scan_id=scan.scan_id,
        last_root=scan.merkle_root,
        last_tx=scan.ledger_tx,
        chain_id=meta.chain_id if meta else None,
    )


def _findings_match_root(session: Session, scan: m.Scan) -> bool:
    """Do the scan's findings, as stored now, still hash to the root it committed?"""
    computed = merkle.to_hex(merkle.root(_leaves_for_scan(session, scan.scan_id)))
    return computed.lower() == str(scan.merkle_root).lower()


def _leaves_for_scan(session: Session, scan_id: int) -> list[bytes]:
    return [merkle.leaf_from_instance_hash(h) for h in instance_hashes_for_scan(session, scan_id)]


def summary_cache_key(scan_id: int) -> str:
    """Key of the executive summary held in `llm_cache` for one scan.

    SPEC? §11.4 does not say where a generated summary lives between requests. It is cached under
    this key when `/agent/summary` runs so the Overview can show it without an LLM call at read
    time (CLAUDE.md: no live network call on a demo path).
    """
    return sha256_hex(f"estate-summary|v1|{scan_id}".encode())


def cached_summary(session: Session, scan_id: int) -> SummaryOut | None:
    row = session.get(m.LlmCache, summary_cache_key(scan_id))
    if row is None:
        return None
    output = dict(row.output or {})
    paragraph = str(output.get("summary_paragraph", ""))
    if not paragraph:
        return None
    return SummaryOut(
        summary_paragraph=paragraph,
        top_themes=[str(t) for t in (output.get("top_themes") or [])][:3],
        model_id=output.get("model_id"),
        prompt_version=row.prompt_version,
        cached=True,
        generated_by=_generated_by(str(output.get("generated_by", "template"))),
    )


def estate_summary(session: Session, ledger_enabled: bool) -> EstateSummary:
    scan = latest_scan(session)
    month = scan.snapshot_month if scan is not None else (current_month(session) or 0)
    scan_id = scan.scan_id if scan is not None else -1

    identity_where = [m.Identity.first_seen_month <= month]
    humans = _count(session, m.Identity, *identity_where, m.Identity.identity_type == "human")
    services = _count(session, m.Identity, *identity_where, m.Identity.identity_type == "service")

    by_severity: dict[Severity, int] = {_severity(s): 0 for s in SEVERITIES}
    for severity, count in session.execute(
        select(m.Finding.severity, func.count())
        .where(m.Finding.scan_id == scan_id)
        .group_by(m.Finding.severity)
    ).all():
        by_severity[_severity(str(severity))] += int(count)

    finding_identities = [
        str(i)
        for i in session.scalars(select(m.Finding.identity_id).where(m.Finding.scan_id == scan_id)).all()
    ]
    clouds = _clouds_by_identity(session, month, sorted(set(finding_identities)))
    by_cloud: dict[Cloud, int] = {cast(Cloud, c): 0 for c in CLOUDS}
    for identity_id in finding_identities:
        for cloud in clouds.get(identity_id, []):
            by_cloud[cloud] += 1

    scores = [
        int(s)
        for s in session.scalars(
            select(m.IdentityScore.score).where(m.IdentityScore.scan_id == scan_id)
        ).all()
    ]
    rollups = department_rollup(session, scan)
    summary = cached_summary(session, scan_id) if scan is not None else None
    if summary is None and scan is not None:
        summary = template_summary(session, scan, rollups)
    return EstateSummary(
        current_month=month,
        current_month_label=month_label(month) if month >= 1 else "no data",
        identity_count=humans + services,
        humans=humans,
        services=services,
        findings_total=sum(by_severity.values()),
        findings_by_severity=by_severity,
        findings_by_cloud=by_cloud,
        findings_by_department=rollups,
        median_score=float(median(scores)) if scores else 0.0,
        ledger=ledger_badge(session, ledger_enabled),
        executive_summary=summary.summary_paragraph if summary else None,
        model_id=summary.model_id if summary else None,
        scan_id=scan.scan_id if scan is not None else None,
    )


# ---------------------------------------------------------------------------
# remediation queue
# ---------------------------------------------------------------------------


_PLAN_SORTS: dict[str, Any] = {
    "created_at": m.RemediationPlan.created_at,
    "status": m.RemediationPlan.status,
    "confidence": m.RemediationPlan.confidence,
    "plan_id": m.RemediationPlan.plan_id,
    "privilege_reduction_pct": m.RemediationPlan.privilege_reduction_pct,
    "display_name": m.Identity.display_name,
}


def _plan_join() -> Any:
    return m.Finding.finding_key == m.RemediationPlan.finding_key


def list_plans(session: Session, filters: ListFilters) -> Page[RemediationPlanOut]:
    """Queue rows; the identity and rule come from the plan's finding (SPEC §14 Remediation)."""
    where: list[Any] = []
    if filters.status is not None:
        where.append(m.RemediationPlan.status == filters.status)
    if filters.rule is not None:
        where.append(m.Finding.rule_id == filters.rule)
    if filters.department is not None:
        where.append(func.lower(m.Identity.department) == filters.department.lower())
    if filters.q:
        where.append(m.Identity.display_name.ilike(_like(filters.q)))
    sorts = dict(_PLAN_SORTS)
    order = _order_by(filters.sort, sorts, "-created_at", m.RemediationPlan.plan_id)
    stmt = (
        select(m.RemediationPlan, m.Finding, m.Identity)
        .outerjoin(
            m.Finding,
            (m.Finding.finding_key == m.RemediationPlan.finding_key)
            & (m.Finding.scan_id == m.RemediationPlan.scan_id),
        )
        .outerjoin(m.Identity, m.Identity.identity_id == m.Finding.identity_id)
        .where(*where)
        .order_by(*order)
        .limit(filters.limit)
        .offset(filters.offset)
    )
    rows = session.execute(stmt).all()
    plan_ids = [r[0].plan_id for r in rows]
    decisions = _decisions_by_plan(session, plan_ids)
    items = [
        plan_out(r[0], r[2], r[1].rule_id if r[1] is not None else "", decisions.get(r[0].plan_id, []))
        for r in rows
    ]
    count_stmt = (
        select(func.count())
        .select_from(m.RemediationPlan)
        .outerjoin(
            m.Finding,
            (m.Finding.finding_key == m.RemediationPlan.finding_key)
            & (m.Finding.scan_id == m.RemediationPlan.scan_id),
        )
        .outerjoin(m.Identity, m.Identity.identity_id == m.Finding.identity_id)
        .where(*where)
    )
    total = int(session.scalar(count_stmt) or 0)
    return Page[RemediationPlanOut](items=items, total=total, limit=filters.limit, offset=filters.offset)


def _decisions_by_plan(session: Session, plan_ids: Sequence[str]) -> dict[str, list[m.Decision]]:
    if not plan_ids:
        return {}
    out: dict[str, list[m.Decision]] = {}
    for row in session.scalars(
        select(m.Decision).where(m.Decision.plan_id.in_(plan_ids)).order_by(m.Decision.created_at)
    ):
        if row.plan_id:
            out.setdefault(row.plan_id, []).append(row)
    return out


def get_plan_row(session: Session, plan_id: str) -> m.RemediationPlan | None:
    return session.get(m.RemediationPlan, plan_id)


def plan_detail(session: Session, plan_id: str) -> RemediationPlanOut | None:
    plan = session.get(m.RemediationPlan, plan_id)
    if plan is None:
        return None
    finding = session.get(m.Finding, {"finding_key": plan.finding_key, "scan_id": plan.scan_id})
    identity = session.get(m.Identity, finding.identity_id) if finding is not None else None
    decisions = _decisions_by_plan(session, [plan_id]).get(plan_id, [])
    return plan_out(plan, identity, finding.rule_id if finding is not None else "", decisions)


# ---------------------------------------------------------------------------
# ledger view (SPEC §12, §14)
# ---------------------------------------------------------------------------


def ledger_scans(session: Session, filters: ListFilters, chain: Any = None) -> Page[LedgerScanOut]:
    """Commit table. `chain` (a `LedgerClient`) is read best-effort; an outage only blanks columns."""
    where = _scan_filters(filters)
    allowed: dict[str, Any] = {
        "scan_id": m.Scan.scan_id,
        "snapshot_month": m.Scan.snapshot_month,
        "finding_count": m.Scan.finding_count,
        "ledger_status": m.Scan.ledger_status,
    }
    order = _order_by(filters.sort, allowed, "-scan_id", m.Scan.scan_id)
    rows = list(
        session.scalars(
            select(m.Scan).where(*where).order_by(*order).limit(filters.limit).offset(filters.offset)
        )
    )
    items = [_ledger_scan_out(row, chain) for row in rows]
    return Page[LedgerScanOut](
        items=items,
        total=_count(session, m.Scan, *where),
        limit=filters.limit,
        offset=filters.offset,
    )


def _ledger_scan_out(row: m.Scan, chain: Any) -> LedgerScanOut:
    chain_root: str | None = None
    timestamp: int | None = None
    if chain is not None and row.ledger_scan_index is not None:
        try:
            commit = chain.get_commit(row.ledger_scan_index)
        except Exception as exc:  # the ledger never blocks a read (SPEC §12.4)
            log.info("ledger read failed", extra={"scan_id": row.scan_id, "error": type(exc).__name__})
        else:
            chain_root = commit.findings_root
            timestamp = int(commit.timestamp)
    return LedgerScanOut(
        scan_id=row.scan_id,
        snapshot_month=row.snapshot_month,
        merkle_root=row.merkle_root,
        snapshot_hash=row.snapshot_hash,
        ruleset_hash=row.ruleset_hash,
        finding_count=row.finding_count,
        ledger_scan_index=row.ledger_scan_index,
        ledger_tx=row.ledger_tx,
        ledger_status=_scan_ledger_status(row.ledger_status),
        block_number=None,  # the commit struct carries no block number; the tx hash is the handle
        chain_root=chain_root,
        timestamp=timestamp,
    )


def instance_hashes_for_scan(session: Session, scan_id: int) -> list[str]:
    """Leaf hashes for a scan, RECOMPUTED from each finding's current columns (SPEC §12.6).

    Deliberately not the stored `instance_hash`: reading that back would only prove the stored
    hashes are self-consistent. Verification has to re-derive the committed instance from the row
    as it stands now, so that editing a severity in the database moves the root — which is exactly
    what the tamper demo shows and what the ledger exists to catch.
    """
    scan = session.get(m.Scan, scan_id)
    month = scan.snapshot_month if scan is not None else 0
    rows = list(session.scalars(select(m.Finding).where(m.Finding.scan_id == scan_id)))
    ordered = sorted(rows, key=lambda r: (r.rule_id, r.identity_id))
    return [
        instance_hash(
            finding_instance(
                finding_key=row.finding_key,
                identity_id=row.identity_id,
                rule_id=row.rule_id,
                severity=row.severity,
                score=row.score,
                snapshot_month=month,
                first_seen_month=row.first_seen_month,
                evidence_refs=[str(e) for e in (row.evidence_refs or [])],
                causal_event_ids=[str(e) for e in (row.causal_event_ids or [])],
            )
        )
        for row in ordered
    ]


_DECISION_SORTS: dict[str, Any] = {
    "created_at": m.Decision.created_at,
    "decision": m.Decision.decision,
    "scan_id": m.Decision.scan_id,
    "decision_id": m.Decision.decision_id,
}


def ledger_decisions(session: Session, filters: ListFilters) -> Page[LedgerDecisionOut]:
    where: list[Any] = []
    if filters.status is not None:
        where.append(or_(m.Decision.decision == filters.status, m.Decision.ledger_status == filters.status))
    if filters.month is not None:
        where.append(
            select(m.Scan.scan_id)
            .where(m.Scan.scan_id == m.Decision.scan_id, m.Scan.snapshot_month == filters.month)
            .correlate(m.Decision)
            .exists()
        )
    order = _order_by(filters.sort, _DECISION_SORTS, "-created_at", m.Decision.decision_id)
    rows = list(
        session.scalars(
            select(m.Decision).where(*where).order_by(*order).limit(filters.limit).offset(filters.offset)
        )
    )
    leaves = _leaves_for(session, rows)
    items = [
        LedgerDecisionOut(
            decision_id=r.decision_id,
            plan_id=r.plan_id,
            finding_key=r.finding_key,
            scan_id=r.scan_id,
            decision=_decision_kind(r.decision),
            decision_code=ledger_verify.DECISION_CODES.get(r.decision, 1),
            actor_user_id=r.actor_user_id,
            actor_hash=ledger_verify.actor_hash(r.actor_user_id),
            evidence_hash=r.evidence_hash,
            leaf=leaves.get((r.finding_key, r.scan_id)),
            ledger_tx=r.ledger_tx,
            ledger_status=_decision_ledger_status(r.ledger_status),
            created_at=r.created_at,
        )
        for r in rows
    ]
    return Page[LedgerDecisionOut](
        items=items,
        total=_count(session, m.Decision, *where),
        limit=filters.limit,
        offset=filters.offset,
    )


def _leaves_for(session: Session, decisions: Sequence[m.Decision]) -> dict[tuple[str, int], str]:
    if not decisions:
        return {}
    keys = sorted({d.finding_key for d in decisions})
    rows = session.execute(
        select(m.Finding.finding_key, m.Finding.scan_id, m.Finding.instance_hash).where(
            m.Finding.finding_key.in_(keys)
        )
    ).all()
    return {
        (str(key), int(scan_id)): merkle.to_hex(merkle.leaf_from_instance_hash(str(instance_hash)))
        for key, scan_id, instance_hash in rows
        if instance_hash
    }
