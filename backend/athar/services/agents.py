"""Agent glue: DB finding → structured facts → agent → persisted result (SPEC §11).

The agents never see the database and never decide anything: this module rebuilds the canonical
facts a finding was made of, hands them to `athar.agents`, and writes the prose back. The score,
the severity and the action set come from the rule engine on both sides of the call.
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from athar.agents.cache import CacheStore, DbCacheStore
from athar.agents.inputs import build_investigate_input, build_plan_input, build_summary_input
from athar.agents.investigate import investigate as run_investigate
from athar.agents.llm_client import LlmClient
from athar.agents.remediate import PlanEngine, PlanResult, plan_as_dict, plan_remediation
from athar.agents.summarise import executive_summary as run_summary
from athar.config import Settings
from athar.db import models as m
from athar.detection.base import EvidenceRef, FindingDraft
from athar.detection.registry import get_rule
from athar.domain import EstateView
from athar.drift.causal import causal_history
from athar.drift.halflife import halflife_by_department, halflife_overall
from athar.log import get_logger
from athar.narrative import rule_name
from athar.normaliser.inverse import policy_diff
from athar.scoring.blast_radius import compute as blast_radius
from athar.scoring.graph import build_graph
from athar.scoring.types import ScoreResult
from athar.services.estate_view import load_estate_view

log = get_logger(__name__)


def cache_for(session: Session) -> CacheStore:
    return DbCacheStore(session)


@lru_cache(maxsize=4)
def _client(provider: str, model: str) -> LlmClient:
    return LlmClient()


def client_for(settings: Settings) -> LlmClient:
    """One client per process, keyed by the provider configuration.

    The client remembers a provider that failed fatally (an invalid key, a model that is not
    pulled) and stops offering it. A fresh client per finding would re-learn that the hard way
    on every call, which on a warm demo is seconds of dead time per row.
    """
    return _client(settings.llm_provider, settings.llm_model)


def draft_from_row(row: m.Finding) -> FindingDraft:
    """Rebuild the rule's draft from what was committed (SPEC §10.1 keeps every field we need)."""
    evidence: list[EvidenceRef] = []
    for ref in row.evidence_refs or []:
        text = str(ref)
        kind, _, value = text.partition(":")
        evidence.append(EvidenceRef(kind=kind or "grant", ref=value or text))  # type: ignore[arg-type]
    return FindingDraft(
        rule_id=row.rule_id,
        identity_id=row.identity_id,
        severity=row.severity,
        evidence=evidence,
        causal_event_ids=[str(e) for e in (row.causal_event_ids or [])],
        facts=dict(row.facts or {}),
    )


def department_baseline(estate: EstateView, department: str | None) -> dict[str, Any]:
    """Median grant and category counts for the identity's department (agent context only)."""
    peers = [i for i in estate.identities.values() if i.department == department] if department else []
    if not peers:
        return {"median_grants": 0.0, "median_categories": 0.0, "identities": 0}
    grants = [len(estate.grants_for(p.identity_id)) for p in peers]
    cats = [len({g.service_category for g in estate.grants_for(p.identity_id)}) for p in peers]
    return {
        "median_grants": float(statistics.median(grants)),
        "median_categories": float(statistics.median(cats)),
        "identities": len(peers),
    }


def _score_for(session: Session, row: m.Finding) -> ScoreResult | None:
    stored = session.get(m.IdentityScore, {"identity_id": row.identity_id, "scan_id": row.scan_id})
    if stored is None:
        return None
    return ScoreResult(
        identity_id=stored.identity_id,
        blast_radius=stored.blast_radius,
        reachable_resources=0,
        high_sensitivity_reached=0,
        reach=stored.reach,
        exploitability=stored.exploitability,
        compensating=stored.compensating,
        formula_score=float(stored.score),
        rule_floor=0,
        score=stored.score,
        severity=stored.severity,
        line_items=[],
        escalation_paths=[],
    )


@dataclass
class InvestigationRecord:
    finding_key: str
    output: dict[str, Any]
    model_id: str
    prompt_version: str
    cached: bool
    generated_by: str


def investigate_finding(
    session: Session,
    settings: Settings,
    row: m.Finding,
    *,
    regenerate: bool = False,
    client: LlmClient | None = None,
) -> InvestigationRecord:
    estate = load_estate_view(session, _month_of_scan(session, row.scan_id))
    draft = draft_from_row(row)
    spec = get_rule(row.rule_id)
    score = _score_for(session, row)
    causal = causal_history(estate, draft)
    identity = estate.identities.get(row.identity_id)
    inp = build_investigate_input(
        estate,
        draft,
        score,
        causal,
        department_baseline(estate, identity.department if identity else None),
        spec,
    )
    result = run_investigate(inp, client or client_for(settings), cache_for(session), regenerate=regenerate)
    session.commit()
    return InvestigationRecord(
        finding_key=row.finding_key,
        output=result.output.model_dump(),
        model_id=result.meta.model_id,
        prompt_version=result.meta.prompt_version,
        cached=result.meta.cached,
        generated_by=result.meta.generated_by,
    )


def _month_of_scan(session: Session, scan_id: int) -> int:
    scan = session.get(m.Scan, scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    return scan.snapshot_month


def native_key(grant: Any) -> tuple[str, str, str]:
    """The provider-side grant a canonical row came from (SPEC §5.1 `granted_via`).

    One Azure role assignment or one AWS managed policy expands into many CPM rows — one per verb
    and category. A provider can only revoke the whole thing, so this is the granularity any
    remediation actually acts at.
    """
    return (grant.principal_ref, grant.granted_via, grant.scope_ref)


def widen_to_native(
    grants: Mapping[str, Any], keep: Sequence[str], drop: Sequence[str]
) -> tuple[list[str], list[str], int]:
    """Expand `drop` to whole provider grants, moving their siblings out of `keep`.

    Dropping half a role assignment is not something a cloud can do. Leaving those siblings on the
    keep list made the plan lie to the approver: apply revoked them anyway, because the generator
    matched the native grant. Returns (keep, drop, siblings_moved) so the rationale can say what
    the provider's granularity cost.
    """
    dropping = {native_key(grants[g]) for g in drop if g in grants}
    new_drop = sorted({g for g, row in grants.items() if native_key(row) in dropping} | set(drop))
    new_keep = sorted(set(keep) - set(new_drop))
    return new_keep, new_drop, len(new_drop) - len(set(drop))


def _plan_id(finding_key: str, scan_id: int, attempt: int) -> str:
    return f"plan-{finding_key[:12]}-{scan_id}-{attempt}"


def plan_for_finding(
    session: Session,
    settings: Settings,
    row: m.Finding,
    *,
    regenerate: bool = False,
    client: LlmClient | None = None,
    user_id: str | None = None,
) -> m.RemediationPlan:
    """Propose (or return) the remediation plan for a finding, with the engine's own after-figures."""
    existing = session.scalars(
        select(m.RemediationPlan)
        .where(m.RemediationPlan.finding_key == row.finding_key, m.RemediationPlan.scan_id == row.scan_id)
        .order_by(m.RemediationPlan.created_at.desc())
    ).first()
    if existing is not None and not regenerate and existing.status in ("proposed", "approved", "applied"):
        return existing

    month = _month_of_scan(session, row.scan_id)
    estate = load_estate_view(session, month)
    draft = draft_from_row(row)
    spec = get_rule(row.rule_id)
    score = _score_for(session, row)
    inp = build_plan_input(estate, draft, score, spec, estate.as_of)

    # The same `allow`-only set `build_plan_input` shows the agent (SPEC §5.2 `effect`). Three
    # things downstream read this, and a `deny` row corrupts each: `widen_to_native` would sweep a
    # deny into `drop` if it ever shared a provider grant with something being revoked, so the plan
    # would propose deleting a control rather than access; `compute_after` divides by the size of
    # this set, so denies in the denominator understate every privilege-reduction figure the
    # approver reads; and `policy_diff` would render the guardrail as a permission being removed.
    all_grants = {g.grant_id: g for g in estate.grants_for(row.identity_id) if g.effect == "allow"}

    def compute_after(keep: Any) -> tuple[float, float]:
        """Recompute both figures from the kept set — never trusted from the model (SPEC §11.4).

        `expected_blast_radius_after` is measured: the graph is rebuilt with only the kept grants.
        `privilege_reduction_pct` is the share of the identity's grants the plan removes. They are
        different questions, and both belong on screen: dropping an administrative grant is a real
        privilege reduction even when a second, redundant grant keeps reachability where it was —
        which is itself worth seeing, because it means one remediation is not enough.
        """
        kept = set(keep)
        trimmed = EstateView(
            month=estate.month,
            identities=estate.identities,
            principals=estate.principals,
            grants=[g for g in estate.grants if g.identity_id != row.identity_id or g.grant_id in kept],
            activity=estate.activity,
            credentials=estate.credentials,
            resources=estate.resources,
            projects=estate.projects,
            exceptions=estate.exceptions,
            events=estate.events,
        )
        after = blast_radius(build_graph(trimmed), row.identity_id)
        total = len(all_grants)
        dropped = len([g for g in all_grants if g not in kept])
        reduction = 0.0 if total == 0 else dropped / total * 100.0
        return (round(after.share, 6), round(reduction, 2))

    result: PlanResult = plan_remediation(
        inp,
        client or client_for(settings),
        cache_for(session),
        engine=PlanEngine(compute_after=compute_after),
        regenerate=regenerate,
    )
    fields = plan_as_dict(result)
    keep, drop, widened = widen_to_native(all_grants, fields["keep"], fields["drop"])
    if widened:
        blast_after, reduction = compute_after(keep)
        fields["keep"], fields["drop"] = keep, drop
        fields["expected_blast_radius_after"] = blast_after
        fields["privilege_reduction_pct"] = reduction
        fields["rationale"] = (
            f"{fields.get('rationale', '')} Widened to provider granularity: {widened} further "
            f"permission(s) go with the grants being revoked, because the cloud grants them together."
        ).strip()
    identity = estate.identities.get(row.identity_id)
    dropped = [all_grants[g] for g in fields["drop"] if g in all_grants]
    diff = (
        policy_diff(
            fields["action"],
            identity,
            list(all_grants.values()),
            dropped,
            [c for c in estate.credentials_for(row.identity_id) if c.active],
        ).as_dict()
        if identity is not None
        else {}
    )

    attempt = 1 + int(existing.plan_id.rsplit("-", 1)[-1]) if existing is not None else 1
    plan = m.RemediationPlan(
        plan_id=_plan_id(row.finding_key, row.scan_id, attempt),
        finding_key=row.finding_key,
        scan_id=row.scan_id,
        action=fields["action"],
        params=fields.get("params", {}),
        policy_diff=diff,
        keep=fields["keep"],
        drop=fields["drop"],
        privilege_reduction_pct=fields["privilege_reduction_pct"],
        expected_blast_radius_after=fields["expected_blast_radius_after"],
        proposed_by=result.proposed_by,
        proposer_user_id=user_id,
        model_id=result.meta.model_id,
        prompt_version=result.meta.prompt_version,
        rationale=fields.get("rationale", ""),
        confidence=fields.get("confidence", 0.0),
        status="proposed",
        created_at=datetime.now(UTC),
    )
    session.add(plan)
    if row.status == "open":
        row.status = "remediation_proposed"
    session.commit()
    log.info(
        "remediation planned",
        extra={
            "finding_key": row.finding_key,
            "action": plan.action,
            "reduction_pct": plan.privilege_reduction_pct,
            "proposed_by": plan.proposed_by,
        },
    )
    return plan


def estate_summary_paragraph(
    session: Session,
    settings: Settings,
    scan: m.Scan,
    *,
    regenerate: bool = False,
    client: LlmClient | None = None,
) -> dict[str, Any]:
    """Executive summary over aggregate statistics only — no identities reach the model (SPEC §11.4)."""
    findings = list(session.scalars(select(m.Finding).where(m.Finding.scan_id == scan.scan_id)))
    estate = load_estate_view(session, scan.snapshot_month)
    per_rule: dict[str, int] = {}
    per_dept: dict[str, int] = {}
    per_sev: dict[str, int] = {}
    for f in findings:
        per_rule[f.rule_id] = per_rule.get(f.rule_id, 0) + 1
        per_sev[f.severity] = per_sev.get(f.severity, 0) + 1
        identity = estate.identities.get(f.identity_id)
        dept = identity.department if identity else "Unassigned"
        per_dept[dept] = per_dept.get(dept, 0) + 1
    rows = halflife_by_department(estate.events, estate.identities, scan.snapshot_month) + halflife_overall(
        estate.events, estate.identities, scan.snapshot_month
    )
    top = sorted(findings, key=lambda f: (-f.score, f.finding_key))[:3]
    headlines = []
    for f in top:
        alt = (f.facts or {}).get("headline")
        headlines.append(str(alt) if alt else f"{rule_name(f.rule_id)} ({f.severity})")
    inp = build_summary_input(
        month=scan.snapshot_month,
        counts_per_rule=per_rule,
        counts_per_department=per_dept,
        counts_per_severity=per_sev,
        halflife_table=rows,
        top_headlines=headlines,
        rule_names={r: rule_name(r) for r in per_rule},
    )
    result = run_summary(inp, client or client_for(settings), cache_for(session), regenerate=regenerate)
    session.commit()
    return {
        "summary_paragraph": result.output.summary_paragraph,
        "top_themes": list(result.output.top_themes),
        "model_id": result.meta.model_id,
        "prompt_version": result.meta.prompt_version,
        "cached": result.meta.cached,
        "generated_by": result.meta.generated_by,
    }
