"""Decisions and applied remediation (SPEC §10.3, §11.5, §12.4).

Every transition writes an `audit_log` row and, for the five decision kinds in SPEC §12.2, a
proof-bound record on the ledger. Applying a plan changes the *simulated* estate, re-ingests and
re-scans, so the score the UI shows afterwards is measured, not asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from athar.clock import month_end
from athar.config import Settings
from athar.db import models as m
from athar.hashing import sha256_hex
from athar.ledger import verify as ledger_verify
from athar.log import get_logger
from athar.services.estate_view import load_estate_view
from athar.services.ingest import estate_dir_for, ingest_month
from athar.services.scan import ScanOutcome, run_scan

log = get_logger(__name__)

DECISION_APPROVED = "approved"
DECISION_REJECTED = "rejected"
DECISION_AUTO = "auto_remediated"
DECISION_APPLIED = "remediation_applied"
DECISION_EXCEPTION = "exception_granted"


class RemediationError(RuntimeError):
    """A transition the lifecycle does not allow (SPEC §10.3)."""


@dataclass
class ApplyOutcome:
    plan_id: str
    finding_key: str
    identity_id: str
    score_before: int
    score_after: int
    blast_radius_before: float
    blast_radius_after: float
    scan: ScanOutcome | None
    ledger_status: str
    ledger_tx: str | None = None
    detail: str = ""
    warnings: list[str] = field(default_factory=list)


def audit(
    session: Session, actor: str, action: str, subject_type: str, subject_id: str, detail: dict[str, Any]
) -> None:
    session.add(
        m.AuditLog(
            at=datetime.now(UTC),
            actor_user_id=actor,
            action=action,
            subject_type=subject_type,
            subject_id=subject_id,
            detail=detail,
        )
    )


def _finding(session: Session, finding_key: str, scan_id: int) -> m.Finding | None:
    return session.get(m.Finding, {"finding_key": finding_key, "scan_id": scan_id})


def record_decision(
    session: Session,
    settings: Settings,
    *,
    kind: str,
    finding_key: str,
    scan_id: int,
    actor_user_id: str,
    plan: m.RemediationPlan | None,
    writer: Any = None,
    rationale: str = "",
) -> m.Decision:
    """Persist a decision and bind it to the committed finding with a Merkle proof (SPEC §12.4)."""
    evidence = ledger_verify.evidence_hash(
        plan.plan_id if plan else f"{kind}:{finding_key}",
        plan.action if plan else kind,
        plan.model_id if plan else None,
        plan.prompt_version if plan else None,
        rationale or (plan.rationale if plan else ""),
    )
    decision = m.Decision(
        decision_id=f"dec-{sha256_hex(f'{kind}|{finding_key}|{scan_id}|{actor_user_id}|{evidence}'.encode())[:24]}",
        plan_id=plan.plan_id if plan else None,
        finding_key=finding_key,
        scan_id=scan_id,
        decision=kind,
        actor_user_id=actor_user_id,
        evidence_hash=evidence,
        ledger_status="pending",
        created_at=datetime.now(UTC),
    )
    existing = session.get(m.Decision, decision.decision_id)
    if existing is not None:
        return existing
    session.add(decision)
    session.flush()

    scan = session.get(m.Scan, scan_id)
    finding = _finding(session, finding_key, scan_id)
    if writer is None or scan is None or finding is None or scan.ledger_scan_index is None:
        decision.ledger_status = "unanchored"
        return decision
    leaf, _ = ledger_verify.leaf_proofs([finding.instance_hash]).get(finding.instance_hash, ("", []))
    proof = [str(p) for p in (finding.leaf_proof or [])]
    try:
        receipt = writer.record_decision(
            scan.ledger_scan_index,
            leaf,
            proof,
            ledger_verify.DECISION_CODES[kind],
            ledger_verify.actor_hash(actor_user_id),
            evidence,
            tag=decision.decision_id,
        ).result(timeout=90)
    except Exception as exc:
        log.warning(
            "decision not anchored",
            extra={"decision_id": decision.decision_id, "error": type(exc).__name__},
        )
        decision.ledger_status = "unanchored"
        return decision
    decision.ledger_tx = receipt.tx_hash
    decision.ledger_status = "anchored"
    return decision


def approve(
    session: Session, settings: Settings, plan: m.RemediationPlan, actor_user_id: str, *, writer: Any = None
) -> m.RemediationPlan:
    if plan.status != "proposed":
        raise RemediationError(f"plan is {plan.status}, only a proposed plan can be approved")
    plan.status = "approved"
    finding = _finding(session, plan.finding_key, plan.scan_id)
    if finding is not None:
        finding.status = "approved"
    record_decision(
        session,
        settings,
        kind=DECISION_APPROVED,
        finding_key=plan.finding_key,
        scan_id=plan.scan_id,
        actor_user_id=actor_user_id,
        plan=plan,
        writer=writer,
    )
    audit(session, actor_user_id, "approve", "remediation_plan", plan.plan_id, {"action": plan.action})
    session.commit()
    return plan


def reject(
    session: Session,
    settings: Settings,
    plan: m.RemediationPlan,
    actor_user_id: str,
    reason: str,
    *,
    writer: Any = None,
) -> m.RemediationPlan:
    if plan.status not in ("proposed", "approved"):
        raise RemediationError(f"plan is {plan.status}, only a proposed or approved plan can be rejected")
    plan.status = "rejected"
    finding = _finding(session, plan.finding_key, plan.scan_id)
    if finding is not None:
        finding.status = "open"  # SPEC §10.3: rejection returns the finding to open
    record_decision(
        session,
        settings,
        kind=DECISION_REJECTED,
        finding_key=plan.finding_key,
        scan_id=plan.scan_id,
        actor_user_id=actor_user_id,
        plan=plan,
        writer=writer,
        rationale=reason,
    )
    audit(session, actor_user_id, "reject", "remediation_plan", plan.plan_id, {"reason": reason})
    session.commit()
    return plan


def grant_exception(
    session: Session,
    settings: Settings,
    finding: m.Finding,
    actor_user_id: str,
    *,
    exception_type: str,
    justification: str,
    review_date: date | None,
    expires_on: date | None,
    writer: Any = None,
) -> m.GovernanceException:
    """Write to the governance register (SPEC §4.3) so the next scan suppresses the rule."""
    exception_id = f"exc-wf-{sha256_hex(f'{finding.identity_id}|{exception_type}'.encode())[:16]}"
    row = session.get(m.GovernanceException, exception_id)
    if row is None:
        row = m.GovernanceException(
            exception_id=exception_id,
            identity_id=finding.identity_id,
            exception_type=exception_type,
            approved_by=actor_user_id,
            approved_on=datetime.now(UTC).date(),
            review_date=review_date,
            expires_on=expires_on,
            justification=justification,
            source="workflow",
        )
        session.add(row)
    else:
        row.exception_type = exception_type
        row.review_date = review_date
        row.expires_on = expires_on
        row.justification = justification
    finding.status = "exception_granted"
    record_decision(
        session,
        settings,
        kind=DECISION_EXCEPTION,
        finding_key=finding.finding_key,
        scan_id=finding.scan_id,
        actor_user_id=actor_user_id,
        plan=None,
        writer=writer,
        rationale=justification,
    )
    audit(
        session,
        actor_user_id,
        "grant_exception",
        "finding",
        finding.finding_key,
        {"exception_type": exception_type},
    )
    session.commit()
    return row


def _grant_refs(session: Session, plan: m.RemediationPlan) -> list[dict[str, Any]]:
    """Native handles for the dropped grants, so the generator can remove them from the exports."""
    ids = [str(g) for g in (plan.drop or [])]
    if not ids:
        return []
    rows = list(session.scalars(select(m.Grant).where(m.Grant.grant_id.in_(ids))))
    seen: set[tuple[str, str, str]] = set()
    refs: list[dict[str, Any]] = []
    for g in rows:
        key = (g.principal_ref, g.granted_via, g.scope_ref)
        if key in seen:
            continue
        seen.add(key)
        # principal + granted_via + scope identify the native grant. `service` is deliberately not
        # sent: the CPM's service_category ("network") is not the provider service name the
        # generator matches on ("Microsoft.Resources"), and sending it matches nothing.
        refs.append(
            {
                "principal_ref": g.principal_ref,
                "cloud": g.cloud,
                "granted_via": g.granted_via,
                "scope_ref": g.scope_ref,
            }
        )
    return refs


def _kept_grants_still_active(session: Session, plan: m.RemediationPlan, month: int) -> list[str]:
    """Grants the plan promised to keep that the apply revoked anyway (there should be none).

    The plan is widened to provider granularity before it is stored, so keep and drop already
    describe whole native grants. This is the check that the promise held after the estate was
    regenerated and re-ingested; anything it returns is surfaced as a warning rather than hidden.
    """
    keep = [str(g) for g in (plan.keep or [])]
    if not keep:
        return []
    rows = session.scalars(
        select(m.Grant).where(m.Grant.grant_id.in_(keep), m.Grant.snapshot_month == month)
    ).all()
    present = {g.grant_id for g in rows if g.active}
    return sorted(set(keep) - present)


def apply_plan(
    session: Session,
    settings: Settings,
    plan: m.RemediationPlan,
    actor_user_id: str,
    *,
    writer: Any = None,
    estate_dir: Path | None = None,
) -> ApplyOutcome:
    """Apply an approved plan to the simulated estate, re-ingest, re-scan (SPEC §11.5)."""
    if plan.status != "approved":
        raise RemediationError(f"plan is {plan.status}, only an approved plan can be applied")
    finding = _finding(session, plan.finding_key, plan.scan_id)
    if finding is None:
        raise RemediationError("the plan's finding is not in this scan")
    before = session.get(m.IdentityScore, {"identity_id": finding.identity_id, "scan_id": plan.scan_id})
    score_before = before.score if before else 0
    br_before = before.blast_radius if before else 0.0

    scan_row = session.get(m.Scan, plan.scan_id)
    month = scan_row.snapshot_month if scan_row else 0
    warnings: list[str] = []
    outcome: ScanOutcome | None = None
    estate_path = estate_dir or estate_dir_for(settings)

    try:
        from athar.generator.estate import apply_remediation
        from athar.generator.state import RemediationSpec

        spec = RemediationSpec(
            month=month,
            identity_id=finding.identity_id,
            action=plan.action,
            cloud=None,
            grant_refs=tuple(_grant_refs(session, plan)),
            credential_ref=(plan.params or {}).get("credential_ref"),
            note=f"{plan.plan_id} approved by {actor_user_id}",
        )
        apply_remediation(estate_path, spec)
        ingest_month(session, estate_path, month)
        outcome = run_scan(session, settings, month, writer=writer)
    except Exception as exc:
        warnings.append(f"estate not updated ({type(exc).__name__}: {exc})")
        log.warning(
            "apply could not change the simulated estate",
            extra={"plan_id": plan.plan_id, "error": type(exc).__name__},
        )

    if outcome is not None:
        lost = _kept_grants_still_active(session, plan, month)
        if lost:
            warnings.append(
                f"{len(lost)} grant(s) the plan kept are no longer active after the change; "
                "the provider revokes them together with the grants that were dropped"
            )
            log.warning(
                "apply revoked grants the plan kept",
                extra={"plan_id": plan.plan_id, "count": len(lost)},
            )

    plan.status = "applied"
    if finding is not None:
        finding.status = "remediated"
    record_decision(
        session,
        settings,
        kind=DECISION_APPLIED,
        finding_key=plan.finding_key,
        scan_id=plan.scan_id,
        actor_user_id=actor_user_id,
        plan=plan,
        writer=writer,
    )
    audit(
        session,
        actor_user_id,
        "apply",
        "remediation_plan",
        plan.plan_id,
        {"action": plan.action, "drop": list(plan.drop or [])},
    )
    session.commit()

    after_scan_id = outcome.scan_id if outcome else plan.scan_id
    after = session.get(m.IdentityScore, {"identity_id": finding.identity_id, "scan_id": after_scan_id})
    return ApplyOutcome(
        plan_id=plan.plan_id,
        finding_key=plan.finding_key,
        identity_id=finding.identity_id,
        score_before=score_before,
        score_after=after.score if after else score_before,
        blast_radius_before=br_before,
        blast_radius_after=after.blast_radius if after else br_before,
        scan=outcome,
        ledger_status=outcome.ledger_status if outcome else "unanchored",
        detail="applied",
        warnings=warnings,
    )


AUTO_ACTION = "disable_identity"
AUTO_DEPARTED_DAYS = 30
AUTO_RATIONALE = "auto-remediation: departed ≥ 30 days, no unexpired exception"


def _auto_candidates(session: Session, scan_id: int, month: int) -> list[m.Finding]:
    """R3 findings that pass every SPEC §11.5 gate, ordered by finding key."""
    estate = load_estate_view(session, month)
    rows = session.scalars(
        select(m.Finding)
        .where(m.Finding.scan_id == scan_id, m.Finding.rule_id == "R3")
        .order_by(m.Finding.finding_key)
    )
    out: list[m.Finding] = []
    for finding in rows:
        identity = estate.identities.get(finding.identity_id)
        if identity is None or identity.identity_type != "human":
            continue
        if identity.employment_status != "departed" or identity.departure_month is None:
            continue
        if (estate.as_of - month_end(identity.departure_month)).days < AUTO_DEPARTED_DAYS:
            continue
        if estate.valid_exception(identity.identity_id):
            continue
        out.append(finding)
    return out


def _disable_in_estate(
    estate_path: Path, month: int, findings: list[m.Finding], warnings: list[str]
) -> set[str]:
    """Disable every candidate identity in the simulated estate; returns the ones that changed.

    One re-simulation for the whole batch (`apply_remediations`), the same generator path an
    approved `disable_identity` plan takes. A spec already in `remediations.jsonl` is not returned,
    so a re-run of the same scan neither rewrites the estate nor claims a second disable. An estate
    that cannot be changed (an uploaded one, or a node that is not a generated tree) degrades to a
    warning: the decision is still recorded, and the audit row says the estate did not change.
    """
    from athar.generator.estate import apply_remediations
    from athar.generator.state import RemediationSpec

    specs = [
        RemediationSpec(
            month=month,
            identity_id=f.identity_id,
            action=AUTO_ACTION,
            cloud=None,
            grant_refs=(),
            credential_ref=None,
            note=f"auto-remediation of {f.finding_key} (SPEC §11.5)",
        )
        for f in findings
    ]
    try:
        return {spec.identity_id for spec in apply_remediations(estate_path, specs)}
    except Exception as exc:  # SPEC §11.5: a degraded estate must not stop the governance loop
        warnings.append(f"estate not updated ({type(exc).__name__}: {exc})")
        log.warning(
            "auto-remediation could not change the simulated estate",
            extra={"month": month, "count": len(specs), "error": type(exc).__name__},
        )
        return set()


def auto_remediate(
    session: Session,
    settings: Settings,
    scan_id: int,
    *,
    writer: Any = None,
    estate_dir: Path | None = None,
) -> list[m.Decision]:
    """The one automatic path (SPEC §11.5): departed humans, ≥ 30 days, no unexpired exception.

    Off unless `auto_remediate_departed` is set by an approver. Action `disable_identity`, applied
    to the simulated estate through the same generator path an approved plan uses, then re-ingested
    and re-scanned so the dashboard shows the access actually gone. Always logged, always on-chain,
    and reversible through a recorded `exception_granted` (the register entry suppresses the rule
    and the remediation can be dropped from `remediations.jsonl`).
    """
    runtime = session.get(m.RuntimeSettings, 1)
    enabled = runtime.auto_remediate_departed if runtime is not None else settings.auto_remediate_departed
    if not enabled:
        return []
    scan = session.get(m.Scan, scan_id)
    if scan is None:
        return []
    month = scan.snapshot_month
    findings = _auto_candidates(session, scan_id, month)
    if not findings:
        return []

    warnings: list[str] = []
    estate_path = estate_dir or estate_dir_for(settings)
    disabled = _disable_in_estate(estate_path, month, findings, warnings)

    out: list[m.Decision] = []
    for finding in findings:
        decision = record_decision(
            session,
            settings,
            kind=DECISION_AUTO,
            finding_key=finding.finding_key,
            scan_id=scan_id,
            actor_user_id="system:auto",
            plan=None,
            writer=writer,
            rationale=AUTO_RATIONALE,
        )
        finding.status = "remediated"
        audit(
            session,
            "system:auto",
            "auto_remediate",
            "finding",
            finding.finding_key,
            {
                "action": AUTO_ACTION,
                "identity_id": finding.identity_id,
                "estate": "changed" if finding.identity_id in disabled else "unchanged",
                "warnings": warnings,
            },
        )
        out.append(decision)
    session.commit()

    if disabled:
        # The estate on disk no longer grants these identities anything; re-ingest and re-scan so
        # the scores and findings the UI serves are measured against what the exports now say.
        try:
            ingest_month(session, estate_path, month)
            run_scan(session, settings, month, writer=writer)
        except Exception as exc:
            session.rollback()
            log.warning(
                "auto-remediation applied but the re-scan failed",
                extra={"month": month, "error": type(exc).__name__, "detail": str(exc)[:200]},
            )
            # The decisions above are already committed and say the access was removed; the estate
            # on disk agrees, and only the database still shows the grants. A log line is not
            # enough for a divergence between what the ledger attests and what the dashboard
            # displays, so it goes in the audit trail, where the next reader will find it. The fix
            # is `athar ingest --month <n>` followed by a scan; nothing here retries on its own,
            # because whatever broke the ingest will most likely break it again.
            audit(
                session,
                "system:auto",
                "auto_remediate_incomplete",
                "snapshot",
                str(month),
                {
                    "identities": sorted(disabled),
                    "error": type(exc).__name__,
                    "detail": str(exc)[:200],
                    "estate": "changed",
                    "database": "stale — re-ingest this month",
                },
            )
            session.commit()
    return out
