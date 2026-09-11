"""Build the export bundle from the database and hand it to the writers (SPEC §16).

One bundle feeds all three formats: `findings.csv` (the §16 column order), `findings.json`
(the sidecar carrying each row's committed instance and Merkle proof, so
`athar verify --csv findings.csv --json findings.json` can check a report without trusting the
dashboard) and `findings.pdf`.

The row set is the `/findings` filter set (`ListFilters`), not the current page: a judge who
filters to "Critical, Finance" and exports gets every matching row, capped at `MAX_EXPORT_ROWS`.
`ScanInfo.generated_at` is the only wall-clock value in the document — an operational timestamp,
never an input to a hash.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from athar.api.schemas import FindingOut, ListFilters
from athar.clock import month_label
from athar.config import APP_NAME, ORG_NAME, Settings
from athar.db import models as m
from athar.detection.registry import all_rules
from athar.export.csv_export import write_findings_csv
from athar.export.json_export import write_findings_json
from athar.export.pdf import write_findings_pdf
from athar.export.summary import build_director_sentence, build_engineer_sentence
from athar.export.types import (
    DepartmentRollupRow,
    ExportBundle,
    FindingExportRow,
    HalfLifeExportRow,
    RuleDef,
    ScanInfo,
)
from athar.log import get_logger
from athar.narrative import rule_summary
from athar.services import queries

log = get_logger(__name__)

#: Upper bound on exported rows; the filters are the real selector (SPEC §16).
MAX_EXPORT_ROWS = 2000

#: Half-life trigger shown in the export table — offboarding is the headline number (SPEC §9.3).
EXPORT_HALFLIFE_TRIGGER = "departure"


def _scan_info(session: Session, settings: Settings, scan: m.Scan | None) -> ScanInfo:
    meta = session.get(m.LedgerMeta, 1)
    generated_at = datetime.now(UTC).isoformat()  # operational only: never hashed, never committed
    if scan is None:
        return ScanInfo(
            scan_id=0,
            snapshot_month=0,
            month_label="no scan yet",
            generated_at=generated_at,
            contract_address=meta.contract_address if meta else None,
            chain_id=meta.chain_id if meta else None,
        )
    return ScanInfo(
        scan_id=scan.scan_id,
        snapshot_month=scan.snapshot_month,
        month_label=month_label(scan.snapshot_month) if scan.snapshot_month >= 1 else "no data",
        merkle_root=scan.merkle_root,
        ledger_tx=scan.ledger_tx,
        ledger_status=scan.ledger_status,
        ledger_scan_index=scan.ledger_scan_index,
        ruleset_hash=scan.ruleset_hash,
        snapshot_hash=scan.snapshot_hash,
        generated_at=generated_at,
        contract_address=meta.contract_address if meta and settings.ledger_enabled else None,
        chain_id=meta.chain_id if meta and settings.ledger_enabled else None,
    )


def _row(finding: FindingOut, triggers: list[str], scan: m.Scan | None) -> FindingExportRow:
    facts: dict[str, Any] = finding.facts
    instance = facts.get("instance")
    action = finding.plan.action if finding.plan is not None else ""
    if not action:
        action = finding.allowed_actions[0] if finding.allowed_actions else "no_action_recommended"
    return FindingExportRow(
        finding_key=finding.finding_key,
        identity_id=finding.identity_id,
        display_name=finding.display_name,
        identity_type=finding.identity_type,
        department=finding.department,
        clouds=list(finding.clouds),
        rule_id=finding.rule_id,
        rule_name=finding.rule_name,
        severity=finding.severity,
        risk_score=max(0, finding.score),
        blast_radius_pct=max(0.0, float(facts.get("blast_radius_pct", 0.0) or 0.0)),
        first_seen_month=max(1, finding.first_seen_month),
        causal_trigger=";".join(triggers),
        plain_english_finding=finding.altitudes.headline,
        recommended_action=action,
        attack_technique=list(finding.attack_techniques),
        control_ref=list(finding.control_refs),
        status=finding.status,
        instance_hash=finding.instance_hash,
        scan_id=finding.scan_id,
        merkle_root=scan.merkle_root if scan is not None else None,
        ledger_tx=scan.ledger_tx if scan is not None else None,
        instance=instance if isinstance(instance, dict) else {},
        proof=list(finding.proof),
        explanation=finding.altitudes.explanation,
    )


def _rule_definitions() -> list[RuleDef]:
    """Every rule with its identifiers exactly as recorded — "(verify)" markers included."""
    return [
        RuleDef(
            rule_id=spec.id,
            name=spec.name,
            severity=spec.severity,
            summary=spec.description or rule_summary(spec.id),
            attack_techniques=list(spec.attack_techniques),
            control_refs=list(spec.control_refs),
        )
        for spec in all_rules()
    ]


def _department_rollup(session: Session, scan: m.Scan | None) -> list[DepartmentRollupRow]:
    return [
        DepartmentRollupRow(
            department=r.department,
            identities=r.identities,
            findings=r.findings,
            critical=r.critical,
            high=r.high,
            medium=r.medium,
            low=r.low,
        )
        for r in queries.department_rollup(session, scan)
    ]


def _halflife(session: Session, month: int) -> list[HalfLifeExportRow]:
    table = queries.halflife(session, month)
    return [
        HalfLifeExportRow(
            department=row.department,
            grants=row.grants,
            revocations=row.revocations,
            half_life_months=row.half_life_months,
            label=row.label,
        )
        for row in table.rows
        if row.trigger == EXPORT_HALFLIFE_TRIGGER
    ]


def eval_sentence(settings: Settings) -> str | None:
    """Both registers of the held-out evaluation (SPEC §17), or None when it has not been run."""
    from athar.eval.harness import load_result

    result = load_result(settings.athar_eval_seed, Path(settings.data_dir))
    if result is None:
        return None
    director = build_director_sentence(result.tp, result.fp, result.decoys_recognised)
    # Provenance is asserted from the setting, not taken from the stored document: this loads the
    # `ATHAR_EVAL_SEED` result by construction, and a file written before `held_out` existed
    # carries the field's False default (SPEC §8.3).
    engineer = build_engineer_sentence(
        result.precision, result.recall, seed=result.seed, held_out=result.seed == settings.athar_eval_seed
    )
    return f"{director} ({engineer})"


def build_bundle(session: Session, settings: Settings, filters: ListFilters) -> ExportBundle:
    """Everything the CSV, JSON and PDF writers need for the current filter set."""
    scan, rows, _total = queries.finding_rows(session, filters, limit=MAX_EXPORT_ROWS, offset=0)
    ctx = queries.build_context(session, scan, rows) if scan is not None else None
    export_rows: list[FindingExportRow] = []
    if ctx is not None:
        for row in rows:
            finding = queries.finding_out(row, ctx)
            triggers: list[str] = []
            for step in queries.causal_steps(row, ctx):
                if step.trigger and step.trigger not in triggers:
                    triggers.append(step.trigger)
            export_rows.append(_row(finding, triggers, scan))
    month = scan.snapshot_month if scan is not None else (queries.current_month(session) or 0)
    summary = queries.cached_summary(session, scan.scan_id) if scan is not None else None
    bundle = ExportBundle(
        org_name=ORG_NAME,
        app_name=APP_NAME,
        scan=_scan_info(session, settings, scan),
        rows=export_rows,
        executive_summary=summary.summary_paragraph if summary is not None else "",
        department_rollup=_department_rollup(session, scan),
        halflife=_halflife(session, month),
        rule_definitions=_rule_definitions(),
        eval_sentence=eval_sentence(settings),
    )
    log.info(
        "export bundle built",
        extra={"scan_id": bundle.scan.scan_id, "rows": len(bundle.rows), "month": month},
    )
    return bundle


def export_csv(session: Session, settings: Settings, filters: ListFilters) -> bytes:
    return write_findings_csv(build_bundle(session, settings, filters))


def export_json(session: Session, settings: Settings, filters: ListFilters) -> bytes:
    return write_findings_json(build_bundle(session, settings, filters))


def export_pdf(session: Session, settings: Settings, filters: ListFilters) -> bytes:
    return write_findings_pdf(build_bundle(session, settings, filters))
