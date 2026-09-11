"""Bundle builders shared by the export tests (lane C3). Rows are built from athar.hashing so the
sidecar's instance_hash is the real committed hash, not a placeholder."""

from __future__ import annotations

from athar.export.types import (
    DepartmentRollupRow,
    ExportBundle,
    FindingExportRow,
    HalfLifeExportRow,
    RuleDef,
    ScanInfo,
)
from athar.hashing import finding_instance, finding_key, instance_hash

ROOT = "0x" + "ab" * 32
TX = "0x" + "cd" * 32
SEVERITIES = ("Critical", "High", "Medium", "Low")


def scan_info(**kw: object) -> ScanInfo:
    base: dict[str, object] = dict(
        scan_id=3,
        snapshot_month=6,
        month_label="June 2026",
        merkle_root=ROOT,
        ledger_tx=TX,
        ledger_status="anchored",
        ledger_scan_index=2,
        ruleset_hash="0x" + "11" * 32,
        snapshot_hash="0x" + "22" * 32,
        generated_at="2026-09-10T08:00:00+00:00",
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        chain_id=31337,
    )
    base.update(kw)
    return ScanInfo(**base)  # type: ignore[arg-type]


def make_row(i: int, **overrides: object) -> FindingExportRow:
    identity_id = f"emp-{i:04d}"
    rule_id = f"R{(i % 5) + 1}"
    key = finding_key(identity_id, rule_id)
    severity = SEVERITIES[i % 4]
    score = 95 - (i % 90)
    instance = finding_instance(
        finding_key=key,
        identity_id=identity_id,
        rule_id=rule_id,
        severity=severity,
        score=score,
        snapshot_month=6,
        first_seen_month=1 + (i % 6),
        evidence_refs=[f"grant:{identity_id}:g{i}", f"credential:{identity_id}:k{i}"],
        causal_event_ids=[f"evt-{i}"],
    )
    base: dict[str, object] = dict(
        finding_key=key,
        identity_id=identity_id,
        display_name=f"Person {i} <{identity_id}@nda.example>",
        identity_type="human" if i % 3 else "service",
        department="Finance" if i % 2 else "Platform Engineering",
        clouds=["aws", "azure"] if i % 2 else ["gcp"],
        rule_id=rule_id,
        rule_name="Admin, dormant",
        severity=severity,
        risk_score=score,
        blast_radius_pct=12.5 + i,
        first_seen_month=1 + (i % 6),
        causal_trigger="role_attached" if i % 2 else "",
        plain_english_finding=f"Person {i} has unrestricted control over everything in the account.",
        recommended_action="revoke_grant",
        attack_technique=["T1078 (verify)", "T1098 (verify)"],
        control_ref=["ISO 27001 A.9.2.3 (verify)"],
        status="open",
        instance_hash=instance_hash(instance),
        instance=instance,
        proof=["0x" + f"{i:064x}", "0x" + f"{i + 1:064x}"],
        explanation=f"Fired because emp-{i:04d} holds admin at org scope and has not been used in 4 months.",
    )
    base.update(overrides)
    return FindingExportRow(**base)  # type: ignore[arg-type]


def make_bundle(n_rows: int = 5, **overrides: object) -> ExportBundle:
    base: dict[str, object] = dict(
        org_name="Nahar Digital Authority",
        app_name="ATHAR",
        scan=scan_info(),
        rows=[make_row(i) for i in range(n_rows)],
        executive_summary="Three departments carry most of the blast radius.\n\nFinance leads on dormant admins.",
        department_rollup=[
            DepartmentRollupRow(
                department="Finance", identities=40, findings=9, critical=2, high=3, medium=3, low=1
            ),
            DepartmentRollupRow(
                department="Platform Engineering",
                identities=55,
                findings=12,
                critical=4,
                high=4,
                medium=2,
                low=2,
            ),
        ],
        halflife=[
            HalfLifeExportRow(
                department="Finance", grants=120, revocations=30, half_life_months=8.5, label="slow"
            ),
            HalfLifeExportRow(
                department="HR", grants=20, revocations=0, half_life_months=None, label="never"
            ),
        ],
        rule_definitions=[
            RuleDef(
                rule_id="R1",
                name="Admin, dormant",
                severity="Critical",
                summary="Admin at org scope with no activity for DORMANT_DAYS.",
                attack_techniques=["T1078 (verify)"],
                control_refs=["ISO 27001 A.9.2.3 (verify)"],
            ),
            RuleDef(rule_id="R2", name="Departed, still active", severity="Critical"),
        ],
        eval_sentence="precision 0.87 / recall 0.95 at High+ on held-out seed 7",
    )
    base.update(overrides)
    return ExportBundle(**base)  # type: ignore[arg-type]
