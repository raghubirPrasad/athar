"""Export input contract (SPEC §16). Pure pydantic models; the services lane builds them from DB rows.

The CSV column order is fixed here (`CSV_COLUMNS`) and must match SPEC §16 exactly — the
`athar verify --csv` path and the judges' spreadsheets depend on it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

#: Exact SPEC §16 column order. Do not reorder.
CSV_COLUMNS: tuple[str, ...] = (
    "finding_key",
    "identity_id",
    "display_name",
    "identity_type",
    "department",
    "clouds",
    "rule_id",
    "rule_name",
    "severity",
    "risk_score",
    "blast_radius_pct",
    "first_seen_month",
    "causal_trigger",
    "plain_english_finding",
    "recommended_action",
    "attack_technique",
    "control_ref",
    "status",
    "instance_hash",
    "scan_id",
    "merkle_root",
    "ledger_tx",
)

#: Columns we format ourselves from non-negative numbers; they can never start with a formula trigger.
NUMERIC_COLUMNS: frozenset[str] = frozenset({"risk_score", "blast_radius_pct", "first_seen_month", "scan_id"})

#: The command a judge runs against an exported report (SPEC §12.6).
VERIFY_COMMAND = "athar verify --csv findings.csv --json findings.json"

#: Separator for multi-valued cells (clouds, attack_technique, control_ref).
MULTI_VALUE_SEPARATOR = ";"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanInfo(_Strict):
    """Scan-level facts shown on the cover, in the footer and in the sidecar."""

    scan_id: int = Field(ge=0)
    snapshot_month: int = Field(ge=0)
    month_label: str
    merkle_root: str | None = None
    ledger_tx: str | None = None
    ledger_status: str = "pending"  # pending | anchored | unanchored | already_anchored | failed
    ledger_scan_index: int | None = None
    ruleset_hash: str | None = None
    snapshot_hash: str | None = None
    generated_at: str  # operational timestamp supplied by the caller (services/api), never computed here
    contract_address: str | None = None
    chain_id: int | None = None


class FindingExportRow(_Strict):
    """One CSV row plus the non-CSV fields the sidecar and PDF need.

    `scan_id`, `merkle_root` and `ledger_tx` default to the bundle's `ScanInfo` when left unset.
    """

    finding_key: str
    identity_id: str
    display_name: str
    identity_type: str
    department: str
    clouds: list[str] = Field(default_factory=list)
    rule_id: str
    rule_name: str
    severity: str
    risk_score: int = Field(ge=0)
    blast_radius_pct: float = Field(ge=0.0)
    first_seen_month: int = Field(ge=1)
    causal_trigger: str = ""
    plain_english_finding: str = ""  # the Headline altitude (SPEC §10.2)
    recommended_action: str = ""
    attack_technique: list[str] = Field(default_factory=list)
    control_ref: list[str] = Field(default_factory=list)
    status: str = "open"
    instance_hash: str
    scan_id: int | None = None
    merkle_root: str | None = None
    ledger_tx: str | None = None
    # --- not in the CSV ---
    instance: dict[str, Any] = Field(default_factory=dict)  # committed instance JSON (SPEC §10.1)
    proof: list[str] = Field(default_factory=list)  # Merkle inclusion proof, 0x-hex nodes
    explanation: str = ""  # the Explanation altitude, used by the PDF top findings


class DepartmentRollupRow(_Strict):
    department: str
    identities: int = Field(ge=0)
    findings: int = Field(ge=0)
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)


class HalfLifeExportRow(_Strict):
    department: str
    grants: int = Field(ge=0)
    revocations: int = Field(ge=0)
    half_life_months: float | None = None
    label: str = ""


class RuleDef(_Strict):
    rule_id: str
    name: str
    severity: str
    summary: str = ""
    attack_techniques: list[str] = Field(default_factory=list)  # keep "(verify)" markers as given
    control_refs: list[str] = Field(default_factory=list)


class ExportBundle(_Strict):
    """Everything the three writers need. Built once by the caller, consumed by CSV, JSON and PDF."""

    org_name: str
    app_name: str
    scan: ScanInfo
    rows: list[FindingExportRow] = Field(default_factory=list)
    executive_summary: str = ""
    department_rollup: list[DepartmentRollupRow] = Field(default_factory=list)
    halflife: list[HalfLifeExportRow] = Field(default_factory=list)
    rule_definitions: list[RuleDef] = Field(default_factory=list)
    eval_sentence: str | None = None


# ---------------------------------------------------------------------------
# Sidecar shape (what `athar verify --csv` reads back)
# ---------------------------------------------------------------------------


class SidecarFinding(_Strict):
    finding_key: str
    instance: dict[str, Any]
    instance_hash: str
    proof: list[str] = Field(default_factory=list)


class FindingsSidecar(_Strict):
    scan: ScanInfo
    merkle_root: str | None = None
    ledger_tx: str | None = None
    contract_address: str | None = None
    chain_id: int | None = None
    findings: list[SidecarFinding] = Field(default_factory=list)
    verify_with: str = VERIFY_COMMAND
