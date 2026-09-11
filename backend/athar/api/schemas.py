"""API response / request models (SPEC §13, §14). pydantic v2, every field typed.

These models ARE the contract: OpenAPI is generated from them and the frontend's TypeScript
types are generated from OpenAPI (`make types`). The data services (`athar.services`) return
these models through the `Repo` protocol in `athar.api.deps`. Names are stable; add fields,
do not rename them.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enumerations (Literal so they become TS unions)
# ---------------------------------------------------------------------------

Cloud = Literal["aws", "azure", "gcp"]
Severity = Literal["Low", "Medium", "High", "Critical"]
Role = Literal["viewer", "analyst", "approver"]
Altitude = Literal["headline", "explanation", "evidence"]
IdentityType = Literal["human", "service"]
EmploymentStatus = Literal["active", "departed", "on_leave"]
FindingStatus = Literal[
    "open",
    "investigated",
    "remediation_proposed",
    "approved",
    "remediated",
    "rejected",
    "exception_granted",
]
PlanStatus = Literal["proposed", "approved", "rejected", "applied"]
ProposedBy = Literal["model", "rule"]
GeneratedBy = Literal["model", "template"]
DecisionKind = Literal["approved", "rejected", "auto_remediated", "remediation_applied", "exception_granted"]
LedgerBadgeStatus = Literal["anchored", "pending", "unanchored", "verification_failed", "disabled"]
ScanLedgerStatus = Literal["pending", "anchored", "unanchored", "already_anchored", "failed"]
DecisionLedgerStatus = Literal["pending", "anchored", "unanchored", "failed"]
ExceptionType = Literal["break-glass", "dr-failover", "approved-privileged-role", "time-boxed"]
ExceptionSource = Literal["register", "workflow"]
HalfLifeLabel = Literal["Healthy", "Slow", "Broken"]
LlmProvider = Literal["gemini", "ollama", "none"]
UploadProvider = Literal["aws", "azure", "gcp", "hr"]
Action = Literal[
    "revoke_grant",
    "downgrade_to_least_privilege",
    "disable_identity",
    "rotate_or_disable_credential",
    "remove_cloud_access",
    "tag_as_exception",
    "no_action_recommended",
]
EvidenceKind = Literal[
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
]


class Page[T](BaseModel):
    """Paginated list (SPEC §13: every list endpoint paginates, limit ≤ 500)."""

    items: list[T]
    total: int = Field(description="Total rows matching the filters, ignoring limit/offset")
    limit: int
    offset: int


class ListFilters(BaseModel):
    """Query parameters shared by every list endpoint (SPEC §13)."""

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(100, ge=1, le=500)
    offset: int = Field(0, ge=0)
    cloud: Cloud | None = None
    department: str | None = Field(None, max_length=64)
    rule: str | None = Field(None, pattern=r"^R(10|[0-9])$", description="Rule id, e.g. R3")
    severity: Severity | None = None
    month: int | None = Field(None, ge=1, le=600)
    status: str | None = Field(None, max_length=32, description="Finding / plan / scan status")
    sort: str | None = Field(
        None,
        max_length=40,
        pattern=r"^-?[a-z_]+$",
        description="Sort field; prefix with '-' for descending, e.g. '-score'",
    )
    q: str | None = Field(None, max_length=120, description="Case-insensitive name search")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254, examples=["analyst@athar.local"])
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    user_id: str = Field(examples=["usr-analyst"])
    email: str
    role: Role


class LogoutOut(BaseModel):
    logged_out: bool = True


# ---------------------------------------------------------------------------
# Problem details (RFC 7807)
# ---------------------------------------------------------------------------


class ValidationIssue(BaseModel):
    loc: list[str]
    msg: str
    type: str


class Problem(BaseModel):
    type: str = Field("about:blank", description="URN identifying the problem class")
    title: str
    status: int
    detail: str | None = None
    code: str = Field(description="Stable machine-readable code, e.g. 'csrf.header_missing'")
    instance: str | None = Field(None, description="Request correlation id (urn:athar:request:<id>)")
    errors: list[ValidationIssue] | None = None


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


class DepartmentRollup(BaseModel):
    department: str
    identities: int
    findings: int
    critical: int
    high: int
    medium: int
    low: int
    offboarding_half_life: float | None = Field(None, description="Months; null == Never (SPEC §9.3)")
    half_life_label: HalfLifeLabel


class LedgerBadge(BaseModel):
    status: LedgerBadgeStatus
    last_scan_id: int | None = None
    last_root: str | None = None
    last_tx: str | None = None
    chain_id: int | None = None


class EstateSummary(BaseModel):
    current_month: int
    current_month_label: str = Field(examples=["August 2026"])
    identity_count: int
    humans: int
    services: int
    findings_total: int
    findings_by_severity: dict[Severity, int]
    findings_by_cloud: dict[Cloud, int]
    findings_by_department: list[DepartmentRollup]
    median_score: float
    ledger: LedgerBadge
    executive_summary: str | None = None
    model_id: str | None = None
    scan_id: int | None = None


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------


class IdentityRow(BaseModel):
    identity_id: str
    display_name: str
    identity_type: IdentityType
    department: str
    clouds: list[Cloud]
    score: int = Field(ge=0, le=100)
    severity: Severity
    top_rule: str | None = Field(None, examples=["R3"])
    top_rule_name: str | None = None
    blast_radius_pct: float = Field(description="Percent of estate reachable with control verbs")
    last_activity_at: date | None = None
    status: EmploymentStatus
    finding_count: int
    external: bool
    mfa_enforced: bool


class GrantOut(BaseModel):
    grant_id: str
    principal_ref: str
    cloud: Cloud
    service_category: str
    verb: str
    scope_level: str
    scope_ref: str
    region: str | None = None
    effect: str
    granted_via: str
    snapshot_month: int
    raw_snippet: dict[str, Any]
    source_file: str
    source_pointer: str
    active: bool = True


class ActivityOut(BaseModel):
    cloud: Cloud
    service_category: str
    snapshot_month: int
    last_activity_at: date | None = None
    operation_count: int


class CredentialOut(BaseModel):
    credential_ref: str
    cloud: Cloud
    kind: str
    created_at: date | None = None
    last_rotated_at: date | None = None
    last_used_at: date | None = None
    active: bool
    age_days: int | None = Field(None, description="Days since last rotation at the snapshot month-end")


class LineItemOut(BaseModel):
    term: str = Field(examples=["exploitability"])
    label: str = Field(examples=["departed +0.5"])
    value: float
    detail: dict[str, Any] = Field(default_factory=dict)


class PathEdgeOut(BaseModel):
    src: str
    verb: str
    dst: str
    grant_id: str | None = None


class ScoreOut(BaseModel):
    blast_radius: float
    reachable_resources: int
    high_sensitivity_reached: int
    reach: float
    exploitability: float
    compensating: float
    formula_score: float
    rule_floor: int
    score: int
    severity: Severity
    line_items: list[LineItemOut]
    escalation_paths: list[list[PathEdgeOut]]


class CausalStepOut(BaseModel):
    month: int
    event_id: str
    kind: str
    trigger: str
    cloud: Cloud | None = None
    description: str
    grant_delta: dict[str, Any] = Field(default_factory=dict)


class RiskPoint(BaseModel):
    month: int
    score: int
    severity: Severity
    events: list[CausalStepOut] = Field(default_factory=list, description="Events that moved the score")


class ExceptionOut(BaseModel):
    exception_id: str
    identity_id: str
    exception_type: ExceptionType
    approved_by: str
    approved_on: date | None = None
    review_date: date | None = None
    expires_on: date | None = None
    justification: str
    source: ExceptionSource
    valid: bool = Field(description="Unexpired at the current snapshot month-end")


class PrincipalOut(BaseModel):
    principal_ref: str
    cloud: Cloud
    principal_type: str
    link_method: str
    link_confidence: str


class AltitudesOut(BaseModel):
    """Three altitudes rendered from the same facts (SPEC §10.2)."""

    headline: str
    explanation: str
    evidence: dict[str, Any] = Field(description="Structured evidence: snippets, rows, rules, paths, ledger")


class EvidenceRefOut(BaseModel):
    kind: EvidenceKind
    ref: str
    note: str = ""


class InvestigationOut(BaseModel):
    finding_key: str
    hypothesis: str
    is_expected_for_role: bool
    evidence_cited: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: Action
    rationale: str
    model_id: str | None = None
    prompt_version: str
    cached: bool
    generated_by: GeneratedBy


class PolicyOperation(BaseModel):
    op: str = Field(
        examples=["detach_managed_policy"],
        description="detach_managed_policy | remove_inline_statement | delete_role_assignment | "
        "remove_binding_member | deactivate_key | disable_login",
    )
    target: str
    detail: str = ""


class PolicyDiffOut(BaseModel):
    cloud: Cloud | None = None
    before: dict[str, Any] = Field(default_factory=dict, description="Provider-native JSON before")
    after: dict[str, Any] = Field(default_factory=dict, description="Provider-native JSON after")
    operations: list[PolicyOperation] = Field(default_factory=list)
    summary: str = ""


class DecisionOut(BaseModel):
    decision_id: str
    plan_id: str | None = None
    finding_key: str
    scan_id: int
    decision: DecisionKind
    actor_user_id: str
    actor_email: str | None = None
    evidence_hash: str
    ledger_tx: str | None = None
    ledger_status: DecisionLedgerStatus
    created_at: datetime


class RemediationPlanOut(BaseModel):
    plan_id: str
    finding_key: str
    scan_id: int
    identity_id: str
    display_name: str
    rule_id: str
    action: Action
    params: dict[str, Any] = Field(default_factory=dict)
    policy_diff: PolicyDiffOut
    keep: list[str]
    drop: list[str]
    privilege_reduction_pct: float
    expected_blast_radius_after: float
    proposed_by: ProposedBy
    proposer_user_id: str | None = None
    model_id: str | None = None
    prompt_version: str | None = None
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    status: PlanStatus
    created_at: datetime
    decisions: list[DecisionOut] = Field(default_factory=list)


class FindingOut(BaseModel):
    finding_key: str
    scan_id: int
    snapshot_month: int
    identity_id: str
    display_name: str
    identity_type: IdentityType
    department: str
    clouds: list[Cloud]
    rule_id: str
    rule_name: str
    severity: Severity
    score: int
    first_seen_month: int
    status: FindingStatus
    evidence_refs: list[EvidenceRefOut]
    causal_event_ids: list[str]
    instance_hash: str
    leaf: str = Field(description="keccak256(keccak256(canonical_json(instance))) as 0x-hex")
    proof: list[str]
    altitudes: AltitudesOut
    allowed_actions: list[Action]
    attack_techniques: list[str] = Field(description="Marked '(verify)' until docs/MAPPINGS.md confirms")
    control_refs: list[str]
    facts: dict[str, Any]
    plan: RemediationPlanOut | None = None
    investigation: InvestigationOut | None = None
    exception: ExceptionOut | None = None


class IdentityDetail(BaseModel):
    identity_id: str
    display_name: str
    identity_type: IdentityType
    department: str
    employment_type: str
    employment_status: EmploymentStatus
    hire_month: int | None = None
    departure_month: int | None = None
    external: bool
    mfa_enforced: bool
    tags: dict[str, Any] = Field(
        description="Cloud-side tags: evidence to display, never an exception source"
    )
    contract_end_month: int | None = None
    first_seen_month: int
    last_seen_month: int
    clouds: list[Cloud]
    score: ScoreOut | None = None
    severity: Severity
    blast_radius_pct: float
    last_activity_at: date | None = None
    top_finding_key: str | None = None
    grants: list[GrantOut]
    activity: list[ActivityOut]
    credentials: list[CredentialOut]
    findings: list[FindingOut]
    causal_history: list[CausalStepOut]
    risk_history: list[RiskPoint]
    exceptions: list[ExceptionOut]
    altitudes: AltitudesOut | None = Field(None, description="Altitudes of the identity's top finding")
    principals: list[PrincipalOut]


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


class HalfLifeOut(BaseModel):
    department: str
    trigger: str = Field(examples=["all", "departure", "role_change"])
    grants: int
    revocations: int
    half_life_months: float | None = Field(None, description="null == Never (R/G < 0.10)")
    label: HalfLifeLabel


class HalfLifeTable(BaseModel):
    month: int
    rows: list[HalfLifeOut]


class TimelinePoint(BaseModel):
    month: int
    month_label: str
    identity_count: int
    findings_by_severity: dict[Severity, int]
    median_score: float
    half_life: dict[str, float | None] = Field(description="department -> months (null = Never)")


class TimelineOut(BaseModel):
    current_month: int
    points: list[TimelinePoint]


# ---------------------------------------------------------------------------
# Scans / ingest / simulation
# ---------------------------------------------------------------------------


class ScanOut(BaseModel):
    scan_id: int
    snapshot_month: int
    ruleset_hash: str
    started_at: datetime
    finished_at: datetime | None = None
    finding_count: int
    merkle_root: str | None = None
    snapshot_hash: str | None = None
    ledger_scan_index: int | None = None
    ledger_tx: str | None = None
    ledger_status: ScanLedgerStatus


class ScanRunRequest(BaseModel):
    month: int | None = Field(None, ge=1, le=600, description="Defaults to the current month")


class UploadedFileOut(BaseModel):
    filename: str
    bytes: int
    rows: int = Field(0, description="Canonical rows produced from this file")


class UploadResult(BaseModel):
    provider: UploadProvider
    month: int
    files: list[UploadedFileOut]
    warnings: list[str] = Field(default_factory=list)
    unmapped: int = Field(0, description="Grants that fell through to R0")


class AdvanceResult(BaseModel):
    new_month: int
    scan: ScanOut


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


class SummaryOut(BaseModel):
    summary_paragraph: str
    top_themes: list[str] = Field(max_length=3)
    model_id: str | None = None
    prompt_version: str
    cached: bool
    generated_by: GeneratedBy


# ---------------------------------------------------------------------------
# Remediation / exceptions
# ---------------------------------------------------------------------------


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class ApplyResult(BaseModel):
    plan: RemediationPlanOut
    finding: FindingOut
    score_before: int
    score_after: int
    blast_radius_before: float = Field(0.0, description="Share of the estate reachable, before")
    blast_radius_after: float = Field(0.0, description="Measured again after the re-scan, not predicted")
    scan_id: int = Field(description="The re-scan that produced score_after")
    ledger_status: str = Field("unanchored", description="Anchoring state of that re-scan")
    warnings: list[str] = Field(
        default_factory=list,
        description="Anything that stopped the simulated estate from changing; the decision is still recorded",
    )


class ExceptionRequest(BaseModel):
    exception_type: ExceptionType
    justification: str = Field(min_length=5, max_length=500)
    review_date: date | None = None
    expires_on: date | None = None


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class LedgerScanOut(BaseModel):
    scan_id: int
    snapshot_month: int
    merkle_root: str | None = None
    snapshot_hash: str | None = None
    ruleset_hash: str
    finding_count: int
    ledger_scan_index: int | None = None
    ledger_tx: str | None = None
    ledger_status: ScanLedgerStatus
    block_number: int | None = None
    chain_root: str | None = None
    timestamp: int | None = Field(None, description="Block timestamp (unix seconds) of the commit")


class LedgerVerifyOut(BaseModel):
    scan_id: int
    passed: bool
    computed_root: str | None = None
    chain_root: str | None = None
    scan_index: int | None = None
    finding_count: int
    detail: str


class LedgerDecisionOut(BaseModel):
    decision_id: str
    plan_id: str | None = None
    finding_key: str
    scan_id: int
    decision: DecisionKind
    decision_code: int = Field(
        ge=1, le=5, description="1 approved · 2 rejected · 3 auto · 4 applied · 5 exception"
    )
    actor_user_id: str
    actor_hash: str = Field(description="keccak256(user_id)")
    evidence_hash: str
    leaf: str | None = None
    ledger_tx: str | None = None
    ledger_status: DecisionLedgerStatus
    created_at: datetime


class LedgerInfo(BaseModel):
    enabled: bool
    contract_address: str | None = None
    chain_id: int | None = None
    writer_address: str | None = None
    purpose: str
    limits: str
    what_is_on_chain: list[str]
    what_is_not_on_chain: list[str]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


class RuleEval(BaseModel):
    rule_id: str
    tp: int
    fp: int
    fn: int
    precision: float | None = None
    recall: float | None = None


class DecoyEval(BaseModel):
    identity_id: str
    display_name: str
    looks_like: list[str]
    why_legitimate: str
    flagged_at: Severity | None = None
    correctly_handled: bool


class EvalOut(BaseModel):
    seed: int
    held_out: bool
    computed: bool = Field(
        default=True,
        description="False when `make eval` has not been run on this deployment. Every metric "
        "below is then zero because nothing was measured, not because the engine scored zero — "
        "a client must say so rather than render 0%.",
    )
    precision: float
    recall: float
    f1: float
    threshold: Literal["High+"] = "High+"
    tp: int
    fp: int
    fn: int
    per_rule: list[RuleEval]
    decoys: list[DecoyEval]
    director_sentence: str
    engineer_sentence: str
    generated_from: str = Field(
        description="Name of the estate these numbers came from (e.g. `seed-7`), or 'mock'. "
        "Never a path on the API host."
    )


# ---------------------------------------------------------------------------
# Settings / health
# ---------------------------------------------------------------------------


class LlmStatus(BaseModel):
    provider: LlmProvider
    model: str
    reachable: bool | None = Field(None, description="null when not probed")
    cache_entries: int


class SettingsOut(BaseModel):
    dormant_days: int
    stale_key_days: int
    approved_regions: list[str]
    auto_remediate_departed: bool
    updated_by: str | None = None
    updated_at: datetime | None = None
    llm: LlmStatus


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dormant_days: int | None = Field(None, ge=1, le=3650)
    stale_key_days: int | None = Field(None, ge=1, le=3650)
    approved_regions: list[str] | None = Field(None, max_length=32)
    auto_remediate_departed: bool | None = Field(None, description="Approver only (SPEC §15.1)")


class DepStatus(BaseModel):
    ok: bool
    detail: str


class RuleOut(BaseModel):
    """One detection rule's static metadata (SPEC §7). Served by GET /rules."""

    rule_id: str
    name: str
    severity: Severity
    version: str
    summary: str
    attack_techniques: list[str] = Field(default_factory=list)
    control_refs: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)


class HealthOut(BaseModel):
    status: Literal["ok"] = "ok"
    app: str
    version: str
    month: int | None = None
    mock: bool = False


class HealthDeps(BaseModel):
    db: DepStatus
    anvil: DepStatus
    llm: DepStatus
