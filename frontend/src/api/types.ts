/**
 * Aliases into the generated OpenAPI schema (`npm run types` → schema.d.ts).
 * Nothing here declares a shape: every alias is a reference to a backend model,
 * so a contract change shows up as a type error rather than as silent drift
 * (CLAUDE.md, frontend conventions: never hand-write a response type).
 */
import type { components, operations } from "./schema";

export type Schemas = components["schemas"];

/** 200 JSON body of an operation, e.g. `Json<"estate_summary">`. */
export type Json<K extends keyof operations> =
  operations[K]["responses"] extends { 200: { content: { "application/json": infer T } } } ? T : never;

/** Query parameters of an operation, e.g. `Query<"list_identities">`. */
export type Query<K extends keyof operations> =
  operations[K]["parameters"] extends { query?: infer Q } ? NonNullable<Q> : never;

// Auth (SPEC §13, §15.1)
export type UserOut = Schemas["UserOut"];
export type LoginRequest = Schemas["LoginRequest"];
export type Problem = Schemas["Problem"];

// Enumerations — reused by filters and badges so the UI can never invent a value.
export type Cloud = Schemas["IdentityRow"]["clouds"][number];
export type Severity = Schemas["IdentityRow"]["severity"];
export type Role = Schemas["UserOut"]["role"];
export type EmploymentStatus = Schemas["IdentityRow"]["status"];
export type LedgerBadgeStatus = Schemas["LedgerBadge"]["status"];
export type HalfLifeLabel = Schemas["DepartmentRollup"]["half_life_label"];
export type Altitude = keyof Schemas["AltitudesOut"];

// Overview
export type EstateSummary = Schemas["EstateSummary"];
export type DepartmentRollup = Schemas["DepartmentRollup"];
export type LedgerBadge = Schemas["LedgerBadge"];

// Identities
export type IdentityRow = Schemas["IdentityRow"];
export type IdentityPage = Schemas["Page_IdentityRow_"];
export type IdentityDetail = Schemas["IdentityDetail"];
export type IdentityListQuery = Query<"list_identities">;

// Findings / remediation / ledger / eval — used by the later page passes.
export type FindingOut = Schemas["FindingOut"];
export type RuleOut = Schemas["RuleOut"];
export type RemediationPlanOut = Schemas["RemediationPlanOut"];
export type HalfLifeTable = Schemas["HalfLifeTable"];
export type TimelineOut = Schemas["TimelineOut"];
export type LedgerScanOut = Schemas["LedgerScanOut"];
export type LedgerInfo = Schemas["LedgerInfo"];
export type EvalOut = Schemas["EvalOut"];
export type SettingsOut = Schemas["SettingsOut"];

// Pieces of the drill-down (SPEC §14): every one is a backend model.
export type AltitudesOut = Schemas["AltitudesOut"];
export type ScoreOut = Schemas["ScoreOut"];
export type LineItemOut = Schemas["LineItemOut"];
export type PathEdgeOut = Schemas["PathEdgeOut"];
export type GrantOut = Schemas["GrantOut"];
export type ActivityOut = Schemas["ActivityOut"];
export type CredentialOut = Schemas["CredentialOut"];
export type CausalStepOut = Schemas["CausalStepOut"];
export type RiskPoint = Schemas["RiskPoint"];
export type ExceptionOut = Schemas["ExceptionOut"];
export type PrincipalOut = Schemas["PrincipalOut"];
export type EvidenceRefOut = Schemas["EvidenceRefOut"];
export type InvestigationOut = Schemas["InvestigationOut"];
export type SummaryOut = Schemas["SummaryOut"];

// Remediation (SPEC §11.5) and the decisions it produces (SPEC §12.4).
export type PolicyDiffOut = Schemas["PolicyDiffOut"];
export type PolicyOperation = Schemas["PolicyOperation"];
export type PlanAction = Schemas["RemediationPlanOut"]["action"];
export type PlanStatus = Schemas["RemediationPlanOut"]["status"];
export type DecisionOut = Schemas["DecisionOut"];
export type ApplyResult = Schemas["ApplyResult"];
export type RejectRequest = Schemas["RejectRequest"];
export type FindingStatus = Schemas["FindingOut"]["status"];

// Ledger (SPEC §12) and evaluation (SPEC §17).
export type LedgerDecisionOut = Schemas["LedgerDecisionOut"];
export type LedgerVerifyOut = Schemas["LedgerVerifyOut"];
export type LedgerDecisionKind = Schemas["LedgerDecisionOut"]["decision"];
export type LedgerRowStatus = Schemas["LedgerScanOut"]["ledger_status"];
export type RuleEval = Schemas["RuleEval"];
export type DecoyEval = Schemas["DecoyEval"];

// Timeline / half-life (SPEC §9).
export type TimelinePoint = Schemas["TimelinePoint"];
export type HalfLifeOut = Schemas["HalfLifeOut"];

// Settings (SPEC §14 settings, §13 RBAC on auto_remediate_departed).
export type SettingsUpdate = Schemas["SettingsUpdate"];
export type LlmStatus = Schemas["LlmStatus"];

// Paginated list bodies.
export type FindingPage = Schemas["Page_FindingOut_"];
export type PlanPage = Schemas["Page_RemediationPlanOut_"];
export type LedgerScanPage = Schemas["Page_LedgerScanOut_"];
export type LedgerDecisionPage = Schemas["Page_LedgerDecisionOut_"];

// List query shapes (SPEC §13: the same filter vocabulary everywhere).
export type FindingListQuery = Query<"list_findings">;
export type PlanListQuery = Query<"list_plans">;
export type LedgerListQuery = Query<"ledger_scans">;
export type ExportQuery = Query<"export_findings_csv">;

// Actions
export type ScanOut = Schemas["ScanOut"];
export type AdvanceResult = Schemas["AdvanceResult"];
