/**
 * One thin, typed function per API operation the shell uses (SPEC §13).
 * Pages call these through TanStack Query; the response type always comes from
 * the generated schema, never from a hand-written interface.
 */
import { api, apiFile, type FileResponse } from "./client";
import type {
  AdvanceResult,
  ApplyResult,
  EstateSummary,
  EvalOut,
  ExportQuery,
  FindingOut,
  FindingPage,
  FindingListQuery,
  HalfLifeTable,
  IdentityDetail,
  IdentityListQuery,
  IdentityPage,
  InvestigationOut,
  LedgerDecisionPage,
  LedgerInfo,
  LedgerListQuery,
  LedgerScanPage,
  LedgerVerifyOut,
  LoginRequest,
  PlanListQuery,
  PlanPage,
  RemediationPlanOut,
  RuleOut,
  ScanOut,
  SettingsOut,
  SettingsUpdate,
  SummaryOut,
  TimelineOut,
  UserOut,
} from "./types";

// --- auth (SPEC §15.1): the JWT is set as an httpOnly cookie, never returned ---

export const login = (body: LoginRequest) => api<UserOut>("/auth/login", { method: "POST", json: body });

export const logout = () => api<{ logged_out: boolean }>("/auth/logout", { method: "POST" });

export const getMe = () => api<UserOut>("/auth/me");

// --- read ---

export const getEstateSummary = () => api<EstateSummary>("/estate/summary");

export const listIdentities = (query: IdentityListQuery) => api<IdentityPage>("/identities", { query });

export const getIdentity = (identityId: string) =>
  api<IdentityDetail>(`/identities/${encodeURIComponent(identityId)}`);

// --- analyst actions (mutating → X-Requested-With: athar, added by the client) ---

export const runScan = (month?: number) =>
  api<ScanOut>("/scan", { method: "POST", json: { month: month ?? null } });

export const advanceMonth = () => api<AdvanceResult>("/simulate/advance", { method: "POST" });

// --- findings (SPEC §14 findings, §10) ---

export const listFindings = (query: FindingListQuery) => api<FindingPage>("/findings", { query });

export const getFinding = (findingKey: string) =>
  api<FindingOut>(`/findings/${encodeURIComponent(findingKey)}`);

/** The detection catalogue (SPEC §7) — static per ruleset, fetched once. */
export const listRules = () => api<RuleOut[]>("/rules");

// --- drift analytics (SPEC §9) ---

export const getHalfLife = () => api<HalfLifeTable>("/departments/halflife");

export const getTimeline = () => api<TimelineOut>("/timeline");

// --- agents (SPEC §11; cache-aware, `regenerate` bypasses the cache) ---

export const investigateFinding = (findingKey: string, regenerate = false) =>
  api<InvestigationOut>(`/agent/investigate/${encodeURIComponent(findingKey)}`, {
    method: "POST",
    query: regenerate ? { regenerate: true } : undefined,
  });

export const planRemediation = (findingKey: string, regenerate = false) =>
  api<RemediationPlanOut>(`/agent/plan/${encodeURIComponent(findingKey)}`, {
    method: "POST",
    query: regenerate ? { regenerate: true } : undefined,
  });

export const executiveSummary = (regenerate = false) =>
  api<SummaryOut>("/agent/summary", { method: "POST", query: regenerate ? { regenerate: true } : undefined });

// --- remediation queue (SPEC §11.5; the API enforces separation of duties) ---

export const listPlans = (query: PlanListQuery) => api<PlanPage>("/remediation", { query });

export const approvePlan = (planId: string) =>
  api<RemediationPlanOut>(`/remediation/${encodeURIComponent(planId)}/approve`, { method: "POST" });

export const rejectPlan = (planId: string, reason: string) =>
  api<RemediationPlanOut>(`/remediation/${encodeURIComponent(planId)}/reject`, {
    method: "POST",
    json: { reason },
  });

export const applyPlan = (planId: string) =>
  api<ApplyResult>(`/remediation/${encodeURIComponent(planId)}/apply`, { method: "POST" });

// --- ledger (SPEC §12) ---

export const getLedgerInfo = () => api<LedgerInfo>("/ledger");

export const listLedgerScans = (query: LedgerListQuery = {}) => api<LedgerScanPage>("/ledger/scans", { query });

export const verifyLedgerScan = (scanId: number) => api<LedgerVerifyOut>(`/ledger/scans/${scanId}/verify`);

export const listLedgerDecisions = (query: LedgerListQuery = {}) =>
  api<LedgerDecisionPage>("/ledger/decisions", { query });

// --- evaluation (SPEC §17: held-out seed) ---

export const getEval = () => api<EvalOut>("/eval");

// --- settings (SPEC §14 settings) ---

export const getSettings = () => api<SettingsOut>("/settings");

export const updateSettings = (body: SettingsUpdate) =>
  api<SettingsOut>("/settings", { method: "PUT", json: body });

// --- exports (SPEC §16): a file, not a page, with the current filters applied ---

export type ExportFormat = "csv" | "pdf" | "json";

const EXPORT_PATH: Record<ExportFormat, string> = {
  csv: "/export/findings.csv",
  pdf: "/export/findings.pdf",
  json: "/export/findings.json",
};

export const exportFindings = (format: ExportFormat, query: ExportQuery = {}): Promise<FileResponse> =>
  apiFile(EXPORT_PATH[format], { query }, `athar-findings.${format}`);
