import type { ExportQuery, FindingListQuery } from "../../api/types";

/**
 * Findings-table state, in the URL so a filtered view is a link someone can
 * paste into a ticket. Same filter vocabulary as the identity table (SPEC §13):
 * cloud, department, rule, severity, month, status, search.
 */
export interface FindingFilterState {
  cloud: string;
  department: string;
  rule: string;
  severity: string;
  status: string;
  month: string;
  q: string;
  sort: string;
  offset: number;
  limit: number;
  /** Finding key of the row opened in the detail dialog. */
  open: string;
}

export const DEFAULT_SORT = "-score";
export const DEFAULT_LIMIT = 50;

function int(params: URLSearchParams, key: string, fallback: number): number {
  const value = params.get(key);
  if (value === null || value.trim() === "") return fallback;
  const raw = Number(value);
  return Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : fallback;
}

export function readFindingFilters(params: URLSearchParams): FindingFilterState {
  return {
    cloud: params.get("cloud") ?? "",
    department: params.get("department") ?? "",
    rule: params.get("rule") ?? "",
    severity: params.get("severity") ?? "",
    status: params.get("status") ?? "",
    month: params.get("month") ?? "",
    q: params.get("q") ?? "",
    sort: params.get("sort") ?? DEFAULT_SORT,
    offset: int(params, "offset", 0),
    limit: Math.min(500, Math.max(1, int(params, "limit", DEFAULT_LIMIT))),
    open: params.get("open") ?? "",
  };
}

export function writeFindingFilters(state: FindingFilterState): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of ["cloud", "department", "rule", "severity", "status", "month", "q", "open"] as const) {
    if (state[key]) params.set(key, state[key]);
  }
  if (state.sort !== DEFAULT_SORT) params.set("sort", state.sort);
  if (state.offset > 0) params.set("offset", String(state.offset));
  if (state.limit !== DEFAULT_LIMIT) params.set("limit", String(state.limit));
  return params;
}

/** The filter half of the state, shared by the list and the export endpoints. */
export function toFindingQuery(state: FindingFilterState): ExportQuery {
  const query: ExportQuery = {};
  if (state.cloud === "aws" || state.cloud === "azure" || state.cloud === "gcp") query.cloud = state.cloud;
  if (state.department) query.department = state.department;
  if (state.rule) query.rule = state.rule;
  if (
    state.severity === "Low" ||
    state.severity === "Medium" ||
    state.severity === "High" ||
    state.severity === "Critical"
  ) {
    query.severity = state.severity;
  }
  if (state.status) query.status = state.status;
  if (state.month) {
    const month = Number(state.month);
    if (Number.isFinite(month) && month > 0) query.month = month;
  }
  if (state.q) query.q = state.q;
  return query;
}

/** Filters plus paging and sort — what `GET /findings` is called with. */
export function toFindingListQuery(state: FindingFilterState): FindingListQuery {
  return { ...toFindingQuery(state), limit: state.limit, offset: state.offset, sort: state.sort };
}

export function isFindingFilterDirty(state: FindingFilterState): boolean {
  return (
    Boolean(state.cloud || state.department || state.rule || state.severity || state.status || state.month || state.q) ||
    state.sort !== DEFAULT_SORT
  );
}
