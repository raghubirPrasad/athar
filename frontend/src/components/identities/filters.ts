import type { IdentityListQuery } from "../../api/types";

/** Table state that lives in the URL, so a filtered view is a shareable link. */
export interface IdentityFilterState {
  cloud: string;
  department: string;
  rule: string;
  severity: string;
  status: string;
  q: string;
  /** API sort string, e.g. "-score" (SPEC §13). */
  sort: string;
  offset: number;
  limit: number;
}

export const DEFAULT_SORT = "-score";
export const DEFAULT_LIMIT = 50;

export function readFilters(params: URLSearchParams): IdentityFilterState {
  const int = (key: string, fallback: number) => {
    const value = params.get(key);
    if (value === null || value.trim() === "") return fallback;
    const raw = Number(value);
    return Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : fallback;
  };
  return {
    cloud: params.get("cloud") ?? "",
    department: params.get("department") ?? "",
    rule: params.get("rule") ?? "",
    severity: params.get("severity") ?? "",
    status: params.get("status") ?? "",
    q: params.get("q") ?? "",
    sort: params.get("sort") ?? DEFAULT_SORT,
    offset: int("offset", 0),
    limit: Math.min(500, Math.max(1, int("limit", DEFAULT_LIMIT))),
  };
}

/** Only non-default values reach the URL, so "/identities" stays clean. */
export function writeFilters(state: IdentityFilterState): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of ["cloud", "department", "rule", "severity", "status", "q"] as const) {
    if (state[key]) params.set(key, state[key]);
  }
  if (state.sort !== DEFAULT_SORT) params.set("sort", state.sort);
  if (state.offset > 0) params.set("offset", String(state.offset));
  if (state.limit !== DEFAULT_LIMIT) params.set("limit", String(state.limit));
  return params;
}

/** Filter state → the query the API actually accepts (`ListFilters`, SPEC §13). */
export function toQuery(state: IdentityFilterState): IdentityListQuery {
  const query: IdentityListQuery = { limit: state.limit, offset: state.offset, sort: state.sort };
  if (state.cloud === "aws" || state.cloud === "azure" || state.cloud === "gcp") query.cloud = state.cloud;
  if (state.department) query.department = state.department;
  if (state.rule) query.rule = state.rule;
  if (state.severity === "Low" || state.severity === "Medium" || state.severity === "High" || state.severity === "Critical") {
    query.severity = state.severity;
  }
  if (state.status) query.status = state.status;
  if (state.q) query.q = state.q;
  return query;
}
