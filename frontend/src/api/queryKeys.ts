/**
 * Query-key factory. Page agents add entries per resource; keep keys
 * hierarchical so invalidation can target a subtree (`queryKeys.findings.all`).
 */
export type ListParams = Record<string, string | number | boolean | null | undefined>;

export const queryKeys = {
  auth: {
    all: ["auth"] as const,
    me: () => ["auth", "me"] as const,
  },
  estate: {
    all: ["estate"] as const,
    summary: () => ["estate", "summary"] as const,
  },
  identities: {
    all: ["identities"] as const,
    list: (params: ListParams = {}) => ["identities", "list", params] as const,
    detail: (id: string) => ["identities", "detail", id] as const,
  },
  findings: {
    all: ["findings"] as const,
    list: (params: ListParams = {}) => ["findings", "list", params] as const,
    detail: (key: string) => ["findings", "detail", key] as const,
  },
  rules: {
    all: ["rules"] as const,
    catalogue: () => ["rules", "catalogue"] as const,
  },
  departments: {
    all: ["departments"] as const,
    halflife: () => ["departments", "halflife"] as const,
  },
  scans: {
    all: ["scans"] as const,
    list: () => ["scans", "list"] as const,
    detail: (id: number | string) => ["scans", "detail", String(id)] as const,
  },
  remediation: {
    all: ["remediation"] as const,
    list: (params: ListParams = {}) => ["remediation", "list", params] as const,
  },
  ledger: {
    all: ["ledger"] as const,
    info: () => ["ledger", "info"] as const,
    scans: () => ["ledger", "scans"] as const,
    verify: (id: number | string) => ["ledger", "verify", String(id)] as const,
    decisions: () => ["ledger", "decisions"] as const,
  },
  timeline: {
    all: ["timeline"] as const,
    series: () => ["timeline", "series"] as const,
  },
  eval: {
    all: ["eval"] as const,
    report: () => ["eval", "report"] as const,
  },
  settings: {
    all: ["settings"] as const,
    current: () => ["settings", "current"] as const,
  },
  health: {
    all: ["health"] as const,
    deps: () => ["health", "deps"] as const,
  },
} as const;
