/**
 * Typed fixtures for page tests. Every value is shaped by the generated OpenAPI
 * models, so a backend contract change breaks these the same way it breaks the
 * pages (CLAUDE.md: never hand-write a response type).
 *
 * The three `ScoreOut` fixtures are verbatim captures from a running API (seed
 * 42, month 12) rather than hand-written shapes: the score line's arithmetic can
 * only be tested against line items the engine actually emits.
 */
import type {
  EstateSummary,
  EvalOut,
  FindingOut,
  GrantOut,
  HalfLifeTable,
  IdentityDetail,
  PolicyDiffOut,
  RemediationPlanOut,
  RuleOut,
  ScoreOut,
  TimelineOut,
  UserOut,
} from "../api/types";

export const APPROVER: UserOut = { user_id: "usr-approver", email: "approver@athar.local", role: "approver" };
export const ANALYST: UserOut = { user_id: "usr-analyst", email: "analyst@athar.local", role: "analyst" };
export const VIEWER: UserOut = { user_id: "usr-judge", email: "judge@athar.local", role: "viewer" };

/**
 * Three rows of the catalogue `GET /rules` serves, captured verbatim — R0
 * included, because R0 findings exist and the filters must offer it.
 */
export const RULES: RuleOut[] = [
  {
    rule_id: "R0",
    name: "Unmapped permission",
    severity: "Low",
    version: "1.0",
    summary: "A provider permission that the mapping tables could not classify; its verb and category stay unclassified until a mapping is added.",
    attack_techniques: [],
    control_refs: [],
    allowed_actions: [
      "no_action_recommended",
      "tag_as_exception"
    ]
  },
  {
    rule_id: "R3",
    name: "Orphaned identity",
    severity: "Critical",
    version: "1.0",
    summary: "A departed employee (for at least one month) or a service account of a retired project that still holds active grants.",
    attack_techniques: [
      "T1078.004 (verify)"
    ],
    control_refs: [
      "ISO 27001:2022 A.5.18 (verify)",
      "ISO 27001:2022 A.6.5 (verify)"
    ],
    allowed_actions: [
      "disable_identity",
      "remove_cloud_access",
      "revoke_grant",
      "tag_as_exception"
    ]
  },
  {
    rule_id: "R4",
    name: "Cross-cloud superuser",
    severity: "Critical",
    version: "1.0",
    summary: "One identity holds admin (Critical) or write and delete (High) at project scope or above in all three clouds.",
    attack_techniques: [
      "T1078.004 (verify)"
    ],
    control_refs: [
      "ISO 27001:2022 A.5.15 (verify)"
    ],
    allowed_actions: [
      "downgrade_to_least_privilege",
      "remove_cloud_access",
      "revoke_grant",
      "tag_as_exception",
      "no_action_recommended"
    ]
  }
];

export const GRANT: GrantOut = {
  grant_id: "grant-emp-0012-04",
  principal_ref: "aws:user:latifa.al.ketbi",
  cloud: "aws",
  service_category: "identity",
  verb: "admin",
  scope_level: "org",
  scope_ref: "arn:aws:iam::123456789012:user/latifa.al.ketbi",
  region: "me-central-1",
  effect: "allow",
  granted_via: "managed_policy:AdministratorAccess",
  snapshot_month: 12,
  raw_snippet: { PolicyName: "AdministratorAccess" },
  source_file: "aws/authorization-details.json",
  source_pointer: "/UserDetailList/31",
  active: true,
};

/** Critical, floored at 50 by R4 but saturated reach pushes the formula past 100. Captured verbatim from `GET /identities/emp-0093` (seed 42, month 12). */
export const SCORE: ScoreOut = {
  blast_radius: 0.698795,
  reachable_resources: 174,
  high_sensitivity_reached: 87,
  reach: 1.0,
  exploitability: 1.2,
  compensating: 0.0,
  formula_score: 120.0,
  rule_floor: 50,
  score: 100,
  severity: "Critical",
  line_items: [
    {
      term: "reach",
      label: "blast radius 70% of estate, 87 high-sensitivity resources",
      value: 1.0,
      detail: {
        reachable: 174,
        ref_share: 0.25,
        saturated: true,
        blast_radius: 0.6988,
        total_resources: 246,
        high_sensitivity: 87
      }
    },
    {
      term: "exploitability",
      label: "base",
      value: 1.0,
      detail: {}
    },
    {
      term: "exploitability",
      label: "cross-cloud +0.2",
      value: 0.2,
      detail: {
        rule: "R4"
      }
    },
    {
      term: "exploitability",
      label: "exploitability 1.2",
      value: 1.2,
      detail: {
        summary: true
      }
    },
    {
      term: "compensating",
      label: "none",
      value: 0.0,
      detail: {}
    },
    {
      term: "compensating",
      label: "controls 1.0",
      value: 0.0,
      detail: {
        summary: true,
        controls_multiplier: 1.0
      }
    },
    {
      term: "formula",
      label: "100 × reach × exploitability × controls",
      value: 120.0,
      detail: {
        reach: 1.0,
        controls: 1.0,
        exploitability: 1.2
      }
    },
    {
      term: "floor",
      label: "R4",
      value: 50.0,
      detail: {
        fired: {
          R4: "High"
        },
        rules: [
          "R4"
        ]
      }
    },
    {
      term: "final",
      label: "Critical",
      value: 100.0,
      detail: {
        floor: 50,
        clamped: true,
        floored: false,
        formula: 120.0
      }
    }
  ],
  escalation_paths: [
    [
      {
        src: "id:emp-0093",
        verb: "impersonate",
        dst: "p:831fe884-9c17-4363-bc44-cb36d89c568d",
        grant_id: "3a6958c88ab2804ea441d2ac6fa89e2a"
      }
    ],
    [
      {
        src: "id:emp-0093",
        verb: "impersonate",
        dst: "p:84c84c23-676e-34be-78be-c228c455da79",
        grant_id: "3a6958c88ab2804ea441d2ac6fa89e2a"
      }
    ]
  ]
};

/** Departed and dormant: the formula is 4, the R3 floor decides the score. Captured verbatim from `GET /identities/emp-0064` (seed 42, month 12). */
export const SCORE_FLOORED: ScoreOut = {
  blast_radius: 0.006024,
  reachable_resources: 3,
  high_sensitivity_reached: 0,
  reach: 0.0241,
  exploitability: 1.8,
  compensating: 0.0,
  formula_score: 4.34,
  rule_floor: 75,
  score: 75,
  severity: "Critical",
  line_items: [
    {
      term: "reach",
      label: "blast radius 1% of estate, 0 high-sensitivity resources",
      value: 0.0241,
      detail: {
        reachable: 3,
        ref_share: 0.25,
        saturated: false,
        blast_radius: 0.006,
        total_resources: 246,
        high_sensitivity: 0
      }
    },
    {
      term: "exploitability",
      label: "base",
      value: 1.0,
      detail: {}
    },
    {
      term: "exploitability",
      label: "departed +0.5",
      value: 0.5,
      detail: {
        departure_month: 1
      }
    },
    {
      term: "exploitability",
      label: "dormant +0.3",
      value: 0.3,
      detail: {
        rule: "R2"
      }
    },
    {
      term: "exploitability",
      label: "exploitability 1.8",
      value: 1.8,
      detail: {
        summary: true
      }
    },
    {
      term: "compensating",
      label: "none",
      value: 0.0,
      detail: {}
    },
    {
      term: "compensating",
      label: "controls 1.0",
      value: 0.0,
      detail: {
        summary: true,
        controls_multiplier: 1.0
      }
    },
    {
      term: "formula",
      label: "100 × reach × exploitability × controls",
      value: 4.34,
      detail: {
        reach: 0.0241,
        controls: 1.0,
        exploitability: 1.8
      }
    },
    {
      term: "floor",
      label: "R3",
      value: 75.0,
      detail: {
        fired: {
          R2: "Medium",
          R3: "Critical",
          R6: "Medium"
        },
        rules: [
          "R3"
        ]
      }
    },
    {
      term: "final",
      label: "Critical",
      value: 75.0,
      detail: {
        floor: 75,
        clamped: false,
        floored: true,
        formula: 4.34
      }
    }
  ],
  escalation_paths: []
};

/** An unexpired break-glass exception in the register credits 0.35. Captured verbatim from `GET /identities/emp-0277` (seed 42, month 12). */
export const SCORE_COMPENSATED: ScoreOut = {
  blast_radius: 0.692771,
  reachable_resources: 171,
  high_sensitivity_reached: 87,
  reach: 1.0,
  exploitability: 1.0,
  compensating: 0.35,
  formula_score: 65.0,
  rule_floor: 0,
  score: 65,
  severity: "High",
  line_items: [
    {
      term: "reach",
      label: "blast radius 69% of estate, 87 high-sensitivity resources",
      value: 1.0,
      detail: {
        reachable: 171,
        ref_share: 0.25,
        saturated: true,
        blast_radius: 0.6928,
        total_resources: 246,
        high_sensitivity: 87
      }
    },
    {
      term: "exploitability",
      label: "base",
      value: 1.0,
      detail: {}
    },
    {
      term: "exploitability",
      label: "exploitability 1.0",
      value: 1.0,
      detail: {
        summary: true
      }
    },
    {
      term: "compensating",
      label: "break-glass (register, MFA enforced) −0.35",
      value: 0.35,
      detail: {
        review_date: "2026-12-31",
        exception_id: "2d4eb5266fbe1e384eb5944236684aed"
      }
    },
    {
      term: "compensating",
      label: "controls 0.65",
      value: 0.35,
      detail: {
        summary: true,
        controls_multiplier: 0.65
      }
    },
    {
      term: "formula",
      label: "100 × reach × exploitability × controls",
      value: 65.0,
      detail: {
        reach: 1.0,
        controls: 0.65,
        exploitability: 1.0
      }
    },
    {
      term: "floor",
      label: "none",
      value: 0.0,
      detail: {
        fired: {},
        rules: []
      }
    },
    {
      term: "final",
      label: "High",
      value: 65.0,
      detail: {
        floor: 0,
        clamped: false,
        floored: false,
        formula: 65.0
      }
    }
  ],
  escalation_paths: [
    [
      {
        src: "id:emp-0277",
        verb: "grant",
        dst: "p:831fe884-9c17-4363-bc44-cb36d89c568d",
        grant_id: "8eea799b031f8c5629aa3d120af0b622"
      }
    ],
    [
      {
        src: "id:emp-0277",
        verb: "grant",
        dst: "p:84c84c23-676e-34be-78be-c228c455da79",
        grant_id: "8eea799b031f8c5629aa3d120af0b622"
      }
    ]
  ]
};

export const FINDING: FindingOut = {
  finding_key: "007fc6734872bc00c2d94384133e1700",
  scan_id: 12,
  snapshot_month: 12,
  identity_id: "emp-0012",
  display_name: "Latifa Al Ketbi",
  identity_type: "human",
  department: "Data Services",
  clouds: ["aws", "azure", "gcp"],
  rule_id: "R4",
  rule_name: "Cross-cloud superuser",
  severity: "Critical",
  score: 100,
  first_seen_month: 2,
  status: "open",
  evidence_refs: [{ kind: "grant", ref: "grant-emp-0012-04", note: "aws admin" }],
  causal_event_ids: ["evt-02-emp-0012-4"],
  instance_hash: "0xb3aaf52690cb755a76d637ccc9785edb92847019070d333113db82ef2449facd",
  leaf: "0xdbca04995c4ed6e8576d0ef37d87cb95556c5ca006c0d045d0d10699e6502b0d",
  proof: ["0xde469883ee8ddc204446d204b358f1ca97441f06a01e408504adcdab95c29b80"],
  altitudes: {
    headline: "Latifa Al Ketbi (Data Services) is an administrator in all three clouds at once.",
    explanation: "Rule R4 fired at August 2026. This identity can reach 30% of the estate with control verbs.",
    evidence: {
      facts: { rule_id: "R4" },
      rules_fired: ["R4"],
      ledger: { leaf: "0xdbca0499", scan_id: 12, merkle_root: "0x90345860" },
    },
  },
  allowed_actions: ["revoke_grant", "downgrade_to_least_privilege"],
  attack_techniques: ["T1078.004 (verify)"],
  control_refs: ["ISO 27001:2022 A.5.15 (verify)"],
  facts: { rule_id: "R4" },
  plan: null,
  investigation: null,
  exception: null,
};

export const IDENTITY: IdentityDetail = {
  identity_id: "emp-0012",
  display_name: "Latifa Al Ketbi",
  identity_type: "human",
  department: "Data Services",
  employment_type: "staff",
  employment_status: "active",
  hire_month: 1,
  departure_month: null,
  external: false,
  mfa_enforced: false,
  tags: { owner: "latifa.al.ketbi@nda.example" },
  contract_end_month: null,
  first_seen_month: 1,
  last_seen_month: 12,
  clouds: ["aws", "azure", "gcp"],
  score: SCORE,
  severity: "Critical",
  blast_radius_pct: 69.9,
  last_activity_at: "2026-07-24",
  top_finding_key: FINDING.finding_key,
  grants: [GRANT],
  activity: [
    { cloud: "aws", service_category: "identity", snapshot_month: 12, last_activity_at: "2026-07-24", operation_count: 155 },
  ],
  credentials: [],
  findings: [FINDING],
  causal_history: [
    {
      month: 7,
      event_id: "evt-07-emp-0012-3",
      kind: "role_change",
      trigger: "role_change",
      cloud: "gcp",
      description: "GCP admin at org added (role change)",
      grant_delta: {},
    },
  ],
  risk_history: [
    { month: 11, score: 64, severity: "High", events: [] },
    {
      month: 12,
      score: 80,
      severity: "Critical",
      events: [
        {
          month: 12,
          event_id: "evt-12-emp-0012-1",
          kind: "mfa_lapse",
          trigger: "mfa_lapse",
          cloud: "aws",
          description: "MFA flag flipped off",
          grant_delta: {},
        },
      ],
    },
  ],
  exceptions: [],
  altitudes: FINDING.altitudes,
  principals: [
    {
      principal_ref: "aws:user:latifa.al.ketbi",
      cloud: "aws",
      principal_type: "user",
      link_method: "hr_email",
      link_confidence: "exact",
    },
  ],
};

const POLICY_DIFF: PolicyDiffOut = {
  cloud: "aws",
  before: { attached: ["arn:aws:iam::aws:policy/AdministratorAccess"] },
  after: { attached: [] },
  operations: [{ op: "detach_managed_policy", target: "AdministratorAccess", detail: "scope *" }],
  summary: "Remove AdministratorAccess from latifa.al.ketbi",
};

export const PLAN: RemediationPlanOut = {
  plan_id: "plan-0002",
  finding_key: FINDING.finding_key,
  scan_id: 12,
  identity_id: "emp-0012",
  display_name: "Latifa Al Ketbi",
  rule_id: "R4",
  action: "revoke_grant",
  params: { grant_ids: ["grant-emp-0012-04"] },
  policy_diff: POLICY_DIFF,
  keep: ["grant-emp-0012-01"],
  drop: ["grant-emp-0012-04"],
  privilege_reduction_pct: 16.7,
  expected_blast_radius_after: 0.2477,
  proposed_by: "rule",
  proposer_user_id: "usr-approver",
  model_id: null,
  prompt_version: "v1",
  rationale: "Least-privilege diff: drop 1 grant cited by R4; keep read grants used in the last 90 days.",
  confidence: 0.82,
  status: "proposed",
  created_at: "2026-08-31T09:00:00Z",
  decisions: [],
};

export const TIMELINE: TimelineOut = {
  current_month: 3,
  points: [
    {
      month: 1,
      month_label: "September 2025",
      identity_count: 29,
      findings_by_severity: { Low: 0, Medium: 1, High: 1, Critical: 0 },
      median_score: 8.1,
      half_life: { Finance: null, "Data Services": 1 },
    },
    {
      month: 2,
      month_label: "October 2025",
      identity_count: 30,
      findings_by_severity: { Low: 1, Medium: 2, High: 3, Critical: 1 },
      median_score: 12.7,
      half_life: { Finance: null, "Data Services": 1.1 },
    },
    {
      month: 3,
      month_label: "November 2025",
      identity_count: 31,
      findings_by_severity: { Low: 1, Medium: 3, High: 5, Critical: 1 },
      median_score: 13,
      half_life: { Finance: null, "Data Services": 1.3 },
    },
  ],
};

export const HALFLIFE: HalfLifeTable = {
  month: 3,
  rows: [
    // The API's estate-wide aggregate uses the sentinel department `all`.
    { department: "all", trigger: "departure", grants: 80, revocations: 24, half_life_months: 3.5, label: "Healthy" },
    { department: "Finance", trigger: "departure", grants: 30, revocations: 0, half_life_months: null, label: "Broken" },
    { department: "Finance", trigger: "role_change", grants: 30, revocations: 6, half_life_months: 6, label: "Slow" },
    {
      department: "Data Services",
      trigger: "departure",
      grants: 50,
      revocations: 24,
      half_life_months: 1.3,
      label: "Healthy",
    },
  ],
};

export const EVALUATION: EvalOut = {
  seed: 7,
  held_out: true,
  computed: true,
  precision: 0.75,
  recall: 0.973,
  f1: 0.847,
  threshold: "High+",
  tp: 36,
  fp: 12,
  fn: 1,
  per_rule: [{ rule_id: "R4", tp: 2, fp: 2, fn: 0, precision: 0.5, recall: 1 }],
  decoys: [
    {
      identity_id: "emp-0006",
      display_name: "Mariam Al Mazrouei",
      looks_like: ["R1", "R4"],
      why_legitimate: "Break-glass administrator; MFA enforced, monitored, quarterly review",
      flagged_at: null,
      correctly_handled: true,
    },
  ],
  director_sentence: "Of 48 accounts flagged, 36 are verified genuine risks; 12 are known exceptions the system now recognises.",
  engineer_sentence: "precision 0.75 / recall 0.97 / F1 0.85 at High+ on held-out seed 7 (tp 36, fp 12, fn 1)",
  // The API sends an absolute path on its own host; the page must never print it.
  generated_from: "/srv/athar/data/estate/seed-7",
};

/**
 * `GET /estate/summary` as the Overview receives it, trimmed to three
 * departments. Two of them never revoke ("Never"), which is the shape the
 * demo estate actually produces at month 12.
 */
export const SUMMARY: EstateSummary = {
  current_month: 12,
  current_month_label: "August 2026",
  identity_count: 507,
  humans: 400,
  services: 107,
  findings_total: 99,
  findings_by_severity: { Low: 4, Medium: 27, High: 47, Critical: 21 },
  findings_by_cloud: { aws: 70, azure: 47, gcp: 34 },
  findings_by_department: [
    {
      department: "Smart Services",
      identities: 82,
      findings: 17,
      critical: 4,
      high: 6,
      medium: 7,
      low: 0,
      offboarding_half_life: 5,
      half_life_label: "Slow",
    },
    {
      department: "Finance",
      identities: 60,
      findings: 5,
      critical: 1,
      high: 0,
      medium: 1,
      low: 3,
      offboarding_half_life: null,
      half_life_label: "Broken",
    },
    {
      department: "Contractors",
      identities: 36,
      findings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      offboarding_half_life: null,
      half_life_label: "Broken",
    },
  ],
  median_score: 21.4,
  ledger: {
    status: "anchored",
    last_scan_id: 12,
    last_root: "0xc1559c8d30ae2457bd085f348f84d89ca3c07bad3affe2ddd01538e1520fe838",
    last_tx: "0x3cf9e84e642a366be2c6d4e92ef3914803157fb6e45e90610cec77a0ef81341c",
    chain_id: 31337,
  },
  executive_summary: "In August 2026, ATHAR holds 99 open access-governance findings.",
  model_id: "gemini-2.5-flash",
  scan_id: 12,
};
