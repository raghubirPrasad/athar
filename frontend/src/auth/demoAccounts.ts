import type { Role } from "./roles";

/**
 * Seeded demo users (SPEC §15.1). Emails only — passwords live in .env and are
 * printed by `make demo`; they are never embedded in the frontend.
 */
export interface DemoAccount {
  email: string;
  role: Role;
  blurb: string;
}

export const DEMO_ACCOUNTS: readonly DemoAccount[] = [
  { email: "analyst@athar.local", role: "analyst", blurb: "runs scans, uploads, agents" },
  { email: "approver@athar.local", role: "approver", blurb: "approves and applies remediation" },
  { email: "judge@athar.local", role: "viewer", blurb: "read-only evidence view" },
];
