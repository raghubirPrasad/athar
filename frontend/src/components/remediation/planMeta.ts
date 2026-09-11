import type { LedgerDecisionKind, PlanAction, PlanStatus, RemediationPlanOut } from "../../api/types";
import type { BadgeTone } from "../ui/Badge";

/** `allowed_actions` vocabulary (SPEC §11.4), in readable English. */
export const ACTION_LABEL: Record<PlanAction, string> = {
  revoke_grant: "Revoke grant",
  downgrade_to_least_privilege: "Downgrade to least privilege",
  disable_identity: "Disable identity",
  rotate_or_disable_credential: "Rotate or disable credential",
  remove_cloud_access: "Remove cloud access",
  tag_as_exception: "Record an exception",
  no_action_recommended: "No action recommended",
};

export function actionLabel(action: string): string {
  return ACTION_LABEL[action as PlanAction] ?? action;
}

interface StatusLook {
  label: string;
  tone: BadgeTone;
  glyph: string;
}

/** Plan lifecycle (SPEC §11.5). Tone is never the only signal — glyph and word too. */
export const PLAN_STATUS: Record<PlanStatus, StatusLook> = {
  proposed: { label: "Proposed", tone: "warn", glyph: "◷" },
  approved: { label: "Approved", tone: "accent", glyph: "✓" },
  rejected: { label: "Rejected", tone: "danger", glyph: "✕" },
  applied: { label: "Applied", tone: "ok", glyph: "★" },
};

export function planStatusLook(status: string): StatusLook {
  return PLAN_STATUS[status as PlanStatus] ?? { label: status, tone: "neutral", glyph: "•" };
}

/** Decision kinds recorded on chain (SPEC §12.2: 1 approved … 5 exception_granted). */
export const DECISION_LABEL: Record<LedgerDecisionKind, string> = {
  approved: "Approved",
  rejected: "Rejected",
  auto_remediated: "Auto-remediated",
  remediation_applied: "Applied",
  exception_granted: "Exception granted",
};

export function decisionLabel(decision: string): string {
  return DECISION_LABEL[decision as LedgerDecisionKind] ?? decision;
}

export function decisionTone(decision: string): BadgeTone {
  switch (decision) {
    case "approved":
      return "accent";
    case "rejected":
      return "danger";
    case "remediation_applied":
      return "ok";
    case "auto_remediated":
      return "warn";
    default:
      return "neutral";
  }
}

/** Counts per plan status, for the queue tabs. */
export function countByStatus(plans: readonly RemediationPlanOut[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const plan of plans) counts[plan.status] = (counts[plan.status] ?? 0) + 1;
  return counts;
}
