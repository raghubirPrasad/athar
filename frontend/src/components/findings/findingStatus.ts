import type { FindingStatus } from "../../api/types";
import type { BadgeTone } from "../ui/Badge";

interface StatusLook {
  label: string;
  tone: BadgeTone;
  glyph: string;
}

/** Finding lifecycle (SPEC §10.3). Word and glyph carry the meaning, not colour. */
export const FINDING_STATUS: Record<FindingStatus, StatusLook> = {
  open: { label: "Open", tone: "danger", glyph: "•" },
  investigated: { label: "Investigated", tone: "warn", glyph: "◑" },
  remediation_proposed: { label: "Plan proposed", tone: "warn", glyph: "◷" },
  approved: { label: "Approved", tone: "accent", glyph: "✓" },
  remediated: { label: "Remediated", tone: "ok", glyph: "★" },
  rejected: { label: "Plan rejected", tone: "neutral", glyph: "↺" },
  exception_granted: { label: "Exception granted", tone: "ok", glyph: "⌾" },
};

export const FINDING_STATUSES = Object.keys(FINDING_STATUS) as FindingStatus[];

export function findingStatusLook(status: string): StatusLook {
  return FINDING_STATUS[status as FindingStatus] ?? { label: status, tone: "neutral", glyph: "•" };
}
