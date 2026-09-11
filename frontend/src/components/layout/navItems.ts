import type { ComponentType, SVGProps } from "react";
import {
  IconEvaluation,
  IconFindings,
  IconIdentities,
  IconLedger,
  IconOverview,
  IconRemediation,
  IconSettings,
  IconTimeline,
} from "../icons";

export interface NavItem {
  to: string;
  label: string;
  /** Shown as the title attribute when the rail is collapsed to icons. */
  hint: string;
  icon: ComponentType<SVGProps<SVGSVGElement> & { size?: number }>;
  /** Match the path exactly (only the Overview route needs this). */
  end?: boolean;
}

/** Routes of SPEC §14, in the order the demo walks them. */
export const NAV_ITEMS: readonly NavItem[] = [
  { to: "/", label: "Overview", hint: "Department rollup and the organisational finding", icon: IconOverview, end: true },
  { to: "/identities", label: "Identities", hint: "Every identity, ranked by risk score", icon: IconIdentities },
  { to: "/findings", label: "Findings", hint: "All findings with filters and export", icon: IconFindings },
  { to: "/remediation", label: "Remediation", hint: "Proposed plans awaiting approval", icon: IconRemediation },
  { to: "/ledger", label: "Ledger", hint: "Anchored scans and decisions", icon: IconLedger },
  { to: "/timeline", label: "Timeline", hint: "Twelve months of drift", icon: IconTimeline },
  { to: "/evaluation", label: "Evaluation", hint: "Precision and recall against ground truth", icon: IconEvaluation },
  { to: "/settings", label: "Settings", hint: "Thresholds, regions, auto-remediation", icon: IconSettings },
];
