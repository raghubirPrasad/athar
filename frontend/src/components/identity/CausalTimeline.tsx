import { useState } from "react";
import type { CausalStepOut } from "../../api/types";
import { formatMonthLabel } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { CloudIcon } from "../ui/CloudIcon";
import { EmptyState } from "../ui/EmptyState";

const KIND_LABEL: Record<string, string> = {
  hire: "Hired",
  role_change: "Role change",
  departure: "Departure",
  grant: "Grant added",
  revoke: "Grant removed",
  project_launch: "Project launched",
  project_retirement: "Project retired",
  incident_response: "Incident response",
  region_drift: "Region drift",
  mfa_lapse: "MFA lapse",
  activity_stop: "Activity stopped",
  remediation: "Remediation applied",
};

function stepLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind.replace(/_/g, " ");
}

/** Most recent events drawn before the reader asks for the whole history. */
const DEFAULT_MAX = 8;

export interface CausalTimelineProps {
  steps: readonly CausalStepOut[];
  /** Events drawn before the "show full history" control appears. */
  max?: number;
}

/**
 * The finding's birth certificate (SPEC §9.2): the ordered events that produced
 * the rows the rule cited, so "since when" has an answer with an event id on it.
 * A busy identity can carry a hundred of them, so the tail is drawn on request
 * rather than by default.
 */
export function CausalTimeline({ steps, max = DEFAULT_MAX }: CausalTimelineProps) {
  const [expanded, setExpanded] = useState(false);

  if (steps.length === 0) {
    return (
      <EmptyState
        compact
        title="No causal history"
        description="No snapshot diff produced an event for this identity in the window that was ingested."
      />
    );
  }

  const shown = expanded ? steps : steps.slice(0, Math.max(1, max));
  const hidden = steps.length - shown.length;

  return (
    <>
      <ol className="flex flex-col">
        {shown.map((step, index) => (
          <li key={step.event_id} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span
                aria-hidden="true"
                className="mt-1.5 h-2 w-2 shrink-0 rounded-full border border-accent bg-accent-soft"
              />
              {index < shown.length - 1 && <span aria-hidden="true" className="w-px flex-1 bg-border" />}
            </div>
            <div className="min-w-0 pb-3">
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-[13px] font-semibold text-fg">{formatMonthLabel(step.month)}</span>
                <Badge tone="neutral">{stepLabel(step.kind)}</Badge>
                {step.cloud && <CloudIcon cloud={step.cloud} size={14} />}
              </p>
              <p className="mt-0.5 text-[13px] leading-5 text-fg-muted">{step.description}</p>
              <p className="mt-0.5 font-mono text-[11.5px] text-fg-faint">
                {step.event_id}
                {step.trigger && step.trigger !== "unknown" ? ` · trigger ${step.trigger}` : ""}
              </p>
            </div>
          </li>
        ))}
      </ol>
      {(hidden > 0 || expanded) && (
        <Button size="sm" variant="ghost" onClick={() => setExpanded(!expanded)}>
          {expanded ? `Show the ${Math.max(1, max)} most recent only` : `Show full history (${steps.length} events)`}
        </Button>
      )}
    </>
  );
}
