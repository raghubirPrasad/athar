import type { CausalStepOut, RiskPoint } from "../../api/types";

export interface RiskAnnotation {
  month: number;
  score: number;
  /** Change from the previous scored month. */
  delta: number;
  /** True when the score actually moved in this month. */
  moved: boolean;
  /** The most significant distinct changes, capped (SPEC §9.4). */
  descriptions: string[];
  /** Events in the month that are not listed above. */
  more: number;
  /** Events the diff produced for this month, listed or not. */
  eventCount: number;
}

export interface RiskAnnotationOptions {
  /** Changes listed per month before the rest become "and N more". */
  maxPerMonth?: number;
  /** Months annotated; months where the score moved are kept first. */
  maxMonths?: number;
}

/** How much a kind of event tends to matter, before the grants it moved. */
const KIND_WEIGHT: Record<string, number> = {
  departure: 6,
  mfa_lapse: 6,
  role_change: 5,
  incident_response: 4,
  grant: 4,
  project_launch: 3,
  region_drift: 3,
  activity_stop: 3,
  revoke: 2,
  remediation: 2,
  project_retirement: 2,
  hire: 1,
};

/** Control verbs first: an added `admin` says more than an added `read`. */
const VERB_WEIGHT: Record<string, number> = {
  admin: 6,
  grant: 5,
  delete: 4,
  write: 3,
  billing: 2,
  read: 1,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** The heaviest verb in the event's own grant delta, 0 when it carries none. */
function verbWeight(delta: CausalStepOut["grant_delta"]): number {
  let heaviest = 0;
  for (const key of ["added", "removed"] as const) {
    const rows: unknown = delta?.[key];
    if (!Array.isArray(rows)) continue;
    for (const row of rows as readonly unknown[]) {
      if (!isRecord(row)) continue;
      const verb = row["verb"];
      if (typeof verb === "string") heaviest = Math.max(heaviest, VERB_WEIGHT[verb] ?? 0);
    }
  }
  return heaviest;
}

function significance(event: CausalStepOut): number {
  return (KIND_WEIGHT[event.kind] ?? 2) * 10 + verbWeight(event.grant_delta);
}

/** Distinct descriptions, heaviest first; ties keep the order the diff emitted. */
function rank(events: readonly CausalStepOut[]): string[] {
  const best = new Map<string, number>();
  const order = new Map<string, number>();
  events.forEach((event, index) => {
    const text = event.description.trim();
    if (text.length === 0) return;
    const weight = significance(event);
    if (!best.has(text) || weight > (best.get(text) ?? 0)) best.set(text, weight);
    if (!order.has(text)) order.set(text, index);
  });
  return [...best.entries()]
    .sort((a, b) => b[1] - a[1] || (order.get(a[0]) ?? 0) - (order.get(b[0]) ?? 0))
    .map(([text]) => text);
}

/**
 * Months where events moved — or could have moved — the score, with the few
 * changes that mattered most (SPEC §9.4). An identity can collect seventy grant
 * events in one month; the annotation names the heaviest two or three and counts
 * the rest, because a paragraph of every description is not a reading of the
 * history. Months where the score actually changed are kept ahead of months
 * where it did not.
 */
export function riskAnnotations(
  points: readonly RiskPoint[],
  { maxPerMonth = 3, maxMonths = 6 }: RiskAnnotationOptions = {},
): RiskAnnotation[] {
  const all: RiskAnnotation[] = [];
  points.forEach((point, index) => {
    const events = point.events ?? [];
    if (events.length === 0) return;
    const previous = points[index - 1]?.score ?? point.score;
    const delta = point.score - previous;
    const distinct = rank(events);
    const descriptions = distinct.slice(0, Math.max(1, maxPerMonth));
    all.push({
      month: point.month,
      score: point.score,
      delta,
      moved: delta !== 0,
      descriptions,
      more: Math.max(0, events.length - descriptions.length),
      eventCount: events.length,
    });
  });

  if (all.length <= maxMonths) return all;
  const kept = [...all]
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || b.month - a.month)
    .slice(0, maxMonths);
  const keptMonths = new Set(kept.map((annotation) => annotation.month));
  return all.filter((annotation) => keptMonths.has(annotation.month));
}
