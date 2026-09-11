import type { Altitude } from "../api/types";

/**
 * The three altitudes of SPEC §10.2, in order. The reader chooses one and the
 * whole drill-down renders at that depth: a director never scrolls past a
 * sentence, an engineer never has to ask for the raw snippet.
 */
export const ALTITUDES: readonly Altitude[] = ["headline", "explanation", "evidence"];

export const ALTITUDE_LABEL: Record<Altitude, string> = {
  headline: "Headline",
  explanation: "Explanation",
  evidence: "Evidence",
};

/** Who each altitude is written for (shown as the toggle's tooltip). */
export const ALTITUDE_HINT: Record<Altitude, string> = {
  headline: "One sentence per finding — for a director or auditor",
  explanation: "Why it fired, since when, and what changes if we act — for a risk officer",
  evidence: "Raw provider snippets, score line items, escalation chain and the ledger leaf — for an engineer",
};

/** A distinct glyph per altitude so the selected segment is not colour alone. */
export const ALTITUDE_GLYPH: Record<Altitude, string> = {
  headline: "▁",
  explanation: "▄",
  evidence: "█",
};

export function isAltitude(value: unknown): value is Altitude {
  return typeof value === "string" && (ALTITUDES as readonly string[]).includes(value);
}

/** Altitude from a URL search param; anything unexpected falls back to headline. */
export function readAltitude(params: URLSearchParams, key = "altitude"): Altitude {
  const value = params.get(key);
  return isAltitude(value) ? value : "headline";
}

/** True when `current` is at or below `min` in depth (headline < explanation < evidence). */
export function atLeast(current: Altitude, min: Altitude): boolean {
  return ALTITUDES.indexOf(current) >= ALTITUDES.indexOf(min);
}
