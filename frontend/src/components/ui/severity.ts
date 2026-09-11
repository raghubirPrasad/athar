import type { Severity } from "../../api/types";

export type { Severity };

/** Highest first — the order every severity list in the UI uses. */
export const SEVERITIES: readonly Severity[] = ["Critical", "High", "Medium", "Low"];

export interface SeverityTone {
  severity: Severity | "Unknown";
  label: string;
  /** Distinct shape per level so colour is never the only signal (PRD §8.5). */
  glyph: string;
  rank: number; // Critical 3 … Low 0, Unknown -1
  /** Badge chrome: background + text + border. */
  className: string;
  /** Text colour alone, for a glyph or a line item label. */
  textClassName: string;
  /** Solid fill, for a bar or a score meter. */
  barClassName: string;
}

const TONES: Record<Severity | "Unknown", SeverityTone> = {
  Critical: { severity: "Critical", label: "Critical", glyph: "◆", rank: 3, className: "bg-sev-critical-soft text-sev-critical border-sev-critical/40", textClassName: "text-sev-critical", barClassName: "bg-sev-critical" },
  High: { severity: "High", label: "High", glyph: "▲", rank: 2, className: "bg-sev-high-soft text-sev-high border-sev-high/40", textClassName: "text-sev-high", barClassName: "bg-sev-high" },
  Medium: { severity: "Medium", label: "Medium", glyph: "■", rank: 1, className: "bg-sev-medium-soft text-sev-medium border-sev-medium/40", textClassName: "text-sev-medium", barClassName: "bg-sev-medium" },
  Low: { severity: "Low", label: "Low", glyph: "●", rank: 0, className: "bg-sev-low-soft text-sev-low border-sev-low/40", textClassName: "text-sev-low", barClassName: "bg-sev-low" },
  Unknown: { severity: "Unknown", label: "Unknown", glyph: "○", rank: -1, className: "bg-surface-muted text-fg-muted border-border", textClassName: "text-fg-muted", barClassName: "bg-fg-faint" },
};

/** Case-insensitive lookup; anything unexpected renders as "Unknown" rather than throwing. */
export function severityTone(input: string | null | undefined): SeverityTone {
  if (!input) return TONES.Unknown;
  const key = input.charAt(0).toUpperCase() + input.slice(1).toLowerCase();
  return (SEVERITIES as readonly string[]).includes(key) ? TONES[key as Severity] : TONES.Unknown;
}
