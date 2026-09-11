import { cn } from "../../lib/cn";
import { formatScore } from "../../lib/format";
import { severityTone } from "./severity";

export interface ScoreBarProps {
  /** Risk score, 0–100 (SPEC §8.3). */
  value: number;
  /** Severity band the score falls in; drives the fill tone. */
  severity?: string | null;
  className?: string;
}

/**
 * Score meter. The number is always printed next to the bar — the bar is the
 * redundant channel, never the only one (PRD §8.5).
 */
export function ScoreBar({ value, severity, className }: ScoreBarProps) {
  const tone = severityTone(severity);
  const pct = Math.max(0, Math.min(100, value));
  return (
    <span className={cn("flex items-center gap-2", className)}>
      <span
        role="meter"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Risk score"
        className="h-2 w-16 shrink-0 overflow-hidden rounded-sm bg-surface-muted"
      >
        <span className={cn("block h-full rounded-sm", tone.barClassName)} style={{ width: `${pct}%` }} />
      </span>
      <span className="tabular w-7 text-right text-[13px] font-semibold text-fg">{formatScore(value)}</span>
    </span>
  );
}
