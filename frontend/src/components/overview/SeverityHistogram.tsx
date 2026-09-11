import { Link } from "react-router-dom";
import type { Severity } from "../../api/types";
import { formatInt } from "../../lib/format";
import { severityTone } from "../ui/severity";

const ORDER: readonly Severity[] = ["Critical", "High", "Medium", "Low"];

export interface SeverityHistogramProps {
  /** `findings_by_severity` from the estate summary. */
  counts: Record<string, number>;
  /** Route each bar links to, with `?severity=` appended. */
  basePath?: string;
}

/**
 * Findings by severity. The bar is redundant: the level word, the glyph and the
 * count are all present, so the chart is readable without colour (PRD §8.5).
 */
export function SeverityHistogram({ counts, basePath = "/findings" }: SeverityHistogramProps) {
  const max = Math.max(1, ...ORDER.map((s) => counts[s] ?? 0));
  return (
    <ul className="flex flex-col gap-1.5">
      {ORDER.map((severity) => {
        const tone = severityTone(severity);
        const count = counts[severity] ?? 0;
        return (
          <li key={severity}>
            <Link
              to={`${basePath}?severity=${severity}`}
              className="group flex items-center gap-2 rounded px-1 py-0.5 hover:bg-surface-muted"
            >
              <span className="flex w-24 shrink-0 items-center gap-1.5 text-[13px] font-medium text-fg">
                <span aria-hidden="true" className={tone.textClassName}>
                  {tone.glyph}
                </span>
                {tone.label}
              </span>
              <span className="h-3 flex-1 overflow-hidden rounded-sm bg-surface-muted" aria-hidden="true">
                <span
                  className={`block h-full rounded-sm ${tone.barClassName}`}
                  style={{ width: `${Math.round((count / max) * 100)}%` }}
                />
              </span>
              <span className="tabular w-10 shrink-0 text-right text-[13px] font-semibold text-fg">
                {formatInt(count)}
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
