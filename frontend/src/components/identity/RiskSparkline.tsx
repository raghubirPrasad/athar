import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { RiskPoint } from "../../api/types";
import { formatMonthLabel, formatMonthShort } from "../../lib/format";
import { EmptyState } from "../ui/EmptyState";
import { SeverityBadge } from "../ui/SeverityBadge";
import { riskAnnotations } from "./riskAnnotations";

/**
 * Twelve months of risk for one identity, annotated with the events that moved
 * it (SPEC §9.4). Every month is scanned, so this is measured history rather
 * than an interpolation.
 */
export function RiskSparkline({ points }: { points: readonly RiskPoint[] }) {
  if (points.length === 0) {
    return (
      <EmptyState
        compact
        title="No risk history"
        description="This identity has not been scored in any snapshot, so there is no trend to draw."
      />
    );
  }

  const data = points.map((point) => ({
    month: point.month,
    label: formatMonthShort(point.month),
    score: point.score,
    severity: point.severity,
  }));
  const marks = riskAnnotations(points);
  const annotated = points.filter((point) => (point.events ?? []).length > 0).length;
  const last = points[points.length - 1];
  const first = points[0];

  return (
    <div className="flex flex-col gap-3">
      <div className="h-40 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 11, fill: "var(--fg-muted)" }}
              stroke="var(--border-strong)"
              interval="preserveStartEnd"
            />
            <YAxis
              domain={[0, 100]}
              tick={{ fontSize: 11, fill: "var(--fg-muted)" }}
              stroke="var(--border-strong)"
              width={44}
            />
            <Tooltip
              contentStyle={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                fontSize: 12,
                color: "var(--fg)",
              }}
              labelFormatter={(label: string) => label}
              formatter={(value: number | string) => [String(value), "Risk score"]}
            />
            <Line
              type="monotone"
              dataKey="score"
              stroke="var(--accent)"
              strokeWidth={2}
              dot={{ r: 2, fill: "var(--accent)" }}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
            {marks.map((mark) => (
              <ReferenceDot
                key={`mark-${mark.month}`}
                x={formatMonthShort(mark.month)}
                y={mark.score}
                r={5}
                fill="var(--sev-high)"
                stroke="var(--surface)"
                strokeWidth={1.5}
                isFront
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/*
        One snapshot is not a trend: "moved from 100 to 100" reads as a bug
        rather than as a first month, so a single point says so plainly.
      */}
      {first && last && points.length === 1 && (
        <p className="text-[13px] text-fg-muted">
          First scored at <span className="tabular font-semibold text-fg">{last.score}</span> in{" "}
          {formatMonthLabel(last.month)} — there is no earlier month to compare with.{" "}
          <SeverityBadge severity={last.severity} /> today.
        </p>
      )}

      {first && last && points.length > 1 && (
        <p className="text-[13px] text-fg-muted">
          Risk moved from <span className="tabular font-semibold text-fg">{first.score}</span> in{" "}
          {formatMonthLabel(first.month)} to <span className="tabular font-semibold text-fg">{last.score}</span> in{" "}
          {formatMonthLabel(last.month)}. <SeverityBadge severity={last.severity} /> today.
        </p>
      )}

      {marks.length > 0 && (
        <ol className="flex flex-col gap-2">
          {marks.map((mark) => (
            <li key={`annotation-${mark.month}`} className="text-[13px] leading-5">
              <p>
                <span className="font-semibold text-fg">{formatMonthLabel(mark.month)}</span>{" "}
                <span className="tabular text-fg-muted">
                  risk {mark.score}
                  {mark.moved ? (
                    <span className={mark.delta > 0 ? "text-danger" : "text-ok"}>
                      {" "}
                      ({mark.delta > 0 ? "+" : ""}
                      {mark.delta})
                    </span>
                  ) : (
                    <span className="text-fg-muted"> (unchanged)</span>
                  )}
                </span>
              </p>
              <ul className="mt-0.5 flex flex-col gap-0.5 pl-3.5">
                {mark.descriptions.map((description) => (
                  <li key={description} className="list-disc text-fg-muted marker:text-fg-faint">
                    {description}
                  </li>
                ))}
                {mark.more > 0 && (
                  <li className="list-disc text-fg-muted marker:text-fg-faint">
                    and {mark.more} more {mark.more === 1 ? "change" : "changes"} in this month
                  </li>
                )}
              </ul>
            </li>
          ))}
        </ol>
      )}

      {annotated > marks.length && (
        <p className="text-xs text-fg-muted">
          {annotated - marks.length} further {annotated - marks.length === 1 ? "month" : "months"} had changes that
          did not move the score.
        </p>
      )}
    </div>
  );
}
