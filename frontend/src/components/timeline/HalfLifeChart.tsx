import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TimelinePoint } from "../../api/types";

/** Eight readable hues, each with its own dash pattern so colour is not the only cue. */
const SERIES_STYLE: readonly { stroke: string; dash: string }[] = [
  { stroke: "#14b8a6", dash: "0" },
  { stroke: "#f59e0b", dash: "5 3" },
  { stroke: "#3b82f6", dash: "2 2" },
  { stroke: "#a78bfa", dash: "8 3" },
  { stroke: "#22c55e", dash: "4 2 1 2" },
  { stroke: "#ef4444", dash: "6 2" },
  { stroke: "#eab308", dash: "1 3" },
  { stroke: "#06b6d4", dash: "10 4" },
];

function departmentsIn(points: readonly TimelinePoint[]): string[] {
  const names = new Set<string>();
  for (const point of points) {
    for (const name of Object.keys(point.half_life)) names.add(name);
  }
  return [...names].sort();
}

export interface HalfLifeChartProps {
  points: readonly TimelinePoint[];
  /** Department the page was opened for: its line is drawn forward, the rest recede. */
  selected?: string | null;
}

/**
 * Permission Half-Life per department over the window (SPEC §9.3). A gap in a
 * line is the interesting case: fewer than one revocation per ten grants, which
 * the engine reports as "Never".
 */
export function HalfLifeChart({ points, selected = null }: HalfLifeChartProps) {
  const departments = departmentsIn(points);
  const emphasised = selected != null && departments.includes(selected);
  const data = points.map((point) => {
    const row: Record<string, number | string | null> = { label: point.month_label, month: point.month };
    for (const department of departments) row[department] = point.half_life[department] ?? null;
    return row;
  });

  return (
    <div className="flex flex-col gap-2">
      <div className="h-64 w-full">
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
              tick={{ fontSize: 11, fill: "var(--fg-muted)" }}
              stroke="var(--border-strong)"
              width={44}
              label={undefined}
            />
            <Tooltip
              contentStyle={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                fontSize: 12,
                color: "var(--fg)",
              }}
              formatter={(value: number | string) => [`${value} months`, ""]}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            {departments.map((department, index) => {
              const style = SERIES_STYLE[index % SERIES_STYLE.length];
              const isSelected = emphasised && department === selected;
              return (
                <Line
                  key={department}
                  type="monotone"
                  dataKey={department}
                  stroke={style?.stroke}
                  strokeDasharray={style?.dash}
                  // Width and dots, not hue, carry the emphasis: the selected
                  // line is readable in greyscale too (PRD §8.5).
                  strokeWidth={isSelected ? 3.5 : 2}
                  strokeOpacity={emphasised && !isSelected ? 0.25 : 1}
                  dot={isSelected ? { r: 2.5 } : false}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              );
            })}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <p className="text-xs text-fg-muted">
        The median number of months a revoked grant survived before it was revoked. A missing line means the engine
        reports <span className="font-semibold text-fg">Never</span>: fewer than one revocation per ten grants, so
        there is no meaningful median to take. Offboarding — the headline number on the Overview — is one trigger
        within this, broken out in the table below.
      </p>
    </div>
  );
}
