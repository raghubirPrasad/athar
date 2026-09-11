import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Severity, TimelinePoint } from "../../api/types";
import { SEVERITIES, severityTone } from "../ui/severity";

const FILL: Record<Severity, string> = {
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
};

/** Stacked bars are drawn low-to-high so Critical sits on top of each column. */
const STACK_ORDER: readonly Severity[] = [...SEVERITIES].reverse();

export interface SeverityBarsProps {
  points: readonly TimelinePoint[];
  /** Month the slider is on: its column is drawn at full opacity. */
  selectedMonth: number;
}

/**
 * Findings by severity for every month of the simulation (SPEC §14 timeline).
 * The legend labels carry the severity glyph, so the chart is readable without
 * relying on colour (PRD §8.5).
 */
export function SeverityBars({ points, selectedMonth }: SeverityBarsProps) {
  const data = points.map((point) => ({
    month: point.month,
    label: point.month_label,
    Critical: point.findings_by_severity.Critical ?? 0,
    High: point.findings_by_severity.High ?? 0,
    Medium: point.findings_by_severity.Medium ?? 0,
    Low: point.findings_by_severity.Low ?? 0,
  }));

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fontSize: 11, fill: "var(--fg-muted)" }}
            stroke="var(--border-strong)"
            interval={0}
            angle={-30}
            textAnchor="end"
            height={56}
          />
          <YAxis tick={{ fontSize: 11, fill: "var(--fg-muted)" }} stroke="var(--border-strong)" width={44} />
          <Tooltip
            cursor={{ fill: "var(--surface-muted)" }}
            contentStyle={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              fontSize: 12,
              color: "var(--fg)",
            }}
          />
          <Legend
            formatter={(value: string) => `${severityTone(value).glyph} ${value}`}
            wrapperStyle={{ fontSize: 12 }}
          />
          {STACK_ORDER.map((severity) => (
            <Bar key={severity} dataKey={severity} stackId="findings" fill={FILL[severity]} isAnimationActive={false}>
              {data.map((row) => (
                <Cell
                  key={`${severity}-${row.month}`}
                  fillOpacity={row.month === selectedMonth ? 1 : 0.45}
                  stroke={row.month === selectedMonth ? "var(--fg)" : undefined}
                  strokeWidth={row.month === selectedMonth ? 1 : 0}
                />
              ))}
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
