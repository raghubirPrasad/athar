import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { getHalfLife, getTimeline } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import { HalfLifeChart } from "../components/timeline/HalfLifeChart";
import { HalfLifeTableView } from "../components/timeline/HalfLifeTableView";
import { MonthSlider } from "../components/timeline/MonthSlider";
import { SeverityBars } from "../components/timeline/SeverityBars";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonTiles } from "../components/ui/Skeleton";
import { StatTile } from "../components/ui/StatTile";
import { SEVERITIES } from "../components/ui/severity";
import { formatHalfLife, formatInt, formatMonthLabel, formatScore } from "../lib/format";

/** Anchor the half-life numbers elsewhere in the app link to. */
const HALF_LIFE_ANCHOR = "half-life";

/**
 * Twelve months of drift (SPEC §14 timeline, §9). Time is the primary axis: the
 * estate was simulated month by month and allowed to rot, so the shape of these
 * charts is a result, not a design (PRD §9).
 *
 * This page is also where every half-life number in the app lands: arriving with
 * `?department=Finance` narrows the table to Finance's grants and revocations
 * and draws its line forward in the chart (PRD §8.2).
 */
export function TimelinePage() {
  const [params, setParams] = useSearchParams();

  const timeline = useQuery({ queryKey: queryKeys.timeline.series(), queryFn: getTimeline });
  const halflife = useQuery({ queryKey: queryKeys.departments.halflife(), queryFn: getHalfLife });

  const points = useMemo(() => timeline.data?.points ?? [], [timeline.data]);
  const first = points[0]?.month ?? 1;
  const last = points[points.length - 1]?.month ?? timeline.data?.current_month ?? 1;

  const requested = Number(params.get("month") ?? "");
  const month = Number.isFinite(requested) && requested >= first && requested <= last ? Math.floor(requested) : last;
  const department = params.get("department") || null;

  const setMonth = useCallback(
    (next: number) => {
      const updated = new URLSearchParams(params);
      updated.set("month", String(next));
      setParams(updated, { replace: true });
    },
    [params, setParams],
  );

  const setDepartment = useCallback(
    (next: string | null) => {
      const updated = new URLSearchParams(params);
      if (next) updated.set("department", next);
      else updated.delete("department");
      setParams(updated, { replace: true });
    },
    [params, setParams],
  );

  // Landing here from a half-life number elsewhere should land *on* the
  // half-life, not at the top of a page of charts. Once only, and only after
  // the card exists: changing department from inside the card must not jump.
  const scrollPending = useRef(department !== null);
  useEffect(() => {
    if (!scrollPending.current || points.length === 0) return;
    scrollPending.current = false;
    document.getElementById(HALF_LIFE_ANCHOR)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, [points.length]);

  const point = points.find((p) => p.month === month);
  const findingsTotal = point
    ? SEVERITIES.reduce((sum, severity) => sum + (point.findings_by_severity[severity] ?? 0), 0)
    : 0;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Timeline"
        description="How the estate became over-privileged: a year of hires, role changes, departures and incident response, replayed."
      />

      {timeline.isError && <ErrorState error={timeline.error} onRetry={() => void timeline.refetch()} />}
      {timeline.isPending && (
        <>
          <Skeleton lines={2} height="h-8" />
          <SkeletonTiles />
        </>
      )}

      {points.length > 0 && (
        <>
          <MonthSlider min={first} max={last} value={month} onChange={setMonth} />

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Identities"
              value={formatInt(point?.identity_count ?? 0)}
              hint={`In the estate in ${formatMonthLabel(month)}`}
              to="/identities"
            />
            <StatTile
              label="Findings"
              value={formatInt(findingsTotal)}
              hint="All severities in this month"
              to={`/findings?month=${month}`}
            />
            <StatTile
              label="Critical"
              value={formatInt(point?.findings_by_severity.Critical ?? 0)}
              hint="Highest band in this month"
              tone="danger"
              to={`/findings?month=${month}&severity=Critical`}
            />
            <StatTile
              label="Median risk score"
              value={formatScore(point?.median_score ?? 0)}
              hint="Across every scored identity"
              to="/identities"
            />
          </div>

          <Card
            title="Findings by severity, month by month"
            subtitle={`Column highlighted: ${formatMonthLabel(month)}`}
          >
            <SeverityBars points={points} selectedMonth={month} />
          </Card>

          <Card
            id={HALF_LIFE_ANCHOR}
            title="Permission half-life by department"
            // Across every trigger, unlike the Overview card, which is
            // offboarding alone — the two differ, so both say which they are.
            subtitle="Across every trigger: the median months a revoked grant survived, or Never when under a tenth are ever revoked"
            actions={
              department && (
                <Button size="sm" variant="ghost" onClick={() => setDepartment(null)}>
                  Showing {department} — show all departments
                </Button>
              )
            }
          >
            <HalfLifeChart points={points} selected={department} />
            <div className="mt-3">
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
                {formatMonthLabel(month)} · every trigger
              </h3>
              <ul className="grid gap-1 sm:grid-cols-2 lg:grid-cols-4">
                {Object.entries(point?.half_life ?? {}).map(([name, months]) => (
                  <li key={name}>
                    <Link
                      to={`/timeline?month=${month}&department=${encodeURIComponent(name)}`}
                      replace
                      aria-current={name === department ? "true" : undefined}
                      className={`flex items-baseline justify-between gap-2 rounded border px-2 py-1 text-[13px] hover:border-accent ${
                        name === department ? "border-accent bg-accent-soft/50" : "border-border"
                      }`}
                    >
                      <span className="truncate text-fg-muted">{name}</span>
                      <span className="tabular font-semibold text-fg">{formatHalfLife(months, true)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </Card>
        </>
      )}

      <Card
        title="Half-life today, with the engine's diagnosis"
        subtitle={
          department
            ? `${department}, with the estate-wide baseline for comparison`
            : "Offboarding is the headline number — a broken process, not twelve risky people"
        }
        flush
      >
        <div className="p-3">
          {halflife.isError && <ErrorState error={halflife.error} onRetry={() => void halflife.refetch()} />}
          {halflife.isPending && <Skeleton lines={5} />}
          {halflife.data && <HalfLifeTableView rows={halflife.data.rows} selected={department} />}
        </div>
      </Card>
    </div>
  );
}
