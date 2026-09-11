import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getEstateSummary } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import { LedgerStatusBadge } from "../components/LedgerStatusBadge";
import { DepartmentCard } from "../components/overview/DepartmentCard";
import { ScanActions } from "../components/overview/ScanActions";
import { SeverityHistogram } from "../components/overview/SeverityHistogram";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { CloudIcon } from "../components/ui/CloudIcon";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonTiles } from "../components/ui/Skeleton";
import { StatTile } from "../components/ui/StatTile";
import { formatInt, formatScore } from "../lib/format";

/**
 * Landing page (SPEC §14, PRD §8.1): land on the organisational finding, not on
 * 500 rows. Department rollup, severity histogram, ledger badge, the executive
 * paragraph, and the two analyst actions that drive the demo.
 */
export function OverviewPage() {
  const summary = useQuery({ queryKey: queryKeys.estate.summary(), queryFn: getEstateSummary });
  const data = summary.data;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Overview"
        description="Access governance across AWS, Azure and GCP."
        meta={
          data && (
            <>
              <LedgerStatusBadge status={data.ledger.status} scanId={data.ledger.last_scan_id} />
              {Object.entries(data.findings_by_cloud).map(([cloud, count]) => (
                <Link
                  key={cloud}
                  to={`/findings?cloud=${encodeURIComponent(cloud)}`}
                  aria-label={`${formatInt(count)} findings on ${cloud}`}
                  className="rounded-sm hover:opacity-80 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                >
                  <Badge icon={<CloudIcon cloud={cloud} size={13} />} title={`${cloud} findings`}>
                    {formatInt(count)}
                  </Badge>
                </Link>
              ))}
            </>
          )
        }
        actions={<ScanActions />}
      />

      {summary.isError && <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />}

      {summary.isPending && (
        <>
          <SkeletonTiles />
          <Skeleton lines={4} />
        </>
      )}

      {data && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Identities"
              value={formatInt(data.identity_count)}
              hint={`${formatInt(data.humans)} people · ${formatInt(data.services)} service accounts`}
              to="/identities"
            />
            <StatTile
              label="Open findings"
              value={formatInt(data.findings_total)}
              hint="All rules, current scan"
              to="/findings"
            />
            <StatTile
              label="Critical"
              value={formatInt(data.findings_by_severity.Critical ?? 0)}
              hint="Act this week"
              tone="danger"
              to="/findings?severity=Critical"
            />
            <StatTile
              label="Median risk score"
              value={formatScore(data.median_score)}
              hint="0–100, blast-radius weighted"
              to="/identities"
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <Card
              title="Departments"
              subtitle="Findings and how long a permission survives after it stops being needed"
            >
              <div className="grid gap-3 sm:grid-cols-2">
                {data.findings_by_department.map((row) => (
                  <DepartmentCard key={row.department} row={row} />
                ))}
              </div>
            </Card>

            <div className="flex flex-col gap-4">
              <Card title="Findings by severity" subtitle="Click a level for the rows behind it">
                <SeverityHistogram counts={data.findings_by_severity} />
              </Card>

              <Card title="Executive summary">
                <p className="text-[13px] leading-6 text-fg">
                  {data.executive_summary ?? "No executive summary has been generated for this scan yet."}
                </p>
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
