import { useQuery } from "@tanstack/react-query";
import { getEstateSummary, getLedgerInfo, listLedgerDecisions, listLedgerScans } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import { LedgerStatusBadge } from "../components/LedgerStatusBadge";
import { CommitsTable } from "../components/ledger/CommitsTable";
import { DecisionsTable } from "../components/ledger/DecisionsTable";
import { LEDGER_INFO_ANCHOR, LedgerInfoCard } from "../components/ledger/LedgerInfoCard";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonTable } from "../components/ui/Skeleton";
import { StatTile } from "../components/ui/StatTile";
import { formatInt } from "../lib/format";

const LIST = { limit: 50, offset: 0 } as const;

/**
 * Governance ledger (SPEC §14, §12). Commits, decisions, a Verify per scan that
 * shows both roots — and, in plain words from the API itself, what anchoring
 * does and does not defend against.
 */
export function LedgerPage() {
  const info = useQuery({ queryKey: queryKeys.ledger.info(), queryFn: getLedgerInfo });
  const scans = useQuery({
    queryKey: queryKeys.ledger.scans(),
    queryFn: () => listLedgerScans({ ...LIST, sort: "-scan_id" }),
  });
  const decisions = useQuery({
    queryKey: queryKeys.ledger.decisions(),
    queryFn: () => listLedgerDecisions({ ...LIST, sort: "-created_at" }),
  });
  const summary = useQuery({ queryKey: queryKeys.estate.summary(), queryFn: getEstateSummary });

  const anchored = (scans.data?.items ?? []).filter(
    (scan) => scan.ledger_status === "anchored" || scan.ledger_status === "already_anchored",
  ).length;
  const badge = summary.data?.ledger;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Governance ledger"
        description="Every scan is a Merkle root on chain and every decision carries a proof, so a report can be checked without trusting this dashboard."
        meta={badge && <LedgerStatusBadge status={badge.status} scanId={badge.last_scan_id} linked={false} />}
      />

      {info.isError && <ErrorState error={info.error} onRetry={() => void info.refetch()} />}
      {info.isPending && <Skeleton lines={5} />}
      {info.data && <LedgerInfoCard info={info.data} />}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Anchored scans"
          value={formatInt(anchored)}
          hint="Commits whose root is confirmed on chain"
          onClick={() => document.getElementById("commits")?.scrollIntoView?.({ behavior: "smooth" })}
        />
        <StatTile
          label="Scans committed"
          value={formatInt(scans.data?.total ?? 0)}
          hint="Every scanned month is anchored, not only the latest"
          onClick={() => document.getElementById("commits")?.scrollIntoView?.({ behavior: "smooth" })}
        />
        <StatTile
          label="Decisions recorded"
          value={formatInt(decisions.data?.total ?? 0)}
          hint="Approve, reject, apply, auto-remediate, exception"
          onClick={() => document.getElementById("decisions")?.scrollIntoView?.({ behavior: "smooth" })}
        />
        <StatTile
          label="Chain id"
          value={info.data?.chain_id ?? "—"}
          hint={info.data?.contract_address ? "Local Anvil node in this deployment" : "No contract deployed"}
          onClick={() => document.getElementById(LEDGER_INFO_ANCHOR)?.scrollIntoView?.({ behavior: "smooth" })}
        />
      </div>

      <Card
        id="commits"
        title="Scan commits"
        subtitle="Recompute a root from the database and compare it with getCommit(scanIndex).findingsRoot"
        flush
      >
        <div className="p-3">
          {scans.isError && <ErrorState error={scans.error} onRetry={() => void scans.refetch()} />}
          {scans.isPending && <SkeletonTable rows={6} cols={8} />}
          {scans.data && <CommitsTable scans={scans.data.items} />}
        </div>
      </Card>

      <Card
        id="decisions"
        title="Decisions"
        subtitle="A decision can only reference a finding that was in the committed scan — the contract reverts otherwise"
        flush
      >
        <div className="p-3">
          {decisions.isError && <ErrorState error={decisions.error} onRetry={() => void decisions.refetch()} />}
          {decisions.isPending && <SkeletonTable rows={4} cols={10} />}
          {decisions.data && <DecisionsTable decisions={decisions.data.items} />}
        </div>
      </Card>
    </div>
  );
}
