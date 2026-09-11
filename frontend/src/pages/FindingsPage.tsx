import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { getEstateSummary, getFinding, listFindings } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { Altitude } from "../api/types";
import { ExportButtons } from "../components/findings/ExportButtons";
import { FindingDetailModal } from "../components/findings/FindingDetailModal";
import { FindingFilters } from "../components/findings/FindingFilters";
import { FindingTable } from "../components/findings/FindingTable";
import {
  readFindingFilters,
  toFindingListQuery,
  toFindingQuery,
  writeFindingFilters,
  type FindingFilterState,
} from "../components/findings/filters";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Pagination } from "../components/ui/Pagination";
import { SkeletonTable } from "../components/ui/Skeleton";
import { readAltitude } from "../lib/altitude";
import { formatInt } from "../lib/format";

/**
 * Findings list (SPEC §14): one row per finding rather than per identity, the
 * same filter vocabulary as the identity table, and the exports a judge is asked
 * to open (SPEC §16). Filters, the open row and the altitude all live in the URL.
 */
export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readFindingFilters(params), [params]);
  const altitude = readAltitude(params);

  const update = useCallback(
    (patch: Partial<FindingFilterState>) => {
      const next = writeFindingFilters({ ...readFindingFilters(params), ...patch });
      const current = params.get("altitude");
      if (current) next.set("altitude", current);
      setParams(next, { replace: true });
    },
    [params, setParams],
  );

  const setAltitude = useCallback(
    (next: Altitude) => {
      const updated = new URLSearchParams(params);
      if (next === "headline") updated.delete("altitude");
      else updated.set("altitude", next);
      setParams(updated, { replace: true });
    },
    [params, setParams],
  );

  const listQuery = toFindingListQuery(filters);
  const findings = useQuery({
    queryKey: queryKeys.findings.list(listQuery),
    queryFn: () => listFindings(listQuery),
    placeholderData: keepPreviousData,
  });

  const summary = useQuery({ queryKey: queryKeys.estate.summary(), queryFn: getEstateSummary });
  const departments = useMemo(
    () => (summary.data?.findings_by_department ?? []).map((row) => row.department),
    [summary.data],
  );

  const page = findings.data;
  const inPage = page?.items.find((finding) => finding.finding_key === filters.open) ?? null;

  // `?open=` is a shareable deep link — the ledger's decision rows and any
  // pasted URL use it — so a key that is not on the page currently loaded is
  // fetched on its own rather than silently opening nothing.
  const opened = useQuery({
    queryKey: queryKeys.findings.detail(filters.open),
    queryFn: () => getFinding(filters.open),
    enabled: filters.open.length > 0 && inPage === null,
  });
  const open = inPage ?? opened.data ?? null;

  return (
    <div className="flex flex-col gap-3">
      <PageHeader
        title="Findings"
        description="Every finding the rule engine produced, with the rows it cited. Select one for its evidence."
        meta={page && <span className="text-xs text-fg-muted">{formatInt(page.total)} matching findings</span>}
        actions={<ExportButtons query={toFindingQuery(filters)} />}
      />

      <FindingFilters
        value={filters}
        onChange={update}
        departments={departments}
        currentMonth={summary.data?.current_month ?? 12}
      />

      {findings.isError && <ErrorState error={findings.error} onRetry={() => void findings.refetch()} />}

      {opened.isError && (
        <ErrorState
          error={opened.error}
          action={
            <Button size="sm" variant="ghost" onClick={() => update({ open: "" })}>
              Clear the link
            </Button>
          }
        />
      )}

      {findings.isPending && <SkeletonTable rows={10} cols={9} />}

      {page && page.items.length === 0 && (
        <EmptyState
          title="No findings match these filters"
          description="Widen the cloud, rule or severity filter, or clear the name search."
        />
      )}

      {page && page.items.length > 0 && (
        <>
          <FindingTable
            rows={page.items}
            sort={filters.sort}
            openKey={filters.open || undefined}
            onSortChange={(sort) => update({ sort, offset: 0 })}
            onOpen={(findingKey) => update({ open: findingKey })}
          />
          <Pagination
            total={page.total}
            limit={page.limit}
            offset={page.offset}
            onOffsetChange={(offset) => update({ offset })}
            unit="findings"
          />
        </>
      )}

      <FindingDetailModal
        finding={open}
        altitude={altitude}
        onAltitudeChange={setAltitude}
        onClose={() => update({ open: "" })}
      />
    </div>
  );
}
