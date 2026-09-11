import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { getEstateSummary, listIdentities } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import { IdentityFilters } from "../components/identities/IdentityFilters";
import { IdentityTable } from "../components/identities/IdentityTable";
import { readFilters, toQuery, writeFilters, type IdentityFilterState } from "../components/identities/filters";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Pagination } from "../components/ui/Pagination";
import { SkeletonTable } from "../components/ui/Skeleton";
import { formatInt } from "../lib/format";

/**
 * Identity table (SPEC §14). Sorted by score descending by default — the demo's
 * first move (PRD §9). Filters and sort live in the URL, never in web storage.
 */
export function IdentitiesPage() {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readFilters(params), [params]);

  const update = useCallback(
    (patch: Partial<IdentityFilterState>) => {
      setParams(writeFilters({ ...readFilters(params), ...patch }), { replace: true });
    },
    [params, setParams],
  );

  const query = toQuery(filters);
  const identities = useQuery({
    queryKey: queryKeys.identities.list(query),
    queryFn: () => listIdentities(query),
    placeholderData: keepPreviousData,
  });

  const summary = useQuery({ queryKey: queryKeys.estate.summary(), queryFn: getEstateSummary });
  const departments = useMemo(
    () => (summary.data?.findings_by_department ?? []).map((row) => row.department),
    [summary.data],
  );

  const page = identities.data;

  return (
    <div className="flex flex-col gap-3">
      <PageHeader
        title="Identities"
        description="Every human and service identity across the three clouds, ranked by risk score. Select a row for the evidence behind it."
        meta={page && <span className="text-xs text-fg-muted">{formatInt(page.total)} matching identities</span>}
      />

      <IdentityFilters value={filters} onChange={update} departments={departments} />

      {identities.isError && <ErrorState error={identities.error} onRetry={() => void identities.refetch()} />}

      {identities.isPending && <SkeletonTable rows={10} cols={10} />}

      {page && page.items.length === 0 && (
        <EmptyState
          title="No identities match these filters"
          description="Widen the cloud, department or severity filter, or clear the name search."
        />
      )}

      {page && page.items.length > 0 && (
        <>
          <IdentityTable
            rows={page.items}
            sort={filters.sort}
            onSortChange={(sort) => update({ sort, offset: 0 })}
          />
          <Pagination
            total={page.total}
            limit={page.limit}
            offset={page.offset}
            onOffsetChange={(offset) => update({ offset })}
            unit="identities"
          />
        </>
      )}
    </div>
  );
}
