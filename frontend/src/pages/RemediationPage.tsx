import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { getEstateSummary, listLedgerDecisions, listPlans } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { PlanListQuery } from "../api/types";
import { useAuth } from "../auth/useAuth";
import { ROLE_LABEL, isRole } from "../auth/roles";
import { DecisionsTable } from "../components/ledger/DecisionsTable";
import { PlanCard } from "../components/remediation/PlanCard";
import { PlanFilters, type PlanFilterState } from "../components/remediation/PlanFilters";
import { countByStatus } from "../components/remediation/planMeta";
import { Badge } from "../components/ui/Badge";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Pagination } from "../components/ui/Pagination";
import { Skeleton } from "../components/ui/Skeleton";
import { formatInt } from "../lib/format";

const LIMIT = 20;
const COUNT_QUERY: PlanListQuery = { limit: 200, offset: 0, sort: "-created_at" };

function readFilters(params: URLSearchParams): PlanFilterState & { offset: number } {
  const offset = Number(params.get("offset") ?? "0");
  return {
    status: params.get("status") ?? "",
    department: params.get("department") ?? "",
    q: params.get("q") ?? "",
    offset: Number.isFinite(offset) && offset > 0 ? Math.floor(offset) : 0,
  };
}

/**
 * The approver's queue (SPEC §14, §11.5). Every plan shows what it changes, who
 * proposed it and with what confidence, and the provider-native diff — then asks
 * a human. Separation of duties is enforced by the API (SPEC §15.1): a refusal
 * comes back as problem+json and is shown on the plan it belongs to.
 */
export function RemediationPage() {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readFilters(params), [params]);
  const { user } = useAuth();

  const update = useCallback(
    (patch: Partial<PlanFilterState & { offset: number }>) => {
      const next = { ...readFilters(params), ...patch };
      const updated = new URLSearchParams();
      if (next.status) updated.set("status", next.status);
      if (next.department) updated.set("department", next.department);
      if (next.q) updated.set("q", next.q);
      const offset = patch.offset ?? 0;
      if (offset > 0) updated.set("offset", String(offset));
      setParams(updated, { replace: true });
    },
    [params, setParams],
  );

  const listQuery: PlanListQuery = {
    limit: LIMIT,
    offset: filters.offset,
    sort: "-created_at",
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.department ? { department: filters.department } : {}),
    ...(filters.q ? { q: filters.q } : {}),
  };

  const plans = useQuery({
    queryKey: queryKeys.remediation.list(listQuery),
    queryFn: () => listPlans(listQuery),
    placeholderData: keepPreviousData,
  });

  const allPlans = useQuery({
    queryKey: queryKeys.remediation.list(COUNT_QUERY),
    queryFn: () => listPlans(COUNT_QUERY),
  });

  const decisions = useQuery({
    queryKey: queryKeys.ledger.decisions(),
    queryFn: () => listLedgerDecisions({ limit: 50, offset: 0, sort: "-created_at" }),
  });

  const summary = useQuery({ queryKey: queryKeys.estate.summary(), queryFn: getEstateSummary });
  const departments = useMemo(
    () => (summary.data?.findings_by_department ?? []).map((row) => row.department),
    [summary.data],
  );

  const page = plans.data;
  const counts = countByStatus(allPlans.data?.items ?? []);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Remediation queue"
        description="Proposed least-privilege changes waiting for a human decision. Approving records the decision on the ledger; applying changes the estate and re-scores the identity."
        meta={
          <>
            {user && (
              <Badge tone={user.role === "approver" ? "ok" : "neutral"}>
                Signed in as {isRole(user.role) ? ROLE_LABEL[user.role] : user.role}
              </Badge>
            )}
            <span className="text-xs text-fg-muted">
              Separation of duties: a plan cannot be approved by the user who proposed it, and Apply needs an approved
              plan.
            </span>
          </>
        }
      />

      <PlanFilters
        value={filters}
        onChange={(patch) => update({ ...patch, offset: 0 })}
        counts={counts}
        total={allPlans.data?.total ?? 0}
        departments={departments}
      />

      {plans.isError && <ErrorState error={plans.error} onRetry={() => void plans.refetch()} />}

      {plans.isPending && <Skeleton lines={8} height="h-6" />}

      {page && page.items.length === 0 && (
        <EmptyState
          title={allPlans.data?.total ? "No plan matches this filter" : "Nothing in the queue yet"}
          description={
            allPlans.data?.total
              ? "Every proposed plan is still here — widen the status, department or name filter to see it."
              : "No plan has been proposed. Open an identity, expand a finding to Explanation or deeper, and choose “Plan remediation” in its Agent panel."
          }
          action={
            allPlans.data?.total ? (
              <Button size="sm" variant="secondary" onClick={() => update({ status: "", department: "", q: "" })}>
                Clear filters
              </Button>
            ) : (
              <ButtonLink to="/findings" variant="secondary" size="sm">
                Go to findings
              </ButtonLink>
            )
          }
        />
      )}

      {page && page.items.length > 0 && (
        <>
          <p className="text-xs text-fg-muted">
            {formatInt(page.total)} {page.total === 1 ? "plan" : "plans"}
          </p>
          <div className="flex flex-col gap-4">
            {page.items.map((plan) => (
              <PlanCard key={plan.plan_id} plan={plan} />
            ))}
          </div>
          <Pagination
            total={page.total}
            limit={page.limit}
            offset={page.offset}
            onOffsetChange={(offset) => update({ offset })}
            unit="plans"
          />
        </>
      )}

      <Card
        title="Audit trail"
        subtitle="Every decision taken in ATHAR, with the proof it was bound to"
      >
        {decisions.isError && <ErrorState compact error={decisions.error} onRetry={() => void decisions.refetch()} />}
        {decisions.isPending && <Skeleton lines={4} />}
        {decisions.data && <DecisionsTable decisions={decisions.data.items} />}
      </Card>
    </div>
  );
}
