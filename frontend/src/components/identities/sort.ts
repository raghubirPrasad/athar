import type { SortingState } from "@tanstack/react-table";

/** Column ids the API accepts in `sort` (SPEC §13); anything else is display-only. */
export const SORTABLE_COLUMNS = new Set([
  "display_name",
  "department",
  "score",
  "severity",
  "blast_radius_pct",
  "last_activity_at",
  "status",
]);

export const NUMERIC_COLUMNS = new Set(["blast_radius_pct"]);

/** API sort string ("-score") → TanStack sorting state. */
export function parseSort(sort: string): SortingState {
  if (!sort) return [];
  const desc = sort.startsWith("-");
  return [{ id: desc ? sort.slice(1) : sort, desc }];
}

/** TanStack sorting state → API sort string, falling back when sorting is cleared. */
export function formatSort(sorting: SortingState, fallback: string): string {
  const first = sorting[0];
  if (!first) return fallback;
  return first.desc ? `-${first.id}` : first.id;
}
