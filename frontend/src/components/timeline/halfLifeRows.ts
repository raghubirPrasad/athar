import type { HalfLifeOut } from "../../api/types";

/** The API's aggregate row uses this sentinel in the `department` column. */
export const ALL_DEPARTMENTS = "all";

/**
 * Rows to show when the half-life table is opened for one department — the
 * target of every half-life number elsewhere in the app (PRD §8.2).
 *
 * The estate-wide `all` rows stay in view as the baseline: "Finance never
 * revokes" only means something next to what the rest of the estate does.
 * A department with no rows at all (nothing granted, nothing revoked) selects
 * nothing, and the caller shows the empty state rather than a silent full table.
 */
export function selectHalfLifeRows(
  rows: readonly HalfLifeOut[],
  department: string | null,
): readonly HalfLifeOut[] {
  if (!department || department === ALL_DEPARTMENTS) return rows;
  const own = rows.filter((row) => row.department === department);
  if (own.length === 0) return [];
  return rows.filter((row) => row.department === department || row.department === ALL_DEPARTMENTS);
}
