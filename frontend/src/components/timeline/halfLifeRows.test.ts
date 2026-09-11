import { describe, expect, it } from "vitest";
import type { HalfLifeOut } from "../../api/types";
import { selectHalfLifeRows } from "./halfLifeRows";

const ROWS: HalfLifeOut[] = [
  { department: "all", trigger: "all", grants: 10832, revocations: 946, half_life_months: null, label: "Broken" },
  { department: "all", trigger: "departure", grants: 10832, revocations: 619, half_life_months: 3.5, label: "Healthy" },
  { department: "Finance", trigger: "departure", grants: 34, revocations: 2, half_life_months: null, label: "Broken" },
  { department: "Finance", trigger: "role_change", grants: 34, revocations: 8, half_life_months: 6, label: "Slow" },
  { department: "HR", trigger: "departure", grants: 20, revocations: 9, half_life_months: 2, label: "Healthy" },
];

describe("selectHalfLifeRows", () => {
  it("returns every row when no department is selected", () => {
    expect(selectHalfLifeRows(ROWS, null)).toHaveLength(5);
  });

  it("keeps the department's own rows and the estate-wide baseline", () => {
    const rows = selectHalfLifeRows(ROWS, "Finance");

    expect(rows.map((row) => `${row.department}:${row.trigger}`)).toEqual([
      "all:all",
      "all:departure",
      "Finance:departure",
      "Finance:role_change",
    ]);
  });

  it("treats the sentinel department as no selection at all", () => {
    expect(selectHalfLifeRows(ROWS, "all")).toHaveLength(5);
  });

  it("selects nothing for a department the table has no rows for", () => {
    // Not even the baseline: a lone "All departments" row under a heading that
    // says Contractors reads as Contractors' own numbers.
    expect(selectHalfLifeRows(ROWS, "Contractors")).toHaveLength(0);
  });
});
