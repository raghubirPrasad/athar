import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { HalfLifeOut } from "../../api/types";
import { renderWithProviders } from "../../test/render";
import { HalfLifeTableView } from "./HalfLifeTableView";

/** One row per trigger the API actually returns (SPEC §9.1, §9.3). */
const ROWS: HalfLifeOut[] = [
  { department: "all", trigger: "all", grants: 10832, revocations: 946, half_life_months: null, label: "Broken" },
  { department: "all", trigger: "departure", grants: 10832, revocations: 619, half_life_months: 3.5, label: "Healthy" },
  { department: "Finance", trigger: "role_change", grants: 40, revocations: 8, half_life_months: 6, label: "Slow" },
  {
    department: "Finance",
    trigger: "incident_response",
    grants: 40,
    revocations: 5,
    half_life_months: 2,
    label: "Healthy",
  },
  {
    department: "Finance",
    trigger: "project_retirement",
    grants: 40,
    revocations: 4,
    half_life_months: 9,
    label: "Broken",
  },
];

describe("HalfLifeTableView", () => {
  it("labels every trigger the API returns, not just three of them", () => {
    renderWithProviders(<HalfLifeTableView rows={ROWS} />);

    expect(screen.getByText("Incident response")).toBeInTheDocument();
    expect(screen.getByText("Project retirement")).toBeInTheDocument();
    expect(screen.getByText("Offboarding")).toBeInTheDocument();
    expect(screen.getByText("Role change")).toBeInTheDocument();
    expect(screen.getByText("All grants")).toBeInTheDocument();
    expect(screen.queryByText("incident response")).not.toBeInTheDocument();
    expect(screen.queryByText("project retirement")).not.toBeInTheDocument();
  });

  it("names the aggregate row instead of printing the sentinel 'all'", () => {
    renderWithProviders(<HalfLifeTableView rows={ROWS} />);

    expect(screen.getAllByText("All departments")).toHaveLength(2);
    expect(screen.getAllByText("Finance")).toHaveLength(3);
  });

  it("narrows to one department plus the estate-wide baseline when opened for it", () => {
    renderWithProviders(<HalfLifeTableView rows={ROWS} selected="Finance" />);

    expect(screen.getAllByText("Finance")).toHaveLength(3);
    expect(screen.getAllByText("All departments")).toHaveLength(2);
    // The other departments' rows are gone, so nothing on screen is misread as Finance's.
    expect(screen.getAllByRole("row")).toHaveLength(6); // header + 5
  });

  it("marks the selected department's rows as the current selection, not by colour alone", () => {
    renderWithProviders(<HalfLifeTableView rows={ROWS} selected="Finance" />);

    const current = screen.getAllByRole("row").filter((row) => row.getAttribute("aria-current") === "true");
    expect(current).toHaveLength(3);
  });

  it("says which department has no half-life data rather than showing everyone else's", () => {
    renderWithProviders(<HalfLifeTableView rows={[]} selected="Contractors" />);

    expect(screen.getByText("No half-life data for Contractors")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("links no number in the table: this table is the evidence", () => {
    renderWithProviders(<HalfLifeTableView rows={ROWS} />);

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
