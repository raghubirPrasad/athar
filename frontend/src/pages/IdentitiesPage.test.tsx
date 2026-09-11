import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EstateSummary, IdentityListQuery, IdentityPage, IdentityRow } from "../api/types";
import { RULES } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { IdentitiesPage } from "./IdentitiesPage";

const ROWS: IdentityRow[] = [
  {
    identity_id: "emp-0012",
    display_name: "Latifa Al Ketbi",
    identity_type: "human",
    department: "Data Services",
    clouds: ["aws", "azure", "gcp"],
    score: 80,
    severity: "Critical",
    top_rule: "R4",
    top_rule_name: "Cross-cloud superuser",
    blast_radius_pct: 29.7,
    last_activity_at: "2026-07-24",
    status: "active",
    finding_count: 4,
    external: false,
    mfa_enforced: false,
  },
  {
    identity_id: "emp-0002",
    display_name: "Fatima Al Hammadi",
    identity_type: "human",
    department: "HR",
    clouds: ["azure", "gcp"],
    score: 75,
    severity: "Critical",
    top_rule: "R3",
    top_rule_name: "Orphaned identity",
    blast_radius_pct: 39.3,
    last_activity_at: "2026-08-25",
    status: "departed",
    finding_count: 2,
    external: false,
    mfa_enforced: true,
  },
  {
    identity_id: "emp-0021",
    display_name: "Noura Al Suwaidi",
    identity_type: "human",
    department: "Data Services",
    clouds: ["aws"],
    score: 100,
    severity: "Critical",
    // Critical on measured blast radius with no rule fired (SPEC §8.3).
    top_rule: null,
    top_rule_name: null,
    blast_radius_pct: 69.9,
    last_activity_at: "2026-08-01",
    status: "active",
    finding_count: 0,
    external: false,
    mfa_enforced: true,
  },
];

const SUMMARY = {
  findings_by_department: [
    { department: "Data Services" },
    { department: "HR" },
  ],
} as unknown as EstateSummary;

const listIdentities = vi.fn<(query: IdentityListQuery) => Promise<IdentityPage>>();

vi.mock("../api/endpoints", () => ({
  listIdentities: (query: IdentityListQuery) => listIdentities(query),
  getEstateSummary: () => Promise.resolve(SUMMARY),
  listRules: () => Promise.resolve(RULES),
}));

beforeEach(() => {
  listIdentities.mockReset();
  listIdentities.mockImplementation((query) =>
    Promise.resolve({
      items: query.sort === "score" ? [...ROWS].reverse() : ROWS,
      total: ROWS.length,
      limit: query.limit ?? 50,
      offset: query.offset ?? 0,
    }),
  );
});

describe("IdentitiesPage", () => {
  it("renders the rows returned by the query", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities" });

    expect(await screen.findByText("Latifa Al Ketbi")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("Fatima Al Hammadi")).toBeInTheDocument();
    expect(within(table).getByText("R4 · Cross-cloud superuser")).toBeInTheDocument();
    expect(within(table).getAllByRole("meter", { name: "Risk score" })).toHaveLength(ROWS.length);
    expect(within(table).getByText("Departed")).toBeInTheDocument();
  });

  it("asks the API for score-descending order by default", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities" });

    await screen.findByText("Latifa Al Ketbi");
    expect(listIdentities).toHaveBeenCalledWith(expect.objectContaining({ sort: "-score", offset: 0 }));

    const rows = screen.getAllByRole("row").slice(1); // drop the header row
    expect(within(rows[0] as HTMLElement).getByText("Latifa Al Ketbi")).toBeInTheDocument();
  });

  it("re-sorts server-side when the score header is clicked", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities" });
    await screen.findByText("Latifa Al Ketbi");

    fireEvent.click(screen.getByRole("button", { name: /Score/ }));

    await waitFor(() =>
      expect(listIdentities).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "score" })),
    );
    await waitFor(() => {
      const rows = screen.getAllByRole("row").slice(1);
      expect(within(rows[0] as HTMLElement).getByText("Noura Al Suwaidi")).toBeInTheDocument();
    });
  });

  it("passes the severity filter from the URL to the API", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities?severity=Critical&cloud=gcp" });

    await screen.findByText("Latifa Al Ketbi");
    expect(listIdentities).toHaveBeenCalledWith(
      expect.objectContaining({ severity: "Critical", cloud: "gcp" }),
    );
  });

  it("shows a designed empty state when nothing matches", async () => {
    listIdentities.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    renderWithProviders(<IdentitiesPage />, { route: "/identities?q=nobody" });

    expect(await screen.findByText("No identities match these filters")).toBeInTheDocument();
  });

  it("explains a Critical identity that no rule fired on, instead of an em dash", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities" });

    await screen.findByText("Noura Al Suwaidi");
    const row = screen.getAllByRole("row").find((r) => r.textContent?.includes("Noura Al Suwaidi"));
    expect(within(row as HTMLElement).getByText("scored on blast radius alone — no rule fired")).toBeInTheDocument();
    expect(within(row as HTMLElement).queryByText("—")).not.toBeInTheDocument();
  });

  it("offers every rule the API serves in the filter, R0 included", async () => {
    renderWithProviders(<IdentitiesPage />, { route: "/identities" });

    await screen.findByText("Latifa Al Ketbi");
    const rule = screen.getByLabelText("Rule");
    await waitFor(() =>
      expect(within(rule).getByRole("option", { name: "R0 · Unmapped permission" })).toBeInTheDocument(),
    );
    expect(within(rule).getByRole("option", { name: "R4 · Cross-cloud superuser" })).toBeInTheDocument();
  });
});
