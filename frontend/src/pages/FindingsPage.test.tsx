import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { EstateSummary, ExportQuery, FindingListQuery, FindingOut, FindingPage } from "../api/types";
import { FINDING, RULES } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { FindingsPage } from "./FindingsPage";

const PAGE: FindingPage = { items: [FINDING], total: 1, limit: 50, offset: 0 };
const SUMMARY = {
  current_month: 12,
  findings_by_department: [{ department: "Data Services" }],
} as unknown as EstateSummary;

const listFindings = vi.fn<(query: FindingListQuery) => Promise<FindingPage>>();
const getFinding = vi.fn<(key: string) => Promise<FindingOut>>();
const exportFindings = vi.fn<(format: string, query: ExportQuery) => Promise<{ blob: Blob; filename: string }>>();

vi.mock("../api/endpoints", () => ({
  listFindings: (query: FindingListQuery) => listFindings(query),
  getFinding: (key: string) => getFinding(key),
  getEstateSummary: () => Promise.resolve(SUMMARY),
  exportFindings: (format: string, query: ExportQuery) => exportFindings(format, query),
  listRules: () => Promise.resolve(RULES),
  verifyLedgerScan: () => Promise.reject(new Error("not used in this test")),
}));

beforeEach(() => {
  listFindings.mockReset();
  listFindings.mockResolvedValue(PAGE);
  getFinding.mockReset();
  getFinding.mockRejectedValue(new Error("not used in this test"));
  exportFindings.mockReset();
  exportFindings.mockResolvedValue({ blob: new Blob(["a"]), filename: "athar-findings.csv" });
});

describe("FindingsPage", () => {
  it("asks the API for score-descending order and renders a row per finding", async () => {
    renderWithProviders(<FindingsPage />, { route: "/findings" });

    expect(await screen.findByText(FINDING.display_name)).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText("R4 · Cross-cloud superuser")).toBeInTheDocument();
    expect(listFindings).toHaveBeenCalledWith(expect.objectContaining({ sort: "-score", offset: 0 }));
  });

  it("passes the filter vocabulary from the URL to the API", async () => {
    renderWithProviders(<FindingsPage />, { route: "/findings?severity=Critical&cloud=gcp&rule=R4&month=11" });

    await screen.findByText(FINDING.display_name);
    expect(listFindings).toHaveBeenCalledWith(
      expect.objectContaining({ severity: "Critical", cloud: "gcp", rule: "R4", month: 11 }),
    );
  });

  it("opens the finding from a row and keeps it in the URL", async () => {
    renderWithProviders(<FindingsPage />, { route: "/findings" });

    fireEvent.click(await screen.findByText(FINDING.display_name));

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(FINDING.altitudes.headline);
    expect(dialog).toHaveTextContent(FINDING.finding_key);
  });

  it("exports the findings with the filters that are on screen", async () => {
    renderWithProviders(<FindingsPage />, { route: "/findings?severity=Critical" });
    await screen.findByText(FINDING.display_name);

    fireEvent.click(screen.getByRole("button", { name: "CSV" }));

    await waitFor(() => expect(exportFindings).toHaveBeenCalledWith("csv", { severity: "Critical" }));
    expect(await screen.findByText("CSV export downloaded")).toBeInTheDocument();
  });

  it("opens a finding the ledger linked to even when it is not on this page", async () => {
    // The decision rows on the ledger link to ?open=<key>; the default page is
    // fifty score-ordered rows, so the key usually is not one of them.
    const elsewhere: FindingOut = { ...FINDING, finding_key: "f00d", display_name: "Rashid Al Kaabi" };
    getFinding.mockResolvedValue(elsewhere);

    renderWithProviders(<FindingsPage />, { route: "/findings?open=f00d" });

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Rashid Al Kaabi");
    expect(getFinding).toHaveBeenCalledWith("f00d");
  });

  it("says so, rather than silently doing nothing, when a linked finding will not load", async () => {
    getFinding.mockRejectedValue(
      new ApiError(404, { title: "Not Found", detail: "No such finding", code: "finding.not_found", status: 404 }),
    );

    renderWithProviders(<FindingsPage />, { route: "/findings?open=gone" });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No such finding");
    expect(screen.getByRole("button", { name: "Clear the link" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows a designed empty state when nothing matches", async () => {
    listFindings.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 });
    renderWithProviders(<FindingsPage />, { route: "/findings?q=nobody" });

    expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  });
});
