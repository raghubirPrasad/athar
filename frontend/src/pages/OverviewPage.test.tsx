import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SUMMARY } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { OverviewPage } from "./OverviewPage";

vi.mock("../api/endpoints", () => ({
  getEstateSummary: () => Promise.resolve(SUMMARY),
  runScan: () => Promise.reject(new Error("not used in this test")),
  advanceMonth: () => Promise.reject(new Error("not used in this test")),
}));

/**
 * PRD §8.2 / SPEC §14: every number on the landing page is clickable to its
 * evidence. These tests pin the destination of each one, because a number that
 * silently stops being a link is the failure mode nobody notices.
 */
describe("OverviewPage", () => {
  it("links each department's half-life to that department on the timeline", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    const slow = await screen.findByRole("link", { name: "Half-life evidence for Smart Services" });
    expect(slow).toHaveAttribute("href", "/timeline?department=Smart%20Services");
    expect(slow).toHaveTextContent("5.0 months");
  });

  it("links a department that never revokes as well, since Never is the headline number", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    const never = await screen.findByRole("link", { name: "Half-life evidence for Finance" });
    expect(never).toHaveAttribute("href", "/timeline?department=Finance");
    expect(never).toHaveTextContent("Never");
  });

  it("links the per-cloud finding counts to the findings filtered by that cloud", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    const aws = await screen.findByRole("link", { name: "70 findings on aws" });
    expect(aws).toHaveAttribute("href", "/findings?cloud=aws");
    expect(screen.getByRole("link", { name: "47 findings on azure" })).toHaveAttribute(
      "href",
      "/findings?cloud=azure",
    );
    expect(screen.getByRole("link", { name: "34 findings on gcp" })).toHaveAttribute("href", "/findings?cloud=gcp");
  });

  it("shows the executive paragraph on its own, with no attribution line under it", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    expect(await screen.findByText("Executive summary")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /on the governance ledger/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/Generated from templates/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Written by /)).not.toBeInTheDocument();
  });

  it("keeps the stat tiles pointing at the rows behind them", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    expect(await screen.findByRole("link", { name: /^Identities\s*507/ })).toHaveAttribute("href", "/identities");
    // The tile and the histogram bar are both "Critical 21" and both lead to
    // the same filtered list; neither may quietly stop being a link.
    const critical = screen.getAllByRole("link", { name: /Critical\s*21/ });
    expect(critical).toHaveLength(2);
    for (const link of critical) expect(link).toHaveAttribute("href", "/findings?severity=Critical");
    expect(screen.getByRole("link", { name: /^Open findings\s*99/ })).toHaveAttribute("href", "/findings");
  });

  it("leaves no bare number on the page outside a link", async () => {
    const { container } = renderWithProviders(<OverviewPage />, { route: "/" });
    await screen.findByRole("link", { name: "Half-life evidence for Finance" });

    // A "number" here is a value the reader would click: a bare count, percentage
    // or measure. Prose that happens to contain a digit — the model's executive
    // paragraph, a "(SPEC §9.3)" citation — is narrative, and its figures are the
    // same ones the tiles beside it already link.
    const VALUE = /^\d[\d,]*(\.\d+)?\s*(%|mo|months?)?$/;
    const orphans: string[] = [];
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.nodeValue?.trim() ?? "";
      if (!VALUE.test(text)) continue;
      const element = node.parentElement;
      if (!element || element.closest("a[href],button")) continue;
      orphans.push(text);
    }

    expect(orphans).toEqual([]);
  });

  it("keeps the department card's own counts linked to the filtered findings", async () => {
    renderWithProviders(<OverviewPage />, { route: "/" });

    const card = (await screen.findByRole("heading", { name: "Finance" })).closest("article");
    expect(card).not.toBeNull();
    const links = within(card as HTMLElement).getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      "/identities?department=Finance",
      "/findings?department=Finance",
      "/findings?department=Finance&severity=Critical",
      "/timeline?department=Finance",
    ]);
  });
});
