import { fireEvent, screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { IdentityDetail } from "../api/types";
import { IDENTITY } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { IdentityDetailPage } from "./IdentityDetailPage";

const getIdentity = vi.fn<(id: string) => Promise<IdentityDetail>>();

vi.mock("../api/endpoints", () => ({
  getIdentity: (id: string) => getIdentity(id),
  investigateFinding: () => Promise.reject(new Error("not used in this test")),
  planRemediation: () => Promise.reject(new Error("not used in this test")),
  verifyLedgerScan: () => Promise.reject(new Error("not used in this test")),
  approvePlan: () => Promise.reject(new Error("not used in this test")),
  rejectPlan: () => Promise.reject(new Error("not used in this test")),
  applyPlan: () => Promise.reject(new Error("not used in this test")),
}));

function renderPage() {
  getIdentity.mockResolvedValue(IDENTITY);
  return renderWithProviders(
    <Routes>
      <Route path="/identities/:identityId" element={<IdentityDetailPage />} />
    </Routes>,
    { route: "/identities/emp-0012", user: { user_id: "u", email: "a@athar.local", role: "analyst" } },
  );
}

describe("IdentityDetailPage altitude toggle", () => {
  it("shows only the headline sentence at the headline altitude", async () => {
    renderPage();

    expect(await screen.findByText(IDENTITY.findings[0]!.altitudes.headline)).toBeInTheDocument();
    expect(screen.queryByText(IDENTITY.findings[0]!.altitudes.explanation)).not.toBeInTheDocument();
    expect(screen.queryByText("How it got here")).not.toBeInTheDocument();
    expect(screen.queryByText("Escalation chain")).not.toBeInTheDocument();
  });

  it("adds the explanation and the causal history at the explanation altitude", async () => {
    renderPage();
    await screen.findByText(IDENTITY.findings[0]!.altitudes.headline);

    fireEvent.click(screen.getByRole("radio", { name: "Explanation" }));

    expect(await screen.findByText(IDENTITY.findings[0]!.altitudes.explanation)).toBeInTheDocument();
    expect(screen.getByText("How it got here")).toBeInTheDocument();
    expect(screen.getByText("GCP admin at org added (role change)")).toBeInTheDocument();
    // Still one altitude short of the raw provider JSON.
    expect(screen.queryByText("Escalation chain")).not.toBeInTheDocument();
  });

  it("adds the escalation chain and the raw provider snippet at the evidence altitude", async () => {
    renderPage();
    await screen.findByText(IDENTITY.findings[0]!.altitudes.headline);

    fireEvent.click(screen.getByRole("radio", { name: "Evidence" }));

    expect(await screen.findByText("Escalation chain")).toBeInTheDocument();
    expect(screen.getByText("Grants and the provider JSON behind them")).toBeInTheDocument();
    expect(screen.getAllByText("aws/authorization-details.json /UserDetailList/31").length).toBeGreaterThan(0);
    expect(screen.getByText(/Rules fired/)).toBeInTheDocument();
  });

  it("puts the altitude in the URL so a link opens at the same depth", async () => {
    getIdentity.mockResolvedValue(IDENTITY);
    renderWithProviders(
      <Routes>
        <Route path="/identities/:identityId" element={<IdentityDetailPage />} />
      </Routes>,
      { route: "/identities/emp-0012?altitude=evidence" },
    );

    expect(await screen.findByText("Escalation chain")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Evidence" })).toHaveAttribute("aria-checked", "true");
  });

  it("renders the SPEC §8.3 transparency line with every term of the score", async () => {
    renderPage();

    expect(
      await screen.findByText(
        "reach 1.0 (blast radius 70% of estate, 87 high-sensitivity resources) × " +
          "exploitability 1.2 (cross-cloud +0.2) × controls 1.0 = 120 · floor from R4 = 50 · capped at 100 → 100",
      ),
    ).toBeInTheDocument();
  });

  it("explains a score with no finding instead of showing an empty state", async () => {
    // Five of the estate's top twelve are Critical on blast radius alone.
    getIdentity.mockResolvedValue({ ...IDENTITY, findings: [], top_finding_key: null });
    renderWithProviders(
      <Routes>
        <Route path="/identities/:identityId" element={<IdentityDetailPage />} />
      </Routes>,
      { route: "/identities/emp-0021" },
    );

    expect(await screen.findByText("Scored on blast radius alone — no rule fired")).toBeInTheDocument();
    expect(screen.getByText(/69.9% of the estate, 87 high-sensitivity resources/)).toBeInTheDocument();
    expect(screen.queryByText("No rule fired against this identity in the current scan.")).not.toBeInTheDocument();
  });
});
