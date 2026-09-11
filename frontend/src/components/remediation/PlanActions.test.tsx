import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ApplyResult, RemediationPlanOut } from "../../api/types";
import { APPROVER, FINDING, PLAN } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { PlanActions } from "./PlanActions";

const APPROVED: RemediationPlanOut = { ...PLAN, status: "approved" };

const applied: ApplyResult = {
  plan: { ...APPROVED, status: "applied" },
  finding: FINDING,
  score_before: 100,
  score_after: 62,
  blast_radius_before: 0.698795,
  blast_radius_after: 0.2477,
  scan_id: 13,
  ledger_status: "anchored",
  warnings: ["The grant was already absent from the AWS export; nothing was rewritten."],
};

const applyPlan = vi.fn<(planId: string) => Promise<ApplyResult>>();

vi.mock("../../api/endpoints", () => ({
  applyPlan: (planId: string) => applyPlan(planId),
  approvePlan: () => Promise.reject(new Error("not used in this test")),
  rejectPlan: () => Promise.reject(new Error("not used in this test")),
}));

async function apply(result: ApplyResult) {
  applyPlan.mockResolvedValue(result);
  renderWithProviders(<PlanActions plan={APPROVED} />, { route: "/remediation", user: APPROVER });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  fireEvent.click(await screen.findByRole("button", { name: "Apply change" }));
  await waitFor(() => expect(applyPlan).toHaveBeenCalledWith(PLAN.plan_id));
}

describe("PlanActions apply result", () => {
  it("reports the blast radius the re-scan measured, before and after", async () => {
    await apply(applied);

    const outcome = await screen.findByText(/Applied\. Risk/);
    expect(outcome).toHaveTextContent("100");
    expect(outcome).toHaveTextContent("62");
    expect(outcome).toHaveTextContent("69.9%");
    expect(outcome).toHaveTextContent("24.8%");
    expect(outcome).toHaveTextContent("re-scan 13");
  });

  it("shows a warning as a warning, not as part of the success line", async () => {
    await apply(applied);

    expect(await screen.findByText(applied.warnings![0]!)).toBeInTheDocument();
    expect(screen.getByText(/the decision is recorded, the estate may not have changed/)).toBeInTheDocument();
  });

  it("says nothing about warnings when the apply reported none", async () => {
    await apply({ ...applied, warnings: [] });

    await screen.findByText(/Applied\. Risk/);
    expect(screen.queryByText(/the estate may not have changed/)).not.toBeInTheDocument();
  });
});
