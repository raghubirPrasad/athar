import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type {
  EstateSummary,
  LedgerDecisionPage,
  PlanListQuery,
  PlanPage,
  RemediationPlanOut,
} from "../api/types";
import { APPROVER, PLAN, VIEWER } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { RemediationPage } from "./RemediationPage";

const PLANS: PlanPage = { items: [PLAN], total: 1, limit: 20, offset: 0 };
const NO_DECISIONS: LedgerDecisionPage = { items: [], total: 0, limit: 50, offset: 0 };
const SUMMARY = { findings_by_department: [{ department: "Data Services" }] } as unknown as EstateSummary;

const approvePlan = vi.fn<(planId: string) => Promise<RemediationPlanOut>>();
const listPlans = vi.fn<(query: PlanListQuery) => Promise<PlanPage>>();

vi.mock("../api/endpoints", () => ({
  listPlans: (query: PlanListQuery) => listPlans(query),
  listLedgerDecisions: () => Promise.resolve(NO_DECISIONS),
  getEstateSummary: () => Promise.resolve(SUMMARY),
  approvePlan: (planId: string) => approvePlan(planId),
  rejectPlan: () => Promise.reject(new Error("not used in this test")),
  applyPlan: () => Promise.reject(new Error("not used in this test")),
}));

/** The page asks twice: once for the visible page, once (limit 200) for the tab counts. */
function pages(visible: PlanPage, everything: PlanPage = visible) {
  return (query: PlanListQuery) => Promise.resolve(query.limit === 200 ? everything : visible);
}

const EMPTY: PlanPage = { items: [], total: 0, limit: 20, offset: 0 };

beforeEach(() => {
  approvePlan.mockReset();
  listPlans.mockReset();
  listPlans.mockImplementation(pages(PLANS));
});

describe("RemediationPage", () => {
  it("shows the plan, its rationale, confidence and privilege reduction", async () => {
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: APPROVER });

    expect(await screen.findByText(PLAN.rationale)).toBeInTheDocument();
    expect(screen.getByText(/confidence 82%/)).toBeInTheDocument();
    expect(screen.getByText("16.7%")).toBeInTheDocument();
    expect(screen.getByText(PLAN.policy_diff.summary)).toBeInTheDocument();
  });

  it("hides the decision buttons from a viewer and says why", async () => {
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: VIEWER });

    await screen.findByText(PLAN.rationale);
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getByText(/Only an approver can decide this plan/)).toBeInTheDocument();
  });

  it("confirms before approving", async () => {
    approvePlan.mockResolvedValue({ ...PLAN, status: "approved" });
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: APPROVER });

    await screen.findByText(PLAN.rationale);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Approve plan plan-0002?");
    expect(approvePlan).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Approve plan" }));
    await waitFor(() => expect(approvePlan).toHaveBeenCalledWith("plan-0002"));
  });

  it("shows the server's separation-of-duties refusal inline as problem+json", async () => {
    approvePlan.mockRejectedValue(
      new ApiError(403, {
        title: "Forbidden",
        detail: "A plan cannot be approved by the user who proposed it",
        code: "rbac.separation_of_duties",
        status: 403,
      }),
    );
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: APPROVER });

    await screen.findByText(PLAN.rationale);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    fireEvent.click(await screen.findByRole("button", { name: "Approve plan" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("A plan cannot be approved by the user who proposed it");
    expect(alert).toHaveTextContent("rbac.separation_of_duties");
    expect(alert).toHaveTextContent("HTTP 403");
    // The page keeps working: the plan is still on screen, not replaced by a crash.
    expect(screen.getByText(PLAN.rationale)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("tells an empty queue apart from a filter that hides everything", async () => {
    listPlans.mockImplementation(pages(EMPTY, PLANS));
    renderWithProviders(<RemediationPage />, { route: "/remediation?status=rejected", user: APPROVER });

    expect(await screen.findByText("No plan matches this filter")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });

  it("says where plans come from when none has ever been proposed", async () => {
    listPlans.mockImplementation(pages(EMPTY, EMPTY));
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: APPROVER });

    expect(await screen.findByText("Nothing in the queue yet")).toBeInTheDocument();
    expect(screen.getByText(/Plan remediation/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to findings" })).toHaveAttribute("href", "/findings");
  });

  it("counts a single plan in the singular", async () => {
    renderWithProviders(<RemediationPage />, { route: "/remediation", user: APPROVER });

    expect(await screen.findByText("1 plan")).toBeInTheDocument();
  });
});
