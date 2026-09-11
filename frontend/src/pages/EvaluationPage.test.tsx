import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { EvalOut } from "../api/types";
import { EVALUATION, RULES } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { EvaluationPage } from "./EvaluationPage";

const getEval = vi.fn<() => Promise<EvalOut>>(() => Promise.resolve(EVALUATION));

vi.mock("../api/endpoints", () => ({
  getEval: () => getEval(),
  listRules: () => Promise.resolve(RULES),
}));

describe("EvaluationPage", () => {
  it("renders both register sentences, labelled for their reader", async () => {
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText(EVALUATION.director_sentence)).toBeInTheDocument();
    expect(screen.getByText(EVALUATION.engineer_sentence)).toBeInTheDocument();
    expect(screen.getByText("For the board")).toBeInTheDocument();
    expect(screen.getByText("For the engineer")).toBeInTheDocument();
  });

  it("says the numbers come from the held-out seed the constants never saw", async () => {
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText(/These numbers come from/)).toBeInTheDocument();
    expect(screen.getByText("held-out seed 7")).toBeInTheDocument();
    expect(screen.getByText(/never saw this estate/)).toBeInTheDocument();
    expect(screen.getByText("Held-out seed 7")).toBeInTheDocument();
    expect(screen.getByText("Threshold: High+")).toBeInTheDocument();
  });

  it("says nothing has been measured rather than showing zeros", async () => {
    // On a machine where `make eval` has never run, every metric is zero because nothing was
    // measured. Rendering "Precision 0%" under "this is a measurement rather than a rehearsal"
    // is a false claim about the engine, and it is the first thing a judge would see.
    getEval.mockResolvedValueOnce({
      ...EVALUATION,
      computed: false,
      precision: 0,
      recall: 0,
      f1: 0,
      tp: 0,
      fp: 0,
      fn: 0,
      per_rule: [],
      decoys: [],
    });
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText(/No evaluation has been run on this deployment/)).toBeInTheDocument();
    expect(screen.getByText(/make eval/)).toBeInTheDocument();
    expect(screen.queryByText("Precision")).not.toBeInTheDocument();
    expect(screen.queryByText(/never saw this estate/)).not.toBeInTheDocument();
  });

  it("warns instead when the result is from the tuning seed", async () => {
    getEval.mockResolvedValueOnce({ ...EVALUATION, held_out: false, seed: 42 });
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText(/the same estate the scoring constants were tuned on/)).toBeInTheDocument();
  });

  it("shows precision, recall and F1 at High+ and the per-rule confusion", async () => {
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText("75.0%")).toBeInTheDocument();
    expect(screen.getByText("97.3%")).toBeInTheDocument();
    expect(screen.getByText("84.7%")).toBeInTheDocument();
    // The rule's name comes from GET /rules, not from a table kept in the app.
    expect(await screen.findByText("Cross-cloud superuser")).toBeInTheDocument();
  });

  it("names the source of the numbers without printing the API host's path", async () => {
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText("Source: held-out seed 7")).toBeInTheDocument();
    expect(screen.queryByText(EVALUATION.generated_from)).not.toBeInTheDocument();
    expect(screen.queryByText(/\/data\/estate|\/Users\//)).not.toBeInTheDocument();
  });

  it("lists each decoy with why it is legitimate and whether it was handled", async () => {
    renderWithProviders(<EvaluationPage />, { route: "/evaluation" });

    expect(await screen.findByText("Mariam Al Mazrouei")).toBeInTheDocument();
    expect(screen.getByText(EVALUATION.decoys[0]!.why_legitimate)).toBeInTheDocument();
    expect(screen.getByText("Correct")).toBeInTheDocument();
    expect(screen.getByText("Not flagged")).toBeInTheDocument();
  });
});
