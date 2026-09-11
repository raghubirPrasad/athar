import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CausalStepOut, RiskPoint } from "../../api/types";
import { RiskSparkline } from "./RiskSparkline";

function grantEvent(month: number, index: number, verb: string): CausalStepOut {
  return {
    month,
    event_id: `evt-${month}-${index}`,
    kind: "grant",
    trigger: "incident_response",
    cloud: "aws",
    description: `AWS ${verb} category-${index} on * added`,
    grant_delta: { added: [{ verb }] },
  };
}

/** emp-0172's shape: seventy grant events in one month, score unchanged. */
const POINTS: RiskPoint[] = [
  {
    month: 1,
    score: 100,
    severity: "Critical",
    events: [
      ...Array.from({ length: 68 }, (_, index) => grantEvent(1, index, "read")),
      grantEvent(1, 68, "admin"),
      grantEvent(1, 69, "delete"),
    ],
  },
  { month: 2, score: 100, severity: "Critical", events: [] },
];

describe("RiskSparkline annotations", () => {
  it("lists a few changes per month instead of one run-on sentence", () => {
    render(<RiskSparkline points={POINTS} />);

    const changes = screen.getAllByRole("list").at(-1);
    const items = within(changes as HTMLElement).getAllByRole("listitem");
    // Three changes plus the "and N more" line, not seventy descriptions.
    expect(items).toHaveLength(4);
    expect(screen.getByText("and 67 more changes in this month")).toBeInTheDocument();
  });

  it("keeps the annotation short enough to read", () => {
    render(<RiskSparkline points={POINTS} />);

    const longest = screen
      .getAllByRole("listitem")
      .map((item) => item.textContent?.length ?? 0)
      .reduce((a, b) => Math.max(a, b), 0);
    expect(longest).toBeLessThan(400);
  });

  it("says when a month's events did not move the score", () => {
    render(<RiskSparkline points={POINTS} />);

    expect(screen.getByText(/\(unchanged\)/)).toBeInTheDocument();
  });

  it("does not claim a trend for an identity first seen this month", () => {
    const first: RiskPoint = { month: 12, score: 100, severity: "Critical", events: [] };
    render(<RiskSparkline points={[first]} />);

    expect(screen.getByText(/there is no earlier month to compare with/)).toBeInTheDocument();
    expect(screen.queryByText(/Risk moved from/)).not.toBeInTheDocument();
  });

  it("says plainly when an identity was never scored", () => {
    render(<RiskSparkline points={[]} />);

    expect(screen.getByText("No risk history")).toBeInTheDocument();
    expect(screen.getByText(/has not been scored in any snapshot/)).toBeInTheDocument();
  });
});
