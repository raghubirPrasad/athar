import { describe, expect, it } from "vitest";
import type { CausalStepOut, RiskPoint } from "../../api/types";
import { riskAnnotations } from "./riskAnnotations";

function event(overrides: Partial<CausalStepOut> & { description: string }): CausalStepOut {
  return {
    month: 1,
    event_id: `evt-${overrides.description}`,
    kind: "grant",
    trigger: "unknown",
    cloud: "aws",
    grant_delta: {},
    ...overrides,
  };
}

/** A month like emp-0172's first: seventy grant events, most of them reads. */
function floodedMonth(month: number, score: number): RiskPoint {
  const reads = Array.from({ length: 68 }, (_, index) =>
    event({
      month,
      event_id: `evt-read-${index}`,
      description: `AWS read category-${index} on * added`,
      grant_delta: { added: [{ verb: "read" }] },
    }),
  );
  return {
    month,
    score,
    severity: "Critical",
    events: [
      ...reads,
      event({ month, event_id: "evt-admin", description: "AWS admin security on * added", grant_delta: { added: [{ verb: "admin" }] } }),
      event({ month, event_id: "evt-delete", description: "AWS delete storage on * added", grant_delta: { added: [{ verb: "delete" }] } }),
    ],
  };
}

describe("riskAnnotations (SPEC §9.4)", () => {
  it("caps a month at three changes and counts the rest", () => {
    const [annotation] = riskAnnotations([floodedMonth(1, 100)]);

    expect(annotation?.descriptions).toHaveLength(3);
    expect(annotation?.eventCount).toBe(70);
    expect(annotation?.more).toBe(67);
  });

  it("keeps the most significant changes, not the first ones the diff emitted", () => {
    const [annotation] = riskAnnotations([floodedMonth(1, 100)], { maxPerMonth: 2 });

    expect(annotation?.descriptions).toEqual([
      "AWS admin security on * added",
      "AWS delete storage on * added",
    ]);
  });

  it("de-duplicates identical descriptions so the same statement is not listed twice", () => {
    const repeated: RiskPoint = {
      month: 3,
      score: 40,
      severity: "Medium",
      events: Array.from({ length: 25 }, (_, index) =>
        event({ month: 3, event_id: `evt-${index}`, description: "AWS write data on * added" }),
      ),
    };

    const [annotation] = riskAnnotations([repeated]);

    expect(annotation?.descriptions).toEqual(["AWS write data on * added"]);
    expect(annotation?.more).toBe(24);
  });

  it("reports whether the score actually moved", () => {
    const points: RiskPoint[] = [
      { month: 1, score: 12, severity: "Low", events: [] },
      { month: 2, score: 31, severity: "Medium", events: [event({ month: 2, description: "Azure Contributor added" })] },
      { month: 3, score: 31, severity: "Medium", events: [event({ month: 3, description: "AWS read data on * added" })] },
    ];

    const marks = riskAnnotations(points);

    expect(marks.map((mark) => [mark.month, mark.delta, mark.moved])).toEqual([
      [2, 19, true],
      [3, 0, false],
    ]);
  });

  it("prefers the months where the score moved when there are more than the cap", () => {
    const points: RiskPoint[] = Array.from({ length: 8 }, (_, index) => ({
      month: index + 1,
      // Only months 4 and 8 move the score.
      score: index + 1 >= 8 ? 90 : index + 1 >= 4 ? 60 : 10,
      severity: "High",
      events: [event({ month: index + 1, description: `change in month ${index + 1}` })],
    }));

    const marks = riskAnnotations(points, { maxMonths: 2 });

    expect(marks.map((mark) => mark.month)).toEqual([4, 8]);
  });

  it("skips months with no events and stays chronological", () => {
    const points: RiskPoint[] = [
      { month: 1, score: 10, severity: "Low", events: [] },
      { month: 2, score: 20, severity: "Low", events: [event({ month: 2, description: "b" })] },
      { month: 3, score: 30, severity: "Medium", events: [] },
      { month: 4, score: 40, severity: "Medium", events: [event({ month: 4, description: "d" })] },
    ];

    expect(riskAnnotations(points).map((mark) => mark.month)).toEqual([2, 4]);
  });
});
