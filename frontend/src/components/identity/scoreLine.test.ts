import { describe, expect, it } from "vitest";
import type { ScoreOut } from "../../api/types";
import { SCORE, SCORE_COMPENSATED, SCORE_FLOORED } from "../../test/fixtures";
import { scoreLine, transparencyLine } from "./scoreLine";

/** The score the printed line claims, recomputed from the printed pieces. */
function arithmeticOf(score: ScoreOut): number {
  const line = scoreLine(score);
  const product = line.factors.reduce((acc, factor) => acc * factor.value, 100);
  expect(Math.round(product)).toBe(line.formula);
  return Math.max(0, Math.min(100, Math.round(Math.max(product, score.rule_floor))));
}

describe("scoreLine (SPEC §8.3)", () => {
  it("renders the SPEC form: three factors, their product, the floor, the score", () => {
    expect(transparencyLine(SCORE_FLOORED)).toBe(
      "reach 0.02 (blast radius 1% of estate, 0 high-sensitivity resources) × " +
        "exploitability 1.8 (departed +0.5, dormant +0.3) × controls 1.0 = 4 · floor from R3 = 75 → 75",
    );
  });

  it("folds a factor's sub-terms into one parenthetical instead of multiplying them", () => {
    const line = scoreLine(SCORE_FLOORED);

    expect(line.factors).toHaveLength(3);
    expect(line.factors.map((factor) => factor.name)).toEqual(["reach", "exploitability", "controls"]);
    // "departed +0.5" and "dormant +0.3" are sub-terms of exploitability, not factors.
    expect(line.text.split(" × ")).toHaveLength(3);
    expect(line.factors[1]?.text).toBe("exploitability 1.8 (departed +0.5, dormant +0.3)");
  });

  it("never prints a sub-term marker such as 'base' or 'none' as a factor", () => {
    for (const score of [SCORE, SCORE_FLOORED, SCORE_COMPENSATED]) {
      const line = scoreLine(score);
      expect(line.text).not.toMatch(/× (base|none|total)\b/);
      expect(line.factors.some((factor) => factor.text.startsWith("none"))).toBe(false);
    }
  });

  it("says 'no floor' when no rule floor applied", () => {
    const line = scoreLine(SCORE_COMPENSATED);

    expect(line.floor).toBe("no floor");
    expect(line.text).toContain("· no floor →");
    expect(line.text).not.toContain("floor from");
  });

  it("shows a compensating credit under controls, with the multiplier it produced", () => {
    expect(scoreLine(SCORE_COMPENSATED).factors[2]?.text).toBe(
      "controls 0.65 (break-glass (register, MFA enforced) −0.35)",
    );
  });

  it("says the score was capped when the product exceeds 100", () => {
    const line = scoreLine(SCORE);

    expect(line.capped).toBe(true);
    expect(line.formula).toBe(120);
    expect(line.text).toContain("· capped at 100 → 100");
  });

  it("prints arithmetic that holds for every captured score", () => {
    for (const score of [SCORE, SCORE_FLOORED, SCORE_COMPENSATED]) {
      expect(arithmeticOf(score)).toBe(score.score);
      expect(scoreLine(score).text.endsWith(`→ ${score.score}`)).toBe(true);
    }
  });

  it("keeps working when the engine sends no line items at all", () => {
    const bare: ScoreOut = { ...SCORE_COMPENSATED, line_items: [] };

    expect(transparencyLine(bare)).toBe(
      "reach 1.0 (blast radius 69% of estate, 87 high-sensitivity resources) × " +
        "exploitability 1.0 × controls 0.65 = 65 · no floor → 65",
    );
  });

  it("falls back to an unattributed floor when the floor item carries no rule", () => {
    const unattributed: ScoreOut = {
      ...SCORE_FLOORED,
      line_items: SCORE_FLOORED.line_items.map((item) =>
        item.term === "floor" ? { ...item, label: "none" } : item,
      ),
    };

    expect(scoreLine(unattributed).floor).toBe("floor = 75");
  });
});
