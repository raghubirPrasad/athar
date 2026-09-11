import type { LineItemOut, ScoreOut } from "../../api/types";

/**
 * Sub-item labels that are not modifiers of their term: the base value the term
 * starts from, the term's own summary row, and the "nothing applied" marker.
 * Mirrors `_modifiers` in backend/athar/narrative/templates.py.
 */
const NOT_A_MODIFIER: Record<string, readonly string[]> = {
  exploitability: ["base", "exploitability", "total"],
  compensating: ["compensating", "controls", "total", "none"],
};

/** `1.0`, `1.8`, `0.02` — two decimals with trailing zeros trimmed to one. */
function num(value: number): string {
  const fixed = value.toFixed(2).replace(/0+$/, "");
  return fixed.endsWith(".") ? `${fixed}0` : fixed;
}

function pct(share: number): number {
  return Math.max(0, Math.min(100, Math.round(share * 100)));
}

function modifiers(items: readonly LineItemOut[], term: keyof typeof NOT_A_MODIFIER): string[] {
  const skip = NOT_A_MODIFIER[term] ?? [];
  return items
    .filter((item) => item.term === term && item.label.length > 0)
    .filter((item) => !skip.some((prefix) => item.label.toLowerCase().startsWith(prefix)))
    .map((item) => item.label);
}

/** `exploitability 1.8 (departed +0.5, dormant +0.3)`; bare when nothing applied. */
function termText(name: string, value: number, mods: readonly string[]): string {
  return mods.length > 0 ? `${name} ${num(value)} (${mods.join(", ")})` : `${name} ${num(value)}`;
}

function floorText(score: ScoreOut): string {
  if (score.rule_floor <= 0) return "no floor";
  const source = (score.line_items.find((item) => item.term === "floor" && item.label)?.label ?? "")
    .replace(/^floor\s+(from\s+)?/i, "")
    .trim();
  const named = source.length > 0 && source.toLowerCase() !== "none";
  return named ? `floor from ${source} = ${score.rule_floor}` : `floor = ${score.rule_floor}`;
}

/** One factor of the product, with its own sub-terms folded into a parenthetical. */
export interface ScoreFactor {
  /** `reach` · `exploitability` · `controls`. */
  name: string;
  /** The multiplier itself, as it appears in the product. */
  value: number;
  /** `reach 0.02 (blast radius 1% of estate, 0 high-sensitivity resources)`. */
  text: string;
}

export interface ScoreLine {
  /** Multiplied together, in order, to give `formula`. */
  factors: ScoreFactor[];
  /** `100 × reach × exploitability × controls`, rounded as printed. */
  formula: number;
  /** `floor from R3 = 75`, or `no floor` when no rule floor applied. */
  floor: string;
  /** True when `max(formula, floor)` exceeded 100 and the score was clamped. */
  capped: boolean;
  /** The score the engine stored. */
  score: number;
  /** The whole thing as the single line of SPEC §8.3. */
  text: string;
}

/**
 * The transparency line of SPEC §8.3, built the way the engine builds it
 * (backend/athar/narrative/templates.py::render_score_line): three factors whose
 * sub-terms are folded into a parenthetical, their product, the rule floor, and
 * the score. The printed arithmetic holds — `100 × reach × exploitability ×
 * controls = formula`, then `max(formula, floor)` clamped to 100 — because every
 * factor here is the multiplier the engine used, never a sub-term of one.
 */
export function scoreLine(score: ScoreOut): ScoreLine {
  const items = score.line_items;
  const controls = 1 - score.compensating;
  const factors: ScoreFactor[] = [
    {
      name: "reach",
      value: score.reach,
      text:
        `reach ${num(score.reach)} (blast radius ${pct(score.blast_radius)}% of estate, ` +
        `${score.high_sensitivity_reached} high-sensitivity resources)`,
    },
    {
      name: "exploitability",
      value: score.exploitability,
      text: termText("exploitability", score.exploitability, modifiers(items, "exploitability")),
    },
    {
      name: "controls",
      value: controls,
      text: termText("controls", controls, modifiers(items, "compensating")),
    },
  ];

  const formula = Math.round(score.formula_score);
  const floor = floorText(score);
  const capped = Math.round(Math.max(score.formula_score, score.rule_floor)) > 100;
  const parts = [factors.map((factor) => factor.text).join(" × "), `= ${formula}`, `· ${floor}`];
  if (capped) parts.push("· capped at 100");

  return {
    factors,
    formula,
    floor,
    capped,
    score: score.score,
    text: `${parts.join(" ")} → ${score.score}`,
  };
}

/** The §8.3 line as a string, for the one place that only needs the sentence. */
export function transparencyLine(score: ScoreOut): string {
  return scoreLine(score).text;
}
