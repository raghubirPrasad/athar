import { describe, expect, it } from "vitest";
import { formatDate, formatHalfLife, formatMonthLabel, formatPct, formatScore, shortHex } from "./format";

describe("formatMonthLabel", () => {
  it("maps month 1 to September 2025, matching athar.clock", () => {
    expect(formatMonthLabel(1)).toBe("September 2025");
  });

  it("maps month 12 to August 2026", () => {
    expect(formatMonthLabel(12)).toBe("August 2026");
  });

  it("keeps rolling past the first simulated year", () => {
    expect(formatMonthLabel(13)).toBe("September 2026");
  });

  it("rejects a month index below 1", () => {
    expect(() => formatMonthLabel(0)).toThrow(RangeError);
  });
});

describe("value formatting", () => {
  it("renders percentages and scores, with an em dash for missing numbers", () => {
    expect(formatPct(29.72, 1)).toBe("29.7%");
    expect(formatPct(null)).toBe("—");
    expect(formatScore(33.5)).toBe("34");
    expect(formatScore(undefined)).toBe("—");
  });

  it("truncates long hex but keeps short values whole", () => {
    const root = `0x${"ab".repeat(32)}`;
    expect(shortHex(root, 6)).toBe("0xababab…ababab");
    expect(shortHex("0xabcd")).toBe("0xabcd");
    expect(shortHex(null)).toBe("—");
  });

  it("formats dates in UTC regardless of locale", () => {
    expect(formatDate("2026-07-24")).toBe("24 Jul 2026");
    expect(formatDate("not-a-date")).toBe("—");
  });
});

describe("formatHalfLife", () => {
  it("renders a median in months, always to one decimal", () => {
    expect(formatHalfLife(5)).toBe("5.0 months");
    expect(formatHalfLife(3.47)).toBe("3.5 months");
  });

  it("says Never when the engine could take no median (SPEC §9.3)", () => {
    expect(formatHalfLife(null)).toBe("Never");
    expect(formatHalfLife(undefined)).toBe("Never");
    expect(formatHalfLife(Number.NaN)).toBe("Never");
  });

  it("abbreviates the unit for dense grids without changing the value", () => {
    expect(formatHalfLife(5, true)).toBe("5.0 mo");
    expect(formatHalfLife(null, true)).toBe("Never");
  });
});
