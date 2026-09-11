import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "./SeverityBadge";
import { SEVERITIES, severityTone } from "./severity";

describe("SeverityBadge", () => {
  it("renders a text label for every severity, not colour alone", () => {
    for (const severity of SEVERITIES) {
      const { unmount } = render(<SeverityBadge severity={severity} />);
      expect(screen.getByText(severity)).toBeInTheDocument();
      unmount();
    }
  });

  it("carries a distinct glyph per level as a second non-colour channel", () => {
    const glyphs = SEVERITIES.map((s) => severityTone(s).glyph);
    expect(new Set(glyphs).size).toBe(SEVERITIES.length);
  });

  it("falls back to Unknown for an unexpected value instead of throwing", () => {
    render(<SeverityBadge severity="catastrophic" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("labels the value for assistive technology", () => {
    render(<SeverityBadge severity="Critical" />);
    expect(screen.getByText("Severity:")).toBeInTheDocument();
  });
});
