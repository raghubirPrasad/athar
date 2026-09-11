import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { AuthContext, type AuthContextValue } from "../../auth/context";
import type { EstateSummary } from "../../api/types";
import { TopBar } from "./TopBar";

const SUMMARY = {
  current_month: 12,
  current_month_label: "August 2026",
  ledger: { status: "anchored", last_scan_id: 12 },
} as unknown as EstateSummary;

const AUTH: AuthContextValue = {
  user: { email: "approver@athar.local", role: "approver", user_id: "usr-approver" },
  loading: false,
  login: () => Promise.reject(new Error("not used in this test")),
  logout: () => Promise.resolve(),
};

function renderTopBar() {
  return render(
    <MemoryRouter>
      <AuthContext.Provider value={AUTH}>
        <TopBar summary={SUMMARY} onOpenNav={() => undefined} />
      </AuthContext.Provider>
    </MemoryRouter>,
  );
}

describe("TopBar", () => {
  it("carries the month and the ledger status", () => {
    renderTopBar();

    expect(screen.getByText("August 2026")).toBeInTheDocument();
    expect(screen.getByText(/Ledger: Anchored/)).toBeInTheDocument();
  });

  /**
   * Both badges set `inline-flex` in their own base classes, and Tailwind emits
   * `.inline-flex` after `.hidden`, so a bare `hidden sm:inline-flex` never
   * hides them — it silently overflowed the body at 375 px. The narrow-screen
   * rule has to be a variant, which always sorts later.
   */
  it("hides them below `sm` with a variant, not with a losing `hidden`", () => {
    renderTopBar();

    for (const element of [screen.getByText("August 2026").closest("span"), screen.getByText(/Ledger: Anchored/).closest("a")]) {
      const classes = (element?.className ?? "").split(/\s+/);
      expect(classes).toContain("max-sm:hidden");
      expect(classes).not.toContain("hidden");
    }
  });
});
