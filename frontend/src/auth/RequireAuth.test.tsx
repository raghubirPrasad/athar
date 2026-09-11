import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { UserOut } from "../api/types";
import { AuthContext, type AuthContextValue } from "./context";
import { RequireAuth } from "./RequireAuth";
import { redirectTarget } from "./redirect";

function renderAt(route: string, user: UserOut | null, loading = false) {
  const auth: AuthContextValue = {
    user,
    loading,
    login: () => Promise.reject(new Error("unused")),
    logout: () => Promise.resolve(),
  };
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path="/login" element={<p>Sign in page</p>} />
          <Route element={<RequireAuth />}>
            <Route path="/identities" element={<p>Identity table</p>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

const ANALYST: UserOut = { user_id: "usr-analyst", email: "analyst@athar.local", role: "analyst" };

describe("RequireAuth", () => {
  it("redirects to /login when there is no session", () => {
    renderAt("/identities", null);
    expect(screen.getByText("Sign in page")).toBeInTheDocument();
    expect(screen.queryByText("Identity table")).not.toBeInTheDocument();
  });

  it("renders the route when a session exists", () => {
    renderAt("/identities", ANALYST);
    expect(screen.getByText("Identity table")).toBeInTheDocument();
  });

  it("waits for the /auth/me bootstrap instead of bouncing to login", () => {
    renderAt("/identities", null, true);
    expect(screen.getByLabelText("Checking session")).toBeInTheDocument();
    expect(screen.queryByText("Sign in page")).not.toBeInTheDocument();
  });
});

describe("redirectTarget", () => {
  it("returns a same-origin path and refuses anything else", () => {
    expect(redirectTarget({ from: "/identities?sort=-score" })).toBe("/identities?sort=-score");
    expect(redirectTarget({ from: "//evil.example/steal" })).toBe("/");
    expect(redirectTarget({ from: "https://evil.example" })).toBe("/");
    expect(redirectTarget(null)).toBe("/");
  });

  it("refuses a backslash separator, which a browser reads as a second slash", () => {
    // The open redirect react-router's own advisory describes: `/\evil.example` parses as
    // `//evil.example`, so a leading-slash check alone lets the user off the origin.
    expect(redirectTarget({ from: "/\\evil.example/steal" })).toBe("/");
    expect(redirectTarget({ from: "\\\\evil.example" })).toBe("/");
    expect(redirectTarget({ from: "/\\/evil.example" })).toBe("/");
  });

  it("refuses control characters, which a browser strips before parsing", () => {
    // `/<tab>/evil.example` arrives at the parser as `//evil.example`.
    expect(redirectTarget({ from: "/\t/evil.example" })).toBe("/");
    expect(redirectTarget({ from: "/\n/evil.example" })).toBe("/");
    expect(redirectTarget({ from: "/\r\n//evil.example" })).toBe("/");
    expect(redirectTarget({ from: " //evil.example" })).toBe("/");
  });

  it("still accepts the paths the app actually produces", () => {
    for (const path of [
      "/",
      "/identities",
      "/identities/emp-0093",
      "/findings?rule=R3&severity=High",
      "/timeline?month=12",
      "/ledger",
    ]) {
      expect(redirectTarget({ from: path })).toBe(path);
    }
  });

  it("refuses a non-string or missing from", () => {
    expect(redirectTarget({})).toBe("/");
    expect(redirectTarget({ from: 42 })).toBe("/");
    expect(redirectTarget("/identities")).toBe("/");
    expect(redirectTarget(undefined)).toBe("/");
  });
});
