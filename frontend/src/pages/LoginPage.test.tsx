import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { AuthContext, type AuthContextValue } from "../auth/context";
import { renderWithProviders } from "../test/render";
import { LoginPage } from "./LoginPage";

function renderLogin(login: AuthContextValue["login"]) {
  const auth: AuthContextValue = { user: null, loading: false, login, logout: () => Promise.resolve() };
  return renderWithProviders(
    <AuthContext.Provider value={auth}>
      <LoginPage />
    </AuthContext.Provider>,
    { route: "/login" },
  );
}

function fill(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
}

describe("LoginPage", () => {
  it("submits the form (so Enter in a field signs in too)", async () => {
    const login = vi.fn().mockResolvedValue({ user_id: "usr-analyst", email: "a@athar.local", role: "analyst" });
    renderLogin(login);

    // Implicit submission needs a submit button inside the form; assert both.
    const button = screen.getByRole("button", { name: "Sign in" });
    expect(button).toHaveAttribute("type", "submit");
    const form = button.closest("form");
    expect(form).not.toBeNull();

    fill("analyst@athar.local", "analyst-demo-pass");
    fireEvent.submit(form as HTMLFormElement);

    await waitFor(() => expect(login).toHaveBeenCalledWith("analyst@athar.local", "analyst-demo-pass"));
  });

  it("shows the problem+json title, detail and code inline when sign-in fails", async () => {
    const login = vi
      .fn()
      .mockRejectedValue(
        new ApiError(401, {
          title: "Unauthorized",
          detail: "Invalid email or password",
          code: "auth.invalid_credentials",
        }),
      );
    renderLogin(login);

    fill("analyst@athar.local", "nope");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
    expect(screen.getByText("auth.invalid_credentials")).toBeInTheDocument();
  });

  it("hints the demo emails without ever showing a password", () => {
    renderLogin(vi.fn());
    expect(screen.getByText("analyst@athar.local")).toBeInTheDocument();
    expect(screen.getByText("approver@athar.local")).toBeInTheDocument();
    expect(screen.getByText("judge@athar.local")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("demo-pass");
  });

  it("fills the email field from a demo-account hint", () => {
    renderLogin(vi.fn());
    fireEvent.click(screen.getByText("approver@athar.local"));
    expect(screen.getByLabelText("Email")).toHaveValue("approver@athar.local");
  });
});
