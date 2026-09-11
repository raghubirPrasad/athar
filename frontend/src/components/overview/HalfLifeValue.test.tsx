import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { HalfLifeLabel } from "../../api/types";
import { renderWithProviders as render } from "../../test/render";
import { HalfLifeValue } from "./HalfLifeValue";

describe("HalfLifeValue", () => {
  it("renders the months and the engine's diagnosis", () => {
    render(<HalfLifeValue months={3.5} label="Healthy" />);

    expect(screen.getByText("3.5 months")).toBeInTheDocument();
    expect(screen.getByText("Healthy")).toBeInTheDocument();
  });

  it("says Never when no median could be taken", () => {
    render(<HalfLifeValue months={null} label="Broken" />);

    expect(screen.getByText("Never")).toBeInTheDocument();
  });

  it("survives a diagnosis label this build does not know", () => {
    // A backend that adds a fourth label must not unmount the Overview.
    const future = "Stalled" as HalfLifeLabel;

    expect(() => render(<HalfLifeValue months={12} label={future} />)).not.toThrow();
    expect(screen.getByText("Stalled")).toBeInTheDocument();
  });

  it("becomes a link to its evidence when a destination is given (PRD §8.2)", () => {
    render(<HalfLifeValue months={5} label="Slow" to="/timeline?department=Finance" linkLabel="Half-life evidence for Finance" />);

    const link = screen.getByRole("link", { name: "Half-life evidence for Finance" });
    expect(link).toHaveAttribute("href", "/timeline?department=Finance");
    expect(link).toHaveTextContent("5.0 months");
    expect(link).toHaveTextContent("Slow");
  });

  it("links Never too — it is the headline number, not a missing one", () => {
    render(<HalfLifeValue months={null} label="Broken" to="/timeline?department=HR" linkLabel="Half-life evidence for HR" />);

    expect(screen.getByRole("link", { name: "Half-life evidence for HR" })).toHaveTextContent("Never");
  });

  it("stays plain text where the page already is the evidence", () => {
    render(<HalfLifeValue months={3} label="Healthy" />);

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
