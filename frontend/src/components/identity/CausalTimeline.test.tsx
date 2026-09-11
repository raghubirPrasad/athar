import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CausalStepOut } from "../../api/types";
import { CausalTimeline } from "./CausalTimeline";

const STEPS: CausalStepOut[] = Array.from({ length: 30 }, (_, index) => ({
  month: (index % 12) + 1,
  event_id: `evt-${index}`,
  kind: "grant",
  trigger: "role_change",
  cloud: "aws",
  description: `AWS write data on * added (${index})`,
  grant_delta: {},
}));

describe("CausalTimeline", () => {
  it("draws the most recent events and offers the full history", () => {
    render(<CausalTimeline steps={STEPS} />);

    expect(screen.getAllByRole("listitem")).toHaveLength(8);
    expect(screen.getByRole("button", { name: "Show full history (30 events)" })).toBeInTheDocument();
  });

  it("draws everything once the reader asks for it, and can fold back", () => {
    render(<CausalTimeline steps={STEPS} />);

    fireEvent.click(screen.getByRole("button", { name: "Show full history (30 events)" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(30);

    fireEvent.click(screen.getByRole("button", { name: "Show the 8 most recent only" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(8);
  });

  it("shows no control when the history already fits", () => {
    render(<CausalTimeline steps={STEPS.slice(0, 3)} />);

    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
