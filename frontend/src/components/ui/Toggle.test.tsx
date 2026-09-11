import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Toggle, type ToggleOption } from "./Toggle";

type Altitude = "headline" | "explanation" | "evidence";

const OPTIONS: ToggleOption<Altitude>[] = [
  { value: "headline", label: "Headline" },
  { value: "explanation", label: "Explanation" },
  { value: "evidence", label: "Evidence" },
];

function renderToggle(value: Altitude = "headline") {
  const onChange = vi.fn();
  render(<Toggle label="Altitude" value={value} options={OPTIONS} onChange={onChange} />);
  return { onChange };
}

const radio = (name: string) => screen.getByRole("radio", { name });

describe("Toggle (altitude segmented control)", () => {
  it("exposes a radiogroup with the selected option checked", () => {
    renderToggle("explanation");
    expect(screen.getByRole("radiogroup", { name: "Altitude" })).toBeInTheDocument();
    expect(radio("Explanation")).toBeChecked();
    expect(radio("Headline")).not.toBeChecked();
  });

  it("moves selection with the arrow keys and wraps around", () => {
    const { onChange } = renderToggle("headline");

    fireEvent.keyDown(radio("Headline"), { key: "ArrowRight" });
    expect(onChange).toHaveBeenLastCalledWith("explanation");

    fireEvent.keyDown(radio("Headline"), { key: "ArrowLeft" });
    expect(onChange).toHaveBeenLastCalledWith("evidence");
  });

  it("supports Home and End", () => {
    const { onChange } = renderToggle("explanation");

    fireEvent.keyDown(radio("Explanation"), { key: "End" });
    expect(onChange).toHaveBeenLastCalledWith("evidence");

    fireEvent.keyDown(radio("Explanation"), { key: "Home" });
    expect(onChange).toHaveBeenLastCalledWith("headline");
  });

  it("moves focus with the selection so the keyboard stays inside the control", () => {
    renderToggle("headline");
    const first = radio("Headline");
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(document.activeElement).toBe(radio("Explanation"));
  });

  it("ignores keys that are not navigation keys", () => {
    const { onChange } = renderToggle("headline");
    fireEvent.keyDown(radio("Headline"), { key: "a" });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("keeps only the selected option in the tab order", () => {
    renderToggle("evidence");
    expect(radio("Evidence")).toHaveAttribute("tabindex", "0");
    expect(radio("Headline")).toHaveAttribute("tabindex", "-1");
  });

  it("selects an option on click", () => {
    const { onChange } = renderToggle("headline");
    fireEvent.click(radio("Evidence"));
    expect(onChange).toHaveBeenCalledWith("evidence");
  });
});
