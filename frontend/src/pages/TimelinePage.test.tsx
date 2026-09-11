import { act, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HALFLIFE, TIMELINE } from "../test/fixtures";
import { renderWithProviders } from "../test/render";
import { TimelinePage } from "./TimelinePage";

vi.mock("../api/endpoints", () => ({
  getTimeline: () => Promise.resolve(TIMELINE),
  getHalfLife: () => Promise.resolve(HALFLIFE),
}));

afterEach(() => {
  vi.useRealTimers();
});

describe("TimelinePage", () => {
  it("opens on the latest month with that month's numbers", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline" });

    const readout = await screen.findByRole("status", { name: "Selected month" });
    expect(readout).toHaveTextContent("November 2025");
    expect(readout).toHaveTextContent("month 3");
    expect(screen.getByRole("slider")).toHaveValue("3");
  });

  it("advances the month while playing and stops when a person pauses it", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline" });
    const readout = await screen.findByRole("status", { name: "Selected month" });

    vi.useFakeTimers();
    // Play from the end restarts at month 1, then steps once per interval.
    fireEvent.click(screen.getByRole("button", { name: "Play" }));
    expect(readout).toHaveTextContent("September 2025");

    act(() => void vi.advanceTimersByTime(1000));
    expect(readout).toHaveTextContent("October 2025");

    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    act(() => void vi.advanceTimersByTime(5000));
    expect(readout).toHaveTextContent("October 2025");
  });

  it("stops on its own at the last month rather than looping", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?month=1" });
    const readout = await screen.findByRole("status", { name: "Selected month" });

    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Play" }));
    // Each step schedules the next one from an effect, so let five ticks run.
    for (let step = 0; step < 5; step += 1) act(() => void vi.advanceTimersByTime(1000));

    expect(readout).toHaveTextContent("November 2025");
    expect(screen.getByRole("button", { name: "Play" })).toBeInTheDocument();
  });

  it("keeps the month in the URL, so the slider is a shareable position", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?month=1" });

    const readout = await screen.findByRole("status", { name: "Selected month" });
    expect(readout).toHaveTextContent("September 2025");
    expect(screen.getByText("In the estate in September 2025")).toBeInTheDocument();
  });

  it("renders the half-life table with the engine's own diagnosis", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline" });

    expect((await screen.findAllByText("Offboarding")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Never").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Broken").length).toBeGreaterThan(0);
  });

  it("opens on one department when a half-life number elsewhere linked here", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?department=Finance" });

    const table = await screen.findByRole("table");
    // Finance's two rows plus the estate-wide baseline, and nobody else's.
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).queryByText("Data Services")).not.toBeInTheDocument();
    expect(within(table).getAllByText("All departments")).toHaveLength(1);
  });

  it("names the selection in the table's own subtitle, not by highlight alone", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?department=Finance" });

    expect(
      await screen.findByText("Finance, with the estate-wide baseline for comparison"),
    ).toBeInTheDocument();
  });

  it("offers a way back to every department and takes it out of the URL", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?department=Finance" });

    fireEvent.click(await screen.findByRole("button", { name: "Showing Finance — show all departments" }));

    const table = await screen.findByRole("table");
    expect(within(table).getByText("Data Services")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /show all departments/ })).not.toBeInTheDocument();
  });

  it("makes each department in the month grid a link that selects it", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?month=3" });

    const finance = await screen.findByRole("link", { name: /Finance\s*Never/ });
    expect(finance).toHaveAttribute("href", "/timeline?month=3&department=Finance");
    expect(screen.getByRole("link", { name: /Data Services\s*1\.3 mo/ })).toHaveAttribute(
      "href",
      "/timeline?month=3&department=Data%20Services",
    );
  });

  it("shows the empty state, not everyone else's rows, for a department with no data", async () => {
    renderWithProviders(<TimelinePage />, { route: "/timeline?department=Contractors" });

    expect(await screen.findByText("No half-life data for Contractors")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
