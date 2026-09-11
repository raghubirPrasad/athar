import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeBlock } from "./CodeBlock";

const ROOT = "0x6920bf9280476eed8fd2250ebc7b11548d3a2d6b69d9cc9dbd6142e0b13a0a7b";

function withClipboard(writeText: (() => Promise<void>) | null) {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: writeText ? { writeText } : undefined,
  });
}

afterEach(() => {
  withClipboard(null);
  vi.restoreAllMocks();
});

describe("CodeBlock", () => {
  it("copies the full value, not the truncated one on screen", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    withClipboard(writeText);
    render(<CodeBlock inline value={ROOT} label="root" />);

    fireEvent.click(screen.getByRole("button", { name: /Copy root/ }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(ROOT));
  });

  it("says the clipboard was blocked instead of doing nothing", async () => {
    withClipboard(() => Promise.reject(new Error("denied")));
    render(<CodeBlock value={ROOT} label="root" />);

    fireEvent.click(screen.getByRole("button", { name: "Copy" }));

    expect(await screen.findByRole("button", { name: "Copy blocked" })).toBeInTheDocument();
  });
});
