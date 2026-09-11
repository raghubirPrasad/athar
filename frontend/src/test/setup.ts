import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

/**
 * jsdom has no ResizeObserver, and recharts' ResponsiveContainer constructs one
 * on mount. A no-op observer is enough: charts render at zero size in tests and
 * the assertions are on the surrounding text, never on the SVG.
 */
class NoopResizeObserver implements ResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

if (!("ResizeObserver" in globalThis)) {
  globalThis.ResizeObserver = NoopResizeObserver;
}

/** jsdom implements neither object-URL function; the export flow uses both. */
if (typeof URL.createObjectURL !== "function") {
  URL.createObjectURL = () => "blob:athar-test";
  URL.revokeObjectURL = () => undefined;
}

afterEach(() => {
  cleanup();
});
