import { defineConfig, mergeConfig } from "vitest/config";

import viteConfig from "./vite.config";

/**
 * Vitest reads this file in preference to vite.config.ts. `mergeConfig` keeps the app config
 * (plugins, aliases) without importing vite's types into vitest's own `UserConfig`, which is what
 * made `tsc -b` fail before. The tests therefore compile the same TypeScript the app does, through
 * the same plugins — the property SPEC §3 gives as the reason for choosing vitest at all.
 */
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      globals: false,
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      css: false,
      restoreMocks: true,
    },
  }),
);
