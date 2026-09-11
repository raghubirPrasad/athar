import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// Dev-only proxy: the browser talks to the Vite origin and Vite forwards
// /api → the FastAPI dev server, so the httpOnly cookie is same-site in dev
// exactly as it is behind nginx in production (frontend/nginx.conf).
// `API_PORT` is the same variable the backend reads (.env); export it when the
// API is not on its default port. Dev tooling only — nothing ships with this.
// Declared locally rather than pulling in @types/node for two reads.
declare const process: { env: Record<string, string | undefined> };

const API_DEV_PORT = process.env.API_PORT ?? "8000";
const API_DEV_TARGET = process.env.API_DEV_TARGET ?? `http://localhost:${API_DEV_PORT}`;

// Test configuration lives in vitest.config.ts, which merges this one. Vitest and the app now
// share a single deduped vite, so the two could in principle be one file; they are kept apart
// because `defineConfig` from "vitest/config" widens the type `tsc -b` checks this file against.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: API_DEV_TARGET, changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Charts are the heaviest dependency and change least often; keeping
        // them in their own chunk stops one page's edit invalidating them.
        manualChunks: {
          charts: ["recharts"],
          vendor: ["react", "react-dom", "react-router-dom", "@tanstack/react-query", "@tanstack/react-table"],
        },
      },
    },
  },
});
