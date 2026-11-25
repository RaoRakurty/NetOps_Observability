// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig, devices } from "@playwright/test";
import { devPort, reuseDevServer } from "./devPort";

// E2E config — drives the real SPA in a headless browser against the Vite dev
// server, with the backend mocked at the network boundary (route interception).
// This proves the operator workflows actually render and behave in a browser
// WITHOUT standing up the 19-service stack (gap-report #2, pragmatic first cut).
// Specs live in ./e2e (outside src/, so vitest never picks them up).
//
// Parallel worktrees: give each its own port — `PW_PORT=3017 npm run e2e`. An
// already-running dev server is reused only with PW_REUSE=1 (never in CI), so a
// run can never silently test another worktree's code (devPort.ts).
const PORT = devPort();
const BASE = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  use: {
    baseURL: BASE,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npm run dev -- --port ${PORT} --strictPort`,
    url: BASE,
    reuseExistingServer: reuseDevServer(),
    timeout: 120_000,
  },
});
