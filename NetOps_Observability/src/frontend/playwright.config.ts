// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig, devices } from "@playwright/test";

// E2E config — drives the real SPA in a headless browser against the Vite dev
// server, with the backend mocked at the network boundary (route interception).
// This proves the operator workflows actually render and behave in a browser
// WITHOUT standing up the 19-service stack (gap-report #2, pragmatic first cut).
// Specs live in ./e2e (outside src/, so vitest never picks them up).
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  use: {
    baseURL: "http://localhost:3001",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3001",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
