// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Test config for the frontend. happy-dom for component rendering (node-18
// friendly); CSS imports are ignored (we assert structure/text, not styles).
// Keeps the prod vite.config untouched.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "happy-dom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
