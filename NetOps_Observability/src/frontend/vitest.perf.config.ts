// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Render-budget config — deliberately SEPARATE from vitest.config.ts so the
// normal suite stays fast and the budget run stays serial (parallel workers
// would make the timings meaningless). `npm run perf:budget`.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "happy-dom",
    globals: true,
    setupFiles: ["./perf/setup.ts"],
    css: false,
    include: ["perf/**/*.perf.tsx"],
    // One file, one worker, no concurrency: measurements must not contend.
    // Vitest 4 removed `poolOptions`; its single-thread knob is now top-level
    // `maxWorkers: 1` (was poolOptions.threads.{singleThread,maxThreads,minThreads}).
    pool: "threads",
    maxWorkers: 1,
    fileParallelism: false,
    sequence: { concurrent: false },
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
