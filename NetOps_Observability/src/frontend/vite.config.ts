// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { devPort } from "./devPort";

export default defineConfig({
  plugins: [react()],
  server: {
    // PW_PORT (default 3001); a busy port is an error, never a silent move to
    // the next one — see devPort.ts.
    port: devPort(),
    strictPort: true,
    proxy: {
      "/api": "http://localhost:8080",
      "/admin": "http://localhost:8080",
    },
  },
  build: {
    outDir: "dist",
    // No sourcemaps in the shipped bundle: they embed the full original source
    // (comments, internal names, logic) and were leaking developer notes +
    // vendor names into the customer artifact (#97). Set VITE_SOURCEMAP=1 for
    // a local debug build.
    sourcemap: process.env.VITE_SOURCEMAP === "1",
  },
});
