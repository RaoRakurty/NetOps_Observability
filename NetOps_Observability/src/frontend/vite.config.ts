// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
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
