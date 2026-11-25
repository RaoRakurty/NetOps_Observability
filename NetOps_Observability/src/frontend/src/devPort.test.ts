// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { devPort, reuseDevServer, DEFAULT_DEV_PORT } from "../devPort";

describe("dev-server port (parallel worktrees never share a server)", () => {
  it("defaults to 3001 and honours PW_PORT", () => {
    expect(devPort({})).toBe(DEFAULT_DEV_PORT);
    expect(devPort({ PW_PORT: "3017" })).toBe(3017);
    expect(devPort({ PW_PORT: " 3018 " })).toBe(3018);
  });

  it("refuses a malformed or out-of-range port instead of binding elsewhere", () => {
    expect(() => devPort({ PW_PORT: "30a1" })).toThrow(/TCP port/);
    expect(() => devPort({ PW_PORT: "80" })).toThrow(/between/);
    expect(() => devPort({ PW_PORT: "70000" })).toThrow(/between/);
  });

  it("reuses a running server only on explicit request, and never in CI", () => {
    expect(reuseDevServer({})).toBe(false);
    expect(reuseDevServer({ PW_REUSE: "1" })).toBe(true);
    expect(reuseDevServer({ PW_REUSE: "1", CI: "true" })).toBe(false);
    expect(reuseDevServer({ CI: "true" })).toBe(false);
  });

  it("both configs read the shared rule; Vite never drifts to another port", () => {
    const root = resolve(__dirname, "..");
    const vite = readFileSync(resolve(root, "vite.config.ts"), "utf8");
    const pw = readFileSync(resolve(root, "playwright.config.ts"), "utf8");
    expect(vite).toMatch(/port:\s*devPort\(\)/);
    expect(vite).toMatch(/strictPort:\s*true/);
    expect(pw).toMatch(/reuseExistingServer:\s*reuseDevServer\(\)/);
    expect(pw).toMatch(/--strictPort/);
    expect(pw).not.toMatch(/localhost:3001/);
  });
});
