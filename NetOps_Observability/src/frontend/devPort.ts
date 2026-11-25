// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// devPort — the ONE place the dev-server port is decided, shared by
// vite.config.ts and playwright.config.ts.
//
// Several git worktrees on one host each run their own Playwright suite. With a
// fixed port 3001 and `reuseExistingServer`, a second worktree silently reused
// the FIRST worktree's dev server and tested someone else's code (found
// 2026-11-25). Now: PW_PORT picks the port (default 3001), Vite refuses a busy
// port (strictPort) instead of drifting to the next one, and Playwright reuses
// an already-running server only when asked (PW_REUSE=1) and never in CI.

export const DEFAULT_DEV_PORT = 3001;

type Env = Record<string, string | undefined>;

/** The dev-server port from PW_PORT, else 3001. Rejects anything that is not a
 *  plain integer TCP port, so a typo fails loudly instead of binding elsewhere. */
export function devPort(env: Env = process.env): number {
  const raw = (env.PW_PORT ?? "").trim();
  if (raw === "") return DEFAULT_DEV_PORT;
  if (!/^\d+$/.test(raw)) throw new Error(`PW_PORT must be a TCP port number, got "${raw}"`);
  const port = Number(raw);
  if (port < 1024 || port > 65535) throw new Error(`PW_PORT must be between 1024 and 65535, got ${port}`);
  return port;
}

/** Reuse an already-running dev server only on explicit request, never in CI. */
export function reuseDevServer(env: Env = process.env): boolean {
  return !env.CI && env.PW_REUSE === "1";
}
