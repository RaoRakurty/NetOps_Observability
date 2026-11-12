// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// refreshTick — a page-level refresh clock that stops when nobody is looking
// (Flows page redesign P1, 2026-11-12).
//
// The old Flows page gave every panel its own 30 s setInterval, mounted or
// not, visible or not: twelve sections × several queries re-ran every 30 s in
// a background tab. A page that uses this hook owns ONE clock; its panels
// re-read when the tick changes, and only the panels actually on screen are
// mounted. The clock does not run while the document is hidden, and it ticks
// once on return so the operator never looks at numbers that went stale while
// the tab was in the background.

import { createContext, useContext, useEffect, useState } from "react";

/** Visibility, as the browser reports it (true outside a browser). */
export function documentVisible(): boolean {
  return typeof document === "undefined" || document.visibilityState !== "hidden";
}

/**
 * A counter that increases every `intervalMs` while the document is visible
 * and `enabled` holds. Starts at 0; consumers put it in their effect deps.
 */
export function useRefreshTick(intervalMs: number, enabled = true): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    let id: ReturnType<typeof setInterval> | null = null;
    const start = () => {
      if (id === null) id = setInterval(() => setTick((t) => t + 1), intervalMs);
    };
    const stop = () => {
      if (id !== null) {
        clearInterval(id);
        id = null;
      }
    };
    const onVisibility = () => {
      if (documentVisible()) {
        setTick((t) => t + 1); // catch up on what changed while hidden
        start();
      } else {
        stop();
      }
    };
    if (documentVisible()) start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [intervalMs, enabled]);
  return tick;
}

/** The page's clock, for panels below it. 0 outside a provider (no refresh). */
export const RefreshTickContext = createContext(0);

export function usePageTick(): number {
  return useContext(RefreshTickContext);
}
