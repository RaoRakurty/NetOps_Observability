// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// drill.ts — one-shot cross-page "drilldown intent". The Overview sets a filter
// (e.g. show only down devices) that the destination page consumes once on
// mount. Kept out of the hash router so deep-links don't complicate route
// parsing; sessionStorage so it survives the hashchange navigation but not a
// fresh reload.

const KEY = "netops.drill";

export function setDrill(d: Record<string, string>): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(d));
  } catch {
    /* ignore */
  }
}

// takeDrill returns the pending intent and clears it (one-shot).
export function takeDrill(): Record<string, string> {
  try {
    const v = sessionStorage.getItem(KEY);
    if (v) {
      sessionStorage.removeItem(KEY);
      return JSON.parse(v);
    }
  } catch {
    /* ignore */
  }
  return {};
}
