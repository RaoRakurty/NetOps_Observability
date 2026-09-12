// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Resolve a CSS design token to its concrete value for consumers that can't
// use `var()` strings (ECharts canvas renderer, SVG attribute math, etc.).
// Reads the live cascade, so [data-theme]/[data-chrome] swaps are honored at
// the next chart rebuild.
export function cssVar(name: string, fallback: string): string {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch {
    return fallback;
  }
}
