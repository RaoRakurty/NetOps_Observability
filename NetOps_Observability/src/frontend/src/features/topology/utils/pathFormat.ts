// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// pathFormat — shared value formatters for the path surfaces (NetworkPathView
// ribbon + PathAnalysisPanel hop ladder), so both rails render the same number the
// same way. Pure functions, no UI.

/** Format a millisecond value compactly: sub-ms as µs, else 1-decimal ms. */
export function fmtMs(v: number): string {
  if (v < 1) return `${Math.round(v * 1000)} µs`;
  return `${v.toFixed(v < 10 ? 1 : 0)} ms`;
}

/** Mbps → human bitrate: Gbps when ≥1000, Kbps when <1, else Mbps (#85). */
export function fmtMbps(v: number): string {
  if (v >= 1000) return `${(v / 1000).toFixed(v % 1000 ? 1 : 0)} Gbps`;
  if (v < 1) return `${Math.round(v * 1000)} Kbps`;
  return `${v.toFixed(v < 10 ? 1 : 0)} Mbps`;
}
