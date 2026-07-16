// Semantic sort ranks for the Cloud Service View tables (2026-07 UX pass).
//
// DataTable sorts a column by its `sortValue` accessor. For status/severity/
// confidence/verdict columns a raw string sort is meaningless ("degraded" < "down"
// alphabetically, which is not the operator ordering). These helpers give a stable
// numeric rank so ascending sort surfaces the most urgent / strongest row first —
// the same idea as theme/severity.ts::severityRank, reused across every table here.

import type { Confidence, Health } from "./types";

// Health, worst-first: down → degraded → unknown → healthy.
const HEALTH_RANK: Record<Health, number> = { down: 0, degraded: 1, unknown: 2, healthy: 3 };
export function healthRank(h: Health): number {
  return HEALTH_RANK[h] ?? 2;
}

// Confidence, strongest-first: confirmed → strong → suspected → weak → unknown.
const CONF_RANK: Record<Confidence, number> = {
  confirmed: 0, strong: 1, suspected: 2, weak: 3, unknown: 4,
};
export function confidenceRank(c: Confidence): number {
  return CONF_RANK[c] ?? 4;
}

// Engine verdict tiers, most-actionable-first (mirrors the RCA ladder).
const VERDICT_RANK: Record<string, number> = {
  confirmed: 0, suspected: 1, recovered: 2, contradicted: 3, undetermined: 4,
};
export function verdictRank(tier: string): number {
  return VERDICT_RANK[tier] ?? 5;
}

// ISO timestamp → epoch ms, so a Time column sorts chronologically (not lexically).
// A missing/invalid time sorts oldest.
export function timeRank(iso?: string): number {
  if (!iso) return 0;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}
