// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// coverageModel — the pure adapter layer behind the Telemetry coverage page
// (parser programme A6, UI half).
//
// Everything the page renders about parser health is derived HERE, so the
// honesty rules are unit-testable without a DOM:
//   · a null promotion_rate is "No lines yet" — never 0%.
//   · the four fidelity values map to four distinct, tier-ordered badges; an
//     unknown value degrades to a neutral badge instead of being hidden.
//   · a 403 on the platform-admin stats endpoint is a legitimate ANSWER
//     ("platform-admin only"), not a failure to report as an error.
//   · an empty unrecognized list always carries a reason, never a blank table.

import type { ParserRuleStat, ParserStats, UnrecognizedPage } from "../../services/api";

// ── permissions ─────────────────────────────────────────────────────────────

/**
 * True when an api.ts error is the backend's 403. request() throws
 * `Error("403 Forbidden: <body>")`, so the status prefix is the signal; the
 * word "forbidden" anywhere in the message is accepted as a fallback for
 * proxies that reshape the body.
 */
export function isForbidden(err: string | null | undefined): boolean {
  if (!err) return false;
  return /(^|\s)403(\s|:|$)/.test(err) || err.toLowerCase().includes("forbidden");
}

// ── promotion rate ──────────────────────────────────────────────────────────

export type PromotionDisplay = { value: string; caption: string; unknown: boolean };

/**
 * The hero number. `promotion_rate` is a fraction in [0,1]; null means the
 * window admitted nothing, which is reported as such rather than as 0%.
 */
export function promotionDisplay(stats: Pick<ParserStats, "promotion_rate" | "window_lines">): PromotionDisplay {
  const lines = Number.isFinite(stats.window_lines) ? stats.window_lines : 0;
  if (stats.promotion_rate === null || stats.promotion_rate === undefined) {
    return { value: "—", caption: "No lines yet", unknown: true };
  }
  const pct = Math.max(0, Math.min(1, stats.promotion_rate)) * 100;
  return {
    value: `${pct.toFixed(1)}%`,
    caption: `${lines.toLocaleString("en-US")} line${lines === 1 ? "" : "s"}`,
    unknown: false,
  };
}

// ── fidelity ────────────────────────────────────────────────────────────────

// The tier table moved to lib/fidelity.ts when the RCA evidence rows started
// grading the same rules (A7): one ladder, one set of colours, one tooltip.
// Re-exported here so this page's callers and tests keep their import site.
export { fidelityBadgeClass, fidelityLabel, fidelityTitle, fidelityRank } from "../../lib/fidelity";

// ── rules table ─────────────────────────────────────────────────────────────

/** Defensive unwrap: a malformed payload yields an empty list, never a crash. */
export function ruleRows(stats: ParserStats | null | undefined): ParserRuleStat[] {
  return Array.isArray(stats?.rules) ? stats!.rules : [];
}

/**
 * Header summary of the rule inventory. Shadow rules are counted separately —
 * a shadow rule matches but does not promote, so folding it into the active
 * count would overstate coverage.
 */
export function ruleSummary(rows: ParserRuleStat[]): { total: number; shadow: number; validated: number } {
  return {
    total: rows.length,
    shadow: rows.filter((r) => r.shadow).length,
    validated: rows.filter((r) => r.fidelity === "lab_validated" || r.fidelity === "live_validated").length,
  };
}

// ── unrecognized shapes ─────────────────────────────────────────────────────

/**
 * The honest line under the unrecognized table. A backend `note` always wins
 * (it knows why the list is empty — mining not yet run vs a genuinely clean
 * window); otherwise an empty list gets a truthful default and a populated one
 * gets a count line.
 */
export function unrecognizedNote(page: UnrecognizedPage | null | undefined): string {
  if (!page) return "";
  if (page.note) return page.note;
  const items = Array.isArray(page.items) ? page.items : [];
  if (items.length === 0) return `No unrecognized message shapes in the last ${page.days} days.`;
  const shown = items.length;
  const total = Number.isFinite(page.total) ? page.total : shown;
  return total > shown
    ? `${shown} of ${total} shapes over the last ${page.days} days.`
    : `${shown} shape${shown === 1 ? "" : "s"} over the last ${page.days} days.`;
}

/** Defensive unwrap for the item list (§3: never trust the upstream payload). */
export function unrecognizedItems(page: UnrecognizedPage | null | undefined) {
  return Array.isArray(page?.items) ? page!.items : [];
}

// Syslog numeric severity → the shared sev-* badge vocabulary. Out-of-range
// values fall back to the neutral badge rather than a wrong colour.
const SEV_NAMES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"] as const;
const SEV_CLASS = ["sev-critical", "sev-critical", "sev-critical", "sev-error", "sev-warning", "sev-notice", "sev-info", "sev-debug"];

export function severityLabel(sev: number): string {
  return SEV_NAMES[sev] ?? String(sev);
}

export function severityBadgeClass(sev: number): string {
  return `badge ${SEV_CLASS[sev] ?? "sev-info"}`;
}

// Where a drafted catalog row is landed. One constant so a docs move is one
// line; the UI never applies a row itself, it only points at the PR workflow.
export const CATALOG_DOCS_URL =
  "https://github.com/RaoRakurty/NetOps_Observability/blob/main/NetOps_Observability/docs/INGESTION.md";
