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
//   · a vendor with no tested samples reads "Not covered yet", never 0% parsed.
//   · no live reading and no lines are different facts, and both differ from 0%.

import type { ParserRuleStat, ParserStats, UnrecognizedPage, VendorLaneStats, VendorScore } from "../../services/api";

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

// ── vendor scorecard ────────────────────────────────────────────────────────

export const NOT_COVERED = "Not covered yet";

/** Defensive unwrap, and an API older than this page simply has no rows. */
export function vendorRows(stats: ParserStats | null | undefined): VendorScore[] {
  return Array.isArray(stats?.vendors) ? stats!.vendors! : [];
}

const VALIDATED = new Set(["lab_validated", "live_validated"]);

const n = (v: number) => v.toLocaleString("en-US");
const plural = (v: number, one: string, many: string) => `${n(v)} ${v === 1 ? one : many}`;

function ruleCounts(lane: VendorLaneStats): { total: number; proven: number } {
  const rules = lane.rules ?? {};
  let total = 0;
  let proven = 0;
  for (const [fidelity, count] of Object.entries(rules)) {
    total += count;
    if (VALIDATED.has(fidelity)) proven += count;
  }
  return { total, proven };
}

/** What we can read, in words. A lane with no tested sample is not covered,
 *  whatever else exists for it: a definition nobody has tested is not coverage. */
export function laneCapability(lane: VendorLaneStats | undefined, kind: "syslog" | "snmptrap"): string {
  if (!lane || !lane.fixtures) return NOT_COVERED;
  const tested = `${n(lane.fixtures)} tested`;
  if (kind === "syslog") return `${plural(lane.grammars, "format", "formats")}, ${tested}`;
  return `${plural(lane.mib_nodes, "name", "names")}, ${tested}`;
}

export function ruleSummaryOf(row: VendorScore): string {
  const a = ruleCounts(row.lanes.syslog);
  const b = ruleCounts(row.lanes.snmptrap);
  const total = a.total + b.total;
  if (total === 0) return "None yet";
  const proven = a.proven + b.proven;
  return proven > 0 ? `${n(total)}, ${n(proven)} proven on a device` : `${n(total)}, none proven yet`;
}

/** What we read today. The order of the checks is the honesty: no reading, then
 *  no lines, then not covered; a percentage only for a lane that can earn one. */
export function liveReading(row: VendorScore, kind: "syslog" | "snmptrap"): string {
  const lane = row.lanes[kind];
  const unit = kind === "syslog" ? "line" : "trap";
  if (!lane?.live) return "No reading";
  const { total, read } = lane.live;
  if (!total) return `No ${unit}s yet`;
  const seen = plural(total, unit, `${unit}s`);
  if (!lane.fixtures && !row.unidentified) return `${seen}, ${NOT_COVERED.toLowerCase()}`;
  // Rounded down: a lane with one line unread must not read as a clean 100%.
  const pct = Math.floor(Math.max(0, Math.min(1, read / total)) * 1000) / 10;
  return `${pct === 100 || read === 0 ? pct.toFixed(0) : pct.toFixed(1)}% read of ${seen}`;
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
