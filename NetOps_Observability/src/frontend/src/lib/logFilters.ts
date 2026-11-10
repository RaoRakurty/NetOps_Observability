// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// logFilters — the Logs page's summary tiles, filter dropdowns and pager, as pure
// functions (tracker 387). Three rules:
//
//   1. Tiles count what the STORE counted (GET /api/logs/severity-counts), mapped
//      through the one severity map (theme/severity.ts). Nothing here counts the
//      loaded rows: those stay the facets' job, labelled "in these N loaded rows".
//   2. A filter becomes a quoted search clause over a field the index can answer, so
//      it narrows on the server and can never break out of its clause.
//   3. The pager pages through hits.total inside the engine's 10,000-row window and
//      says so; beyond it the export serves the rest.

import type { LogSeverityCounts } from "../services/api";
import { SeverityKey, severityKey } from "../theme/severity";
import { luceneQuote } from "./logEvent";

/** The tiles, in screen order. Notice and debug read as Info; OK reads as Healthy. */
export type SeverityGroup = "critical" | "error" | "warning" | "info" | "ok";

export const SEVERITY_GROUPS: { id: SeverityGroup; label: string; tone: SeverityKey }[] = [
  { id: "critical", label: "Critical", tone: "critical" },
  { id: "error", label: "Error", tone: "error" },
  { id: "warning", label: "Warning", tone: "warning" },
  { id: "info", label: "Info", tone: "info" },
  { id: "ok", label: "Healthy", tone: "ok" },
];

const GROUP_OF: Record<SeverityKey, SeverityGroup> = {
  critical: "critical", error: "error", warning: "warning", notice: "info", info: "info", debug: "info", ok: "ok",
};

export function severityGroupOf(raw: string): SeverityGroup {
  return GROUP_OF[severityKey(raw)];
}

/**
 * The stored words each group stands for, as the stores actually spell them
 * (syslog keywords and numbers, app levels, alarm words). A filter is a match on
 * these exact words, so it finds what the tiles counted.
 */
export const GROUP_WORDS: Record<SeverityGroup, readonly string[]> = {
  critical: ["emerg", "emergency", "alert", "crit", "critical", "fatal", "panic", "0", "1", "2"],
  error: ["err", "error", "major", "3"],
  warning: ["warn", "warning", "minor", "4"],
  info: ["notice", "info", "informational", "debug", "trace", "verbose", "indeterminate", "5", "6", "7"],
  ok: ["ok", "clear", "cleared", "recovered", "resolved", "normal", "up", "healthy", "success"],
};

/** Which severity field each store maps (index-templates.json): app logs use `level`. */
function severityFields(signal: string): string[] {
  if (signal === "applogs") return ["level"];
  if (signal === "syslog" || signal === "snmptrap" || signal === "firewall") return ["severity"];
  if (signal === "flows") return [];
  return ["severity", "level"];
}

/** A quoted clause for one severity group on the chosen store, or "" when it has no severity. */
export function severityGroupClause(group: SeverityGroup, signal: string): string {
  const words = GROUP_WORDS[group].map(luceneQuote).join(" OR ");
  const parts = severityFields(signal).map((f) => `${f}:(${words})`);
  if (parts.length === 0) return "";
  return parts.length === 1 ? parts[0] : `(${parts.join(" OR ")})`;
}

export interface SeverityTile {
  id: SeverityGroup;
  label: string;
  tone: SeverityKey;
  count: number;
}

export interface SeverityTiles {
  tiles: SeverityTile[];
  total: number;
  unrated: number;
  other: number;
  sampled: boolean;
}

/** The store's counts as tiles: every group shown, zero where nothing matched. */
export function tilesFrom(r: LogSeverityCounts | null | undefined): SeverityTiles | null {
  if (!r) return null;
  const by = new Map<SeverityGroup, number>();
  for (const c of r.counts ?? []) {
    if (!c || typeof c.count !== "number" || c.count <= 0) continue;
    const g = severityGroupOf(String(c.value));
    by.set(g, (by.get(g) ?? 0) + c.count);
  }
  return {
    tiles: SEVERITY_GROUPS.map((g) => ({ ...g, count: by.get(g.id) ?? 0 })),
    total: Number(r.total) || 0,
    unrated: Number(r.unrated) || 0,
    other: Number(r.other) || 0,
    sampled: !!r.sampling,
  };
}

/** `field:"value"`, for a dropdown pick. */
export function fieldClause(field: string, value: string): string {
  return `${field}:${luceneQuote(value)}`;
}

/** The operator's query with the dropdown clauses AND-ed on, each parenthesised. */
export function withClauses(query: string, clauses: readonly string[]): string {
  const extra = clauses.filter(Boolean);
  const q = query.trim();
  if (extra.length === 0) return q || "*";
  const base = q === "" || q === "*" ? [] : [`(${q})`];
  return [...base, ...extra.map((c) => (c.startsWith("(") ? c : `(${c})`))].join(" AND ");
}

/** Options for a dropdown from the loaded rows, labelled as such (honest counts). */
export function optionsFrom(values: readonly string[]): { value: string; count: number }[] {
  const m = new Map<string, number>();
  for (const v of values) if (v) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

/** OpenSearch's default max_result_window: from+size may not pass it. */
export const PAGE_WINDOW = 10_000;

export interface PagerState {
  page: number;
  pages: number;
  first: number;
  last: number;
  total: number;
  /** True when total runs past what the engine can page to. */
  capped: boolean;
  /** Page numbers to draw, with null for a gap ("…"). */
  items: (number | null)[];
}

export function pager(total: number, pageSize: number, page: number, shown: number): PagerState {
  const size = Math.max(1, pageSize);
  const reachable = Math.min(total, PAGE_WINDOW);
  const pages = Math.max(1, Math.ceil(reachable / size));
  const p = Math.min(Math.max(1, page), pages);
  const first = total === 0 ? 0 : (p - 1) * size + 1;
  const last = total === 0 ? 0 : Math.min((p - 1) * size + Math.max(shown, 0), total);
  const want = new Set([1, pages, p - 1, p, p + 1]);
  if (p <= 3) [2, 3, 4, 5].forEach((n) => want.add(n));
  if (p >= pages - 2) [pages - 4, pages - 3, pages - 2].forEach((n) => want.add(n));
  const nums = [...want].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
  const items: (number | null)[] = [];
  nums.forEach((n, i) => {
    if (i > 0 && n - nums[i - 1] > 1) items.push(null);
    items.push(n);
  });
  return { page: p, pages, first, last, total, capped: total > PAGE_WINDOW, items };
}
