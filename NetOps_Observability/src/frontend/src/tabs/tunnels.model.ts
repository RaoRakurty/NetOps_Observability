// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tunnels.model.ts — the pure half of the Tunnels page (Paths P4, 2026-11-21).
//
// /api/tunnels returns ONE row per SD-WAN tunnel (both ends folded under the
// correlation engine's tunnel id) with the controller's path quality, the open
// case naming the tunnel and both ends' sites; `?include=matrix` adds a site ×
// site matrix built on the server over every visible tunnel. This file turns
// that into what the page draws: the matrix grid, a cell's tone, the "as of"
// text for quality that is 30–60 minutes behind, and the row filter a matrix
// cell applies. No React, no IO — every rule here is unit-tested.

import type { Tunnel, TunnelEnd, TunnelMatrix, TunnelMatrixCell, TunnelMatrixSite } from "../services/api";
import { fmtTime, type TzMode } from "../lib/time";

export type Tone = "good" | "warn" | "bad" | "muted";

/** A transport state's tone: down is bad, ends that disagree warn, up is good. */
export function stateTone(state: string | undefined | null): Tone {
  switch ((state ?? "").toLowerCase()) {
    case "up": return "good";
    case "disagree": return "warn";
    case "down": return "bad";
    default: return "muted";
  }
}

/** The plain word for a tunnel state. "disagree" names what the operator sees. */
export function stateLabel(state: string | undefined | null): string {
  switch ((state ?? "").toLowerCase()) {
    case "up": return "up";
    case "down": return "down";
    case "disagree": return "ends disagree";
    default: return "unknown";
  }
}

const STATE_RANK: Record<string, number> = { down: 3, disagree: 2, up: 1 };
const rank = (s: string | undefined) => STATE_RANK[(s ?? "").toLowerCase()] ?? 0;

/** Ascending sort key that puts the trouble first: down, disagree, up, unknown. */
export function stateOrder(state: string | undefined | null): number {
  const r = rank(state ?? undefined);
  return r ? 3 - r : 3;
}

/** A row's state: the folded `state` when the server sent one, else the legacy status. */
export function rowState(t: Tunnel): string {
  return t.state || t.status || "";
}

export interface MatrixGrid {
  /** Sites in draw order: worst cell first, then most tunnels, then label. */
  sites: TunnelMatrixSite[];
  /** The cell between two sites, whichever order they are asked in. */
  cellAt: (a: string, b: string) => TunnelMatrixCell | undefined;
}

/**
 * The matrix as a grid. The server sends sparse cells with a <= b; the grid is
 * symmetric, so a lookup in either order finds the same cell. Sites are ordered
 * so the trouble is at the top left: the worst state of any cell the site is
 * in, then the number of tunnels it terminates, then the label (stable).
 */
export function matrixGrid(m: TunnelMatrix | null | undefined): MatrixGrid {
  const cells = m?.cells ?? [];
  const byPair = new Map<string, TunnelMatrixCell>();
  const worst = new Map<string, number>();
  const count = new Map<string, number>();
  for (const c of cells) {
    byPair.set(`${c.a}\u0000${c.b}`, c);
    byPair.set(`${c.b}\u0000${c.a}`, c);
    for (const s of c.a === c.b ? [c.a] : [c.a, c.b]) {
      worst.set(s, Math.max(worst.get(s) ?? 0, rank(c.state)));
      count.set(s, (count.get(s) ?? 0) + c.tunnels);
    }
  }
  const sites = [...(m?.sites ?? [])].sort((x, y) =>
    (worst.get(y.key) ?? 0) - (worst.get(x.key) ?? 0)
    || (count.get(y.key) ?? 0) - (count.get(x.key) ?? 0)
    || x.label.localeCompare(y.label)
    || x.key.localeCompare(y.key));
  return { sites, cellAt: (a, b) => byPair.get(`${a}\u0000${b}`) };
}

/**
 * A matrix cell as the table filter it applies. `ra`/`rb` are the cell's opaque
 * site keys, which rows carry as `site.ref`; `a`/`b` are the labels, used only
 * for a row without refs (labels are not unique: two tenants can both have "HQ").
 */
export interface CellFilter {
  a: string;
  b: string;
  ra?: string;
  rb?: string;
}

export function cellFilter(m: TunnelMatrix | null | undefined, cell: TunnelMatrixCell): CellFilter | null {
  const label = (key: string) => m?.sites.find((s) => s.key === key)?.label;
  const a = label(cell.a);
  const b = label(cell.b);
  return a && b ? { a, b, ra: cell.a, rb: cell.b } : null;
}

const endSite = (e: TunnelEnd | undefined) => e?.site?.label ?? "";
const endRef = (e: TunnelEnd | undefined) => e?.site?.ref ?? "";

/**
 * Whether a row belongs to a matrix cell, in either direction; an intra-site
 * cell needs both ends at that site. When the row's ends carry the matrix's
 * site refs the match is exact on them; only a row without refs falls back to
 * the label pair.
 */
export function rowInCell(t: Tunnel, f: CellFilter): boolean {
  const ra = endRef(t.a);
  const rb = endRef(t.b);
  if (ra && rb && f.ra && f.rb) {
    return (ra === f.ra && rb === f.rb) || (ra === f.rb && rb === f.ra);
  }
  const a = endSite(t.a);
  const b = endSite(t.b);
  if (!a || !b) return false;
  return (a === f.a && b === f.b) || (a === f.b && b === f.a);
}

/**
 * "as of 16:30 (40 min ago)" for a reading taken at `iso`. Controller path
 * quality settles 30 minutes and arrives in 10-minute buckets, so the age is
 * part of the reading. Returns "" for a missing or unreadable time.
 */
export function asOfText(iso: string | null | undefined, now: Date = new Date(), mode?: TzMode): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const clock = fmtTime(new Date(t), { label: false, mode }).slice(0, 5);
  return `as of ${clock} (${agoText(now.getTime() - t)})`;
}

/** "just now", "12 min ago", "3 h ago" — never negative (a clock ahead reads "just now"). */
export function agoText(ms: number): string {
  const min = Math.floor(Math.max(0, ms) / 60_000);
  if (min < 1) return "just now";
  if (min < 120) return `${min} min ago`;
  return `${Math.floor(min / 60)} h ago`;
}

/**
 * The OLDEST quality reading across rows — the honest "as of" for a summary
 * that averages them. Null when no row carries a reading.
 */
export function oldestQualityAsOf(rows: Tunnel[]): string | null {
  let oldest: number | null = null;
  let iso: string | null = null;
  for (const r of rows) {
    const s = r.quality?.as_of;
    if (!s) continue;
    const t = Date.parse(s);
    if (Number.isFinite(t) && (oldest === null || t < oldest)) {
      oldest = t;
      iso = s;
    }
  }
  return iso;
}

/** The deep link a case chip opens: the RCA workspace on that object. */
export function caseHref(id: string): string {
  return `#/investigate/rca?id=${encodeURIComponent(id)}`;
}

/** One end as text: device (or its system-ip when the device is not visible) and colour. */
export function endText(e: TunnelEnd | undefined, fallbackDevice = ""): string {
  const who = e?.device || e?.system_ip || fallbackDevice || "—";
  return e?.color ? `${who} · ${e.color}` : who;
}

/** Everything a search box should find in a row. */
export function searchText(t: Tunnel): string {
  return [
    t.id, t.type, t.tunnel_id, t.local_device, t.local_addr, t.remote_device, t.remote_addr,
    rowState(t), t.a?.device, t.a?.system_ip, t.a?.color, endSite(t.a),
    t.b?.device, t.b?.system_ip, t.b?.color, endSite(t.b),
  ].filter(Boolean).join(" ").toLowerCase();
}
