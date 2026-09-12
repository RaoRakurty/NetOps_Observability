// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// range.ts — the time window the cloud signal views are showing, and how honest
// they are about it (2026-07 owner review #2).
//
// Before this, every cloud signal table was hardwired to "last 24h" in a caption:
// the user could not narrow to the minutes around an incident, was never told how
// many events existed vs how many rendered, and could not tell whether the feed
// was live or a frozen first paint.
//
// HOW THE WINDOW IS HONORED (Wave 2 #5 — real time-range):
// /api/cloud/health|changes|evidence now take an additive ?window_hours= param
// (clamped 1..168 server-side, default 24 — cloud_signals.go clampWindowHours),
// so 7d is a REAL server read, not a re-labeled 24h. Ranges ≤24h keep the one
// default 24h fetch and NARROW client-side inside it (the set is already loaded
// and LIMIT-bounded; a per-click refetch would buy nothing) — see
// windowHoursFor(). A range the server didn't honor is never labeled: callers
// read the response's window_hours back.
//
// Pure + deterministic (an injectable `now`) → unit-tested (range.test.ts).

import type { TimeRange } from "../../context/shell";

// The DEFAULT server-side cloud signal window (no window_hours param).
export const CLOUD_WINDOW_MINUTES = 24 * 60;
// The server's clamp ceiling for ?window_hours= (7 days).
export const CLOUD_WINDOW_MAX_MINUTES = 7 * 24 * 60;

// Range presets. Shape matches the app-wide TimeRange model (context/shell
// TIME_RANGES) so the control reads as the same product, and a custom preset
// could be merged in later. 7d exists because the server honors it now —
// it was deliberately absent while the window was a hardwired 24h constant.
export const CLOUD_RANGES: readonly TimeRange[] = [
  { label: "15m", minutes: 15 },
  { label: "1h", minutes: 60 },
  { label: "6h", minutes: 360 },
  { label: "24h", minutes: CLOUD_WINDOW_MINUTES },
  { label: "7d", minutes: CLOUD_WINDOW_MAX_MINUTES },
] as const;

// Default to the full DEFAULT ingest window (24h — NOT the 7d maximum): the
// first paint shows everything the standing read covers without paying the
// wide 7d scan on every visit.
export const DEFAULT_CLOUD_RANGE: TimeRange =
  CLOUD_RANGES.find((r) => r.minutes === CLOUD_WINDOW_MINUTES) ?? CLOUD_RANGES[0];

export function rangeFor(minutes: number): TimeRange {
  return CLOUD_RANGES.find((r) => r.minutes === minutes) ?? DEFAULT_CLOUD_RANGE;
}

// The ?window_hours= a signal fetch should request for a UI range: sub-24h
// ranges reuse the default 24h window (fetch once, narrow client-side inside
// the already-loaded, LIMIT-bounded set — that also keeps the "nothing in the
// range, newest landed 3h ago — widen" hint able to see beyond the narrow
// range); above 24h the window is the real, server-honored range.
export function windowHoursFor(minutes: number): number {
  if (minutes <= CLOUD_WINDOW_MINUTES) return CLOUD_WINDOW_MINUTES / 60;
  return Math.ceil(Math.min(minutes, CLOUD_WINDOW_MAX_MINUTES) / 60);
}

// Spoken form for captions/empty states ("last 6 hours").
// Hours are preferred up to a full day, so the ingested window reads as the
// familiar "last 24 hours" the page has always said — not "last 1 day". Days
// only take over ABOVE a day (so a future 7d window would read "last 7 days"
// rather than "last 168 hours").
export function rangeWords(minutes: number): string {
  if (minutes > 1440 && minutes % 1440 === 0) {
    const d = minutes / 1440;
    return `last ${d} day${d > 1 ? "s" : ""}`;
  }
  if (minutes % 60 === 0) {
    const h = minutes / 60;
    return `last ${h} hour${h > 1 ? "s" : ""}`;
  }
  return `last ${minutes} min`;
}

// An unparseable stamp is NOT silently dropped as "old": it cannot be placed in
// time, so it stays visible rather than being hidden by a filter it never met.
export function withinRange(iso: string, minutes: number, now: number = Date.now()): boolean {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return true;
  return t >= now - minutes * 60_000;
}

export function filterByRange<T extends { time: string }>(
  rows: readonly T[], minutes: number, now: number = Date.now(),
): T[] {
  return rows.filter((r) => withinRange(r.time, minutes, now));
}

// The newest stamp in a feed — the freshness anchor ("source last reported …").
// "" when the feed is empty or carries no readable stamp.
export function newestIso(rows: readonly { time: string }[]): string {
  let best = "";
  let bestMs = -Infinity;
  for (const r of rows) {
    const ms = new Date(r.time).getTime();
    if (Number.isNaN(ms)) continue;
    if (ms > bestMs) { bestMs = ms; best = r.time; }
  }
  return best;
}

// "showing N of M" — stated only when they differ, so the caption never adds
// noise to a complete feed. `capped` reports the honest reason rows are missing.
export interface FeedCount {
  shown: number;
  total: number;
  text: string;
  narrowed: boolean;
}

export function feedCount(shown: number, total: number, minutes: number): FeedCount {
  const narrowed = shown < total;
  const events = `${shown.toLocaleString()} event${shown === 1 ? "" : "s"}`;
  return {
    shown, total, narrowed,
    text: narrowed
      ? `showing ${shown.toLocaleString()} of ${total.toLocaleString()} · ${rangeWords(minutes)}`
      : `${events} · ${rangeWords(minutes)}`,
  };
}

// Seconds-resolution freshness for the live affordance. `ago()` in ./badges is
// minute-resolution ("now" for anything under 60s), which cannot express "updated
// 8s ago" — the whole point of a liveness cue.
export function freshnessText(loadedAtMs: number, now: number = Date.now()): string {
  const s = Math.max(0, Math.round((now - loadedAtMs) / 1000));
  if (s < 60) return `updated ${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `updated ${m}m ago`;
  return `updated ${Math.round(m / 60)}h ago`;
}
