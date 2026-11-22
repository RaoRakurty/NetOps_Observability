// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// alertsModel.ts — Operations → Active Alerts as a pure presenter (the Logs
// redesign pattern, owner 2026-11-22): an episode becomes a view model the page
// only renders, and every rule here is unit-tested.
//
//   • tabs map 1:1 onto the episode API's status filter (no client re-filter);
//   • a row is a plain sentence plus a detail line, the device by NAME;
//   • severity tiles count the loaded rows and SAY so when the list is cut;
//   • quick filters (device, monitor, flapping, paused, unassigned) narrow the
//     loaded rows only, and are labelled that way.

import type { AlertEpisode } from "../services/api";
import { severityGroupOf, SEVERITY_GROUPS, type SeverityGroup } from "../lib/logFilters";

export type AlertsTab = "active" | "cleared" | "closed" | "all";

export const ALERT_TABS: { id: AlertsTab; label: string; empty: string }[] = [
  { id: "active", label: "Firing", empty: "Nothing firing." },
  { id: "cleared", label: "Cleared", empty: "Nothing cleared recently." },
  { id: "closed", label: "Closed", empty: "No closed episodes." },
  { id: "all", label: "All", empty: "No alert episodes." },
];

export const isSuppressed = (e: AlertEpisode, now: number = Date.now()): boolean =>
  !!e.muted || (!!e.snoozed_until && Date.parse(e.snoozed_until) > now);

export const statusLabel = (s: AlertEpisode["status"]): string =>
  s === "active" ? "Firing" : s === "cleared" ? "Cleared" : "Closed";

export const statusTone = (s: AlertEpisode["status"]): string =>
  s === "active" ? "var(--warn)" : s === "cleared" ? "var(--ok)" : "var(--fg-subtle)";

/** A device id shown by its inventory name; "Platform" for a stack-level episode. */
export function deviceLabel(e: AlertEpisode, names: ReadonlyMap<string, string> | null): string {
  if (!e.resource) return "Platform";
  return names?.get(e.resource) ?? e.resource;
}

export type AlertView = {
  id: string;
  /** "HighCPU on leaf-1" — what fired, where. */
  title: string;
  /** The rule's own summary when it has one, else the count and span. */
  detail: string;
  device: string;
  /** The raw id under the name, only when the two differ. */
  deviceId: string;
  group: SeverityGroup;
  episode: AlertEpisode;
};

export function toAlertView(e: AlertEpisode, names: ReadonlyMap<string, string> | null): AlertView {
  const device = deviceLabel(e, names);
  const count = e.count > 1 ? `${e.count} firings` : "1 firing";
  return {
    id: e.id,
    title: e.resource ? `${e.signal} on ${device}` : e.signal,
    detail: e.summary?.trim() ? `${e.summary.trim()} · ${count}` : count,
    device,
    deviceId: e.resource && device !== e.resource ? e.resource : "",
    group: severityGroupOf(e.state),
    episode: e,
  };
}

export type AlertTiles = {
  tiles: { id: SeverityGroup; label: string; count: number }[];
  /** The sentence under the tiles: what they counted. */
  note: string;
};

/**
 * Severity tiles over the LOADED episodes. The episode API caps the list; when
 * it says `truncated`, the counts cover only the rows on screen and the note
 * says so — they are never presented as store-wide totals.
 */
export function alertTiles(items: readonly AlertEpisode[], truncated: boolean, total: number): AlertTiles {
  const counts = new Map<SeverityGroup, number>();
  for (const e of items) {
    const g = severityGroupOf(e.state);
    counts.set(g, (counts.get(g) ?? 0) + 1);
  }
  const tiles = SEVERITY_GROUPS.filter((g) => g.id !== "ok").map((g) => ({ id: g.id, label: g.label, count: counts.get(g.id) ?? 0 }));
  const n = items.length;
  const note = truncated
    ? `Counted in the ${n.toLocaleString()} loaded episodes of ${total.toLocaleString()}.`
    : `Counted across all ${n.toLocaleString()} episode${n === 1 ? "" : "s"} in this view.`;
  return { tiles, note };
}

export type AlertFilters = {
  q?: string;
  severity?: SeverityGroup;
  device?: string;
  monitor?: string;
  flapping?: boolean;
  paused?: boolean;
  unassigned?: boolean;
};

export function filterAlerts(views: readonly AlertView[], f: AlertFilters, now: number = Date.now()): AlertView[] {
  const needle = (f.q ?? "").trim().toLowerCase();
  return views.filter((v) => {
    const e = v.episode;
    if (f.severity && v.group !== f.severity) return false;
    if (f.device && v.device !== f.device) return false;
    if (f.monitor && e.signal !== f.monitor) return false;
    if (f.flapping && !e.flapping) return false;
    if (f.paused && !isSuppressed(e, now)) return false;
    if (f.unassigned && e.assigned_to) return false;
    if (needle && !`${v.title} ${v.detail} ${v.deviceId} ${e.assigned_to ?? ""}`.toLowerCase().includes(needle)) return false;
    return true;
  });
}

/** Distinct values for a quick filter, most frequent first, in the loaded rows. */
export function facetValues(views: readonly AlertView[], pick: (v: AlertView) => string): { value: string; count: number }[] {
  const m = new Map<string, number>();
  for (const v of views) {
    const k = pick(v);
    if (k) m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

export const activeAlertFilterCount = (f: AlertFilters): number =>
  [f.q?.trim(), f.severity, f.device, f.monitor, f.flapping, f.paused, f.unassigned].filter(Boolean).length;
