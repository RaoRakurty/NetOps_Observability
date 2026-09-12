// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Event-timeline episode model for the Cloud Service View (2026-07 UX pass).
//
// The raw health + change feeds arrive as one row PER observation, so a resource
// that is "down" for 50 minutes and re-reported every ~2 minutes produced ~25
// identical rows — an unreadable wall (audit defect #1). This module collapses a
// CONSECUTIVE run of identical events (same resource + kind + state + signal +
// metric) into a single EPISODE carrying an occurrence count and a first/last-seen
// span, and normalizes empty provider values so a genuinely-absent reading is one
// honest "—" rather than "— — (baseline —)". Pure + deterministic → unit-tested.

import type { ChangeEvent, Health, HealthSignal } from "./types";

export type TimelineKind = "change" | "health" | "down";

// ── Health rows come in TWO shapes, and conflating them is what produced the
// empty metric/baseline/current triplet the owner found on a critical Azure row.
//
//   · METRIC ANOMALY — "CPU is 94% vs a 30% baseline". Has metric_name + value +
//     baseline. metric/current/baseline are the story.
//   · STATE EVENT — "the provider declares this resource Unavailable"
//     (cloud_resource_health / cloud_health). The provider ships NO metric, value
//     or baseline: there is nothing to measure, only a declared state and its
//     reasonType. Rendering it through the metric columns yields "— — —".
//
// So: a health signal with no metric name IS a state event, and its substance is
// state + reason. Neither is fabricated — both come off the wire.

export function isStateEvent(h: Pick<HealthSignal, "metric">): boolean {
  return cleanVal(h.metric) === "";
}

// The provider's declared state, in operator words. Only ever a state the signal
// actually reported — "unknown" stays unknown and is never promoted.
const STATE_LABEL: Record<Health, string> = {
  down: "Down", degraded: "Degraded", healthy: "Healthy", unknown: "Unknown",
};
export function stateLabel(state: Health | string): string {
  return STATE_LABEL[state as Health] ?? cleanVal(state) ?? "Unknown";
}

// The provider's reasonType for a state event ("Customer Initiated"), or "" when
// it declared none — the UI then says "no reason stated", never invents one.
export function stateReason(h: Pick<HealthSignal, "reason">): string {
  return cleanVal(h.reason);
}

// A provider value we treat as "not reported" — collapsed to "" so the UI can
// omit it honestly instead of rendering a bare dash the operator must decode.
export function cleanVal(v: string | null | undefined): string {
  if (v == null) return "";
  const s = String(v).trim();
  const low = s.toLowerCase();
  if (s === "" || s === "—" || s === "-" || low === "null" || low === "n/a" || low === "none" || low === "undefined") {
    return "";
  }
  return s;
}

export interface TimelineEpisode {
  kind: TimelineKind;
  tone: string;          // severity/kind color token
  app: string;
  resource: string;
  detail: string;        // humanized signal name / change type
  metric: string;        // metric name ("" for change rows / when absent)
  current: string;       // observed reading ("" when the provider reported none)
  baseline: string;      // baseline reading ("" when absent)
  severity: string;      // health severity ("" for change rows)
  state: string;         // health state ("" for change rows)
  // The provider's declared cause for a STATE event ("Customer Initiated"); ""
  // for change rows, metric anomalies, and states the provider gave no reason for.
  reason: string;
  // true when this health episode is a provider state declaration rather than a
  // metric anomaly — the Reading column renders state+reason instead of "— —".
  stateEvent: boolean;
  actor: string;         // change actor ("" for health rows)
  source: string;
  count: number;         // occurrences collapsed into this episode
  firstSeen: string;     // earliest ISO in the run
  lastSeen: string;      // latest ISO in the run
  key: string;           // dedup key (resource + kind + state + signal + metric + reason)
}

// Merge health + change signals into newest-first episodes. Consecutive identical
// events collapse; distinct signals never merge (metric is part of the key, so two
// different metrics on the same resource stay separate — we never hide a signal).
export function buildTimeline(health: HealthSignal[], changes: ChangeEvent[], cap = 300): TimelineEpisode[] {
  type Raw = Omit<TimelineEpisode, "count" | "firstSeen" | "lastSeen"> & { time: string };
  const raw: Raw[] = [];

  for (const c of changes) {
    const detail = c.changeType.replace(/_/g, " ");
    raw.push({
      time: c.time, kind: "change", tone: "var(--warn)",
      app: cleanVal(c.app) || "—", resource: cleanVal(c.resource) || "—",
      detail, metric: "", current: "", baseline: "",
      severity: "", state: "", reason: "", stateEvent: false,
      actor: cleanVal(c.actor), source: cleanVal(c.source),
      key: `change|${c.resource}|${c.changeType}`,
    });
  }
  for (const h of health) {
    const kind: TimelineKind = h.state === "down" ? "down" : "health";
    const tone = h.severity === "critical" ? "var(--crit)"
      : h.severity === "warning" ? "var(--warn)" : "var(--fg-subtle)";
    const detail = (cleanVal(h.signal) || "health signal").replace(/_/g, " ");
    const reason = stateReason(h);
    raw.push({
      time: h.time, kind, tone,
      app: cleanVal(h.app) || "—", resource: cleanVal(h.resource) || "—",
      detail, metric: cleanVal(h.metric),
      current: cleanVal(h.current), baseline: cleanVal(h.baseline),
      severity: cleanVal(h.severity), state: cleanVal(h.state),
      reason, stateEvent: isStateEvent(h),
      actor: "", source: cleanVal(h.source),
      // reason joins the key so a state change that keeps the same state but
      // changes cause (Platform → Customer Initiated) stays a distinct episode
      // rather than being silently collapsed into the previous run.
      key: `health|${h.resource}|${h.state}|${h.signal}|${h.metric}|${reason}`,
    });
  }

  // Newest first, then collapse consecutive identical runs.
  raw.sort((a, b) => b.time.localeCompare(a.time));
  const episodes: TimelineEpisode[] = [];
  for (const r of raw) {
    const prev = episodes[episodes.length - 1];
    if (prev && prev.key === r.key) {
      prev.count += 1;
      if (r.time < prev.firstSeen) prev.firstSeen = r.time;
      if (r.time > prev.lastSeen) prev.lastSeen = r.time;
      continue;
    }
    const { time, ...rest } = r;
    episodes.push({ ...rest, count: 1, firstSeen: time, lastSeen: time });
  }
  return episodes.slice(0, cap);
}
