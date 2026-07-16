// Event-timeline episode model for the Cloud Service View (2026-07 UX pass).
//
// The raw health + change feeds arrive as one row PER observation, so a resource
// that is "down" for 50 minutes and re-reported every ~2 minutes produced ~25
// identical rows — an unreadable wall (audit defect #1). This module collapses a
// CONSECUTIVE run of identical events (same resource + kind + state + signal +
// metric) into a single EPISODE carrying an occurrence count and a first/last-seen
// span, and normalizes empty provider values so a genuinely-absent reading is one
// honest "—" rather than "— — (baseline —)". Pure + deterministic → unit-tested.

import type { ChangeEvent, HealthSignal } from "./types";

export type TimelineKind = "change" | "health" | "down";

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
  actor: string;         // change actor ("" for health rows)
  source: string;
  count: number;         // occurrences collapsed into this episode
  firstSeen: string;     // earliest ISO in the run
  lastSeen: string;      // latest ISO in the run
  key: string;           // dedup key (resource + kind + state + signal + metric)
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
      severity: "", state: "", actor: cleanVal(c.actor), source: cleanVal(c.source),
      key: `change|${c.resource}|${c.changeType}`,
    });
  }
  for (const h of health) {
    const kind: TimelineKind = h.state === "down" ? "down" : "health";
    const tone = h.severity === "critical" ? "var(--crit)"
      : h.severity === "warning" ? "var(--warn)" : "var(--fg-subtle)";
    const detail = (cleanVal(h.signal) || "health signal").replace(/_/g, " ");
    raw.push({
      time: h.time, kind, tone,
      app: cleanVal(h.app) || "—", resource: cleanVal(h.resource) || "—",
      detail, metric: cleanVal(h.metric),
      current: cleanVal(h.current), baseline: cleanVal(h.baseline),
      severity: cleanVal(h.severity), state: cleanVal(h.state), actor: "", source: cleanVal(h.source),
      key: `health|${h.resource}|${h.state}|${h.signal}|${h.metric}`,
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
