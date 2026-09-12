// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// monitors.ts — pure logic for the cloud Monitors editor (Wave 5 #14 slice 3).
// Validation mirrors the backend's closed vocabularies so a refused save is
// caught before the round-trip; description/state helpers keep the card's
// language honest ("never evaluated" is not "ok").

import type { CloudMonitorInput, CloudMonitorRow, CloudMonitorState } from "../../services/api";
import { CLOUD_METRIC_FALLBACK } from "./metricsPanel";

export interface MonitorDraft {
  name: string;
  metric: string;
  resourceId: string;
  mode: "threshold" | "anomaly";
  condition: "above" | "below";
  threshold: string; // raw input
}

export const EMPTY_MONITOR_DRAFT: MonitorDraft = {
  name: "", metric: "cloud_cpu_util", resourceId: "",
  mode: "threshold", condition: "above", threshold: "",
};

// validateMonitorDraft — "" when saveable, else the first problem in plain
// words (backend bounds mirrored: name 1..80, catalog metric, finite threshold).
export function validateMonitorDraft(d: MonitorDraft): string {
  const name = d.name.trim();
  if (!name) return "give the monitor a name";
  if (name.length > 80) return "name must be at most 80 characters";
  if (!CLOUD_METRIC_FALLBACK.some((m) => m.name === d.metric)) return "pick a metric from the catalog";
  if (d.mode === "threshold") {
    const n = Number(d.threshold);
    if (d.threshold.trim() === "" || !Number.isFinite(n)) return "threshold must be a number";
  }
  return "";
}

// draftToInput — the wire shape the API expects (anomaly mode strips
// condition/threshold — the backend refuses leftovers by design).
export function draftToInput(d: MonitorDraft, enabled = true): CloudMonitorInput {
  const base: CloudMonitorInput = {
    name: d.name.trim(), metric: d.metric, mode: d.mode, enabled,
  };
  if (d.resourceId.trim()) base.resource_id = d.resourceId.trim();
  if (d.mode === "threshold") {
    base.condition = d.condition;
    base.threshold = Number(d.threshold);
  }
  return base;
}

// rowToInput — an existing row back to the PUT shape (used by enable/disable).
export function rowToInput(r: CloudMonitorRow, enabled: boolean): CloudMonitorInput {
  const base: CloudMonitorInput = { name: r.name, metric: r.metric, mode: r.mode, enabled };
  if (r.resource_id) base.resource_id = r.resource_id;
  if (r.mode === "threshold") {
    base.condition = r.condition;
    base.threshold = r.threshold;
  }
  return base;
}

// describeMonitor — one honest sentence for the list row.
export function describeMonitor(r: CloudMonitorRow): string {
  const metric = CLOUD_METRIC_FALLBACK.find((m) => m.name === r.metric)?.label ?? r.metric;
  const scope = r.resource_id ? `on ${r.resource_id}` : "on every cloud resource";
  if (r.mode === "anomaly") return `${metric} ${scope} — alert on deviation from its own 6h behaviour`;
  return `${metric} ${scope} — alert when ${r.condition} ${r.threshold}`;
}

// monitorStateLabel / tone — display vocabulary. "never evaluated" and
// "no data" are explicitly NOT green: absence of a verdict is not health.
export function monitorStateLabel(s: CloudMonitorState): string {
  switch (s) {
    case "never_evaluated": return "never evaluated";
    case "no_data": return "no data";
    default: return s;
  }
}

export function monitorStateTone(s: CloudMonitorState): string {
  switch (s) {
    case "ok": return "var(--ok)";
    case "firing": return "var(--crit)";
    case "error": return "var(--crit)";
    case "no_data": return "var(--warn)";
    default: return "var(--fg-subtle)"; // never_evaluated / disabled
  }
}
