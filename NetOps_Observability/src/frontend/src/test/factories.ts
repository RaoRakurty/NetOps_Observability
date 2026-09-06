// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { CorrSignal, CorrTimeline, CorrObject } from "../services/api";

// Minimal, valid fixture builders for RCA tests. Defaults are sane; override only
// the fields a test cares about. Keeps test scenarios readable.

export function signal(over: Partial<CorrSignal> = {}): CorrSignal {
  return {
    signal_id: over.signal_id ?? "sig-" + Math.random().toString(36).slice(2, 8),
    ts: "2026-06-16 19:25:06",
    ingest_ts: "2026-06-16 19:25:07",
    source: "lab",
    kind: "bgp_state_anomaly",
    observer_type: "device",
    observer_id: "obs-1",
    collection_path: "snmp",
    modality_class: "control_plane",
    clock_quality: "good",
    entity_type: "device",
    entity_id: "wan-r2",
    severity: "warning",
    value: 1,
    metric_name: "bgp_state",
    onset_uncertainty_s: 1,
    phase: "onset",
    clear_ts: "",
    attached: true,
    is_trigger: true,
    evidence: null,
    link_status: "attached",
    link_role: "supporting",
    link_reason: "",
    linked_edges: null,
    ...over,
  };
}

export function timeline(over: Partial<CorrTimeline> = {}): CorrTimeline {
  return {
    correlation_id: "corr-abc1234567890",
    version: 1,
    window_start: "2026-06-16 19:25:00",
    window_end: "2026-06-16 19:26:15",
    trigger_signal: "sig-1",
    verdict_tier: "suspected",
    top_hypothesis: "undetermined",
    top_confidence: 0.3,
    evidence_missing: "[]",
    signals: [],
    evidence: [],
    edges: [],
    counts: {
      total: 0, attached: 0, unattached: 0, recovery: 0, unlinked: 0,
      attached_observers: 0, by_modality: {}, attached_by_modality: {},
      by_role: {}, by_grounding: {}, by_status: {},
    } as CorrTimeline["counts"],
    ...over,
  };
}

export function corrObject(over: Partial<CorrObject> = {}): CorrObject {
  return {
    correlation_id: "corr-abc1234567890",
    version: 1,
    state: "open",
    window_start: "2026-06-16 19:25:00",
    window_end: "2026-06-16 19:26:15",
    top_hypothesis: "undetermined",
    top_confidence: 0.3,
    verdict_tier: "suspected",
    hypotheses: "{}",
    evidence_missing: "[]",
    affected: "{}",
    signal_count: 1,
    ...(over as object),
  } as CorrObject;
}
