// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Shared fixtures for the Iris presentation tests — shaped exactly like the
// backend's plan.ResultSet JSON (src/backend/internal/nlquery/plan/result.go,
// rows from plan/lists.go changeRow / incident rows / compare rows).

export const HOSTILE = "<script>alert(1)</script>";
export const HOSTILE_IMG = '<img src=x onerror="alert(1)">';

export const WINDOW = { from: "2026-09-20T10:00:00Z", to: "2026-09-20T12:00:00Z" };

export function changeRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    change_id: "chg-1",
    time: "2026-09-20T10:30:00Z",
    type: "config_change",
    actor: "alice",
    source: "ledger",
    object: "core-sw-1",
    object_kind: "device",
    site: "DFW",
    app: "",
    summary: "Raised BGP hold timer",
    ticket: "CHG-1001",
    has_diff: false,
    relation: "temporal",
    ...over,
  };
}

export function baseResult(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    query_id: "q-123",
    ast_hash: "h-abc",
    catalog_version: "1",
    query_type: "change_list",
    window: WINDOW,
    truncated: false,
    provenance: { source: "change_ledger", executed_at: "2026-09-20T12:00:01Z", duration_ms: 42, entities: [] },
    ...over,
  };
}

export function seriesResult(over: Record<string, unknown> = {}): Record<string, unknown> {
  return baseResult({
    query_type: "metric_series",
    metric: "interface_utilization",
    unit: "%",
    series: [
      { entity: { device: "core-sw-1" }, points: [{ t: 1789898400, v: 10 }, { t: 1789898460, v: 12 }] },
      { entity: { device: "edge-1" }, points: [{ t: 1789898400, v: 3 }, { t: 1789898460, v: null }] },
    ],
    provenance: { source: "victoriametrics", executed_at: "2026-09-20T12:00:01Z", duration_ms: 12, entities: [{ type: "device", id: "core-sw-1" }] },
    ...over,
  });
}

export function compareResult(over: Record<string, unknown> = {}): Record<string, unknown> {
  return baseResult({
    query_type: "compare_windows",
    metric: "latency",
    unit: "ms",
    rows: [
      { site: "DFW", value: 40, previous: 30, delta: 10 },
      { site: "NYC", value: 25 }, // no earlier measurement
    ],
    compare: { from: "2026-09-13T10:00:00Z", to: "2026-09-13T12:00:00Z" },
    provenance: { source: "victoriametrics", executed_at: "2026-09-20T12:00:01Z", duration_ms: 9, entities: [] },
    ...over,
  });
}

export const RCA_DETAIL = {
  IncidentID: "7b0e8c4e-1111-4222-8333-444455556666",
  DisplayID: "INC-42",
  Title: "WAN loss at DFW",
  Verdict: "confirmed",
  RootCauseState: "confirmed",
  Confidence: 0.91,
  ConfidenceLabel: "High",
  RootCause: {
    Identified: true,
    Statement: "Carrier circuit CKT-9 dropped",
    Mechanism: "link down",
    Object: "CKT-9",
    ObjectType: "circuit",
    PossibleCause: "",
    Known: ["Interface ge-0/0/1 went down at 10:31", "BGP session reset at 10:31"],
    Missing: ["Carrier ticket status"],
  },
  Localization: { Localized: true, Statement: "Evidence converges on the DFW WAN edge", Object: "edge-1", ObjectType: "device" },
  Affected: { Devices: ["edge-1", "core-sw-1"], Sites: ["DFW"], Services: [], Targets: [], Seams: [], Regions: [], Paths: 0 },
  Owner: { Triage: "Carrier (ISP)" },
  Missing: ["Carrier ticket status"],
  Truncated: false,
};

export function incidentResult(over: Record<string, unknown> = {}): Record<string, unknown> {
  return baseResult({
    query_type: "incident_explain",
    rows: [
      {
        incident_id: "7b0e8c4e-1111-4222-8333-444455556666",
        display_id: "INC-42",
        title: "WAN loss at DFW",
        state: "open",
        verdict_tier: "confirmed",
        created_at: "2026-09-20T10:31:00Z",
      },
    ],
    detail: RCA_DETAIL,
    provenance: { source: "rca_report", executed_at: "2026-09-20T12:00:01Z", duration_ms: 30, entities: [] },
    ...over,
  });
}
