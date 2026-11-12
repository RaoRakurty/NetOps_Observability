// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyFixtures.ts — topology_context payloads for the four states (RCA
// document v2 §2), shaped exactly as the server's TopologyContext JSON
// (internal/rca/topology_context.go). P-3E0400 is derived from the captured lab
// fixture (src/backend/internal/rca/testdata/p3e0400) following the server's
// AssembleTopologyContext rules — it is the device_only regression case.

import p3e0400 from "./p3e0400.topology_context.json";

/** P-3E0400 — device_only: in the inventory, every neighbour source read and empty. */
export const P3E0400_CONTEXT: unknown = p3e0400;

const SOURCES_WITH_LINKS = [
  { kind: "inventory", status: "read", rows: 1, stale: false, freshness: "current" },
  { kind: "lldp", status: "read", rows: 1, observed_at: "2026-11-12T04:55:00Z", stale: false, freshness: "current" },
  { kind: "cdp", status: "read", rows: 1, observed_at: "2026-11-12T03:10:00Z", stale: true, freshness: "stale" },
  { kind: "bgp_ls", status: "not_configured", rows: 0, stale: false, freshness: "not_configured" },
];

const NODES = [
  { id: "edge-1", label: "edge-1", role: "wan_edge", source: "inventory", anchor: true, managed: true, last_seen: "2026-11-12T04:56:00Z", stale: false },
  { id: "core-1", label: "core-1", role: "core_router", source: "inventory", anchor: false, managed: true, last_seen: "2026-11-12T04:56:00Z", stale: false },
  { id: "isp-gw", label: "isp-gw", source: "cdp", anchor: false, managed: false, stale: true },
];

const EDGES = [
  { id: "e-edge1-core1", a: "edge-1", a_port: "Gi1", b: "core-1", b_port: "Te0/1", relationship: "physical", protocol: "lldp",
    sources: ["lldp"], bidirectional: true, first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-11-12T04:55:00Z", stale: false, freshness: "current" },
  { id: "e-edge1-isp", a: "edge-1", a_port: "Gi2", b: "isp-gw", relationship: "physical", protocol: "cdp",
    sources: ["cdp"], bidirectional: false, first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-11-12T03:10:00Z", stale: true, freshness: "stale" },
];

const FAULTS = [
  { target_type: "interface", target_id: "edge-1:Gi1", device: "edge-1", port: "Gi1", kinds: ["if_errors"], peak_severity: "crit", evidence_refs: ["s-1", "s-2"] },
  { target_type: "node", target_id: "core-1", device: "core-1", kinds: ["bgp_adjacency_change"], peak_severity: "warn", evidence_refs: ["s-3"] },
];

const CAUSAL = [
  { from: "edge-1:Gi1", from_type: "interface", from_kind: "if_errors", to: "core-1", to_type: "node", to_kind: "bgp_adjacency_change",
    relation: "suspected", directed: true, basis: "direction from onset order (direction confidence 0.70); joined across a known link (authoritative)",
    direction_conf: 0.7, evidence_refs: ["s-1", "s-3"] },
  { from: "edge-1", from_type: "node", to: "isp-gw", to_type: "node", relation: "unknown", directed: false,
    basis: "known link (CDP); no evidence was joined across it", direction_conf: 0, evidence_refs: [] },
];

/** topology_only — known links, no measured path: the causal path is unverified. */
export const TOPOLOGY_ONLY_CONTEXT = {
  state: "topology_only", sources: SOURCES_WITH_LINKS, anchors: ["edge-1"],
  nodes: NODES, edges: EDGES, more_nodes: 2, faults: FAULTS, causal: CAUSAL,
  reason: "No measured path is attached to this case. The topology drawn is the known adjacency around the affected device from LLDP, CDP; the causal path across it is unverified.",
  remediation: ["To verify the causal path, add an active path test toward the affected service so a measured path can be attached."],
};

/** topology_with_path — the same topology plus a measured path. */
export const TOPOLOGY_WITH_PATH_CONTEXT = {
  ...TOPOLOGY_ONLY_CONTEXT,
  state: "topology_with_path",
  spine: { available: true, vantage_id: "agent-1", observed_at: "2026-11-12 04:55:00 UTC", hops: [] },
  reason: "A measured path is attached to this case, and the known topology around the affected devices is drawn with it.",
  remediation: [],
};

/** no_asset_mapping — the affected entity is not in the inventory. */
export const NO_ASSET_MAPPING_CONTEXT = {
  state: "no_asset_mapping",
  sources: [{ kind: "inventory", status: "read", rows: 0, stale: false, freshness: "empty" }],
  anchors: ["ghost-9"], unmapped: ["ghost-9"], nodes: [], edges: [], more_nodes: 0, faults: [], causal: [],
  reason: "The affected entity (ghost-9) is not in the device inventory, so no topology can be anchored to it.",
  remediation: [
    "Add the device to the inventory, or match it to an existing device (Devices → discovery, or the SD-WAN / NMS integration's device matching).",
    "Check that the name the telemetry uses for it (ghost-9) matches the inventory name or management address.",
  ],
};
