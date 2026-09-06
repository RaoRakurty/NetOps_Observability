// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// capacityTopology.ts — mock TopologyView for the "capacity" workflow (PDF §9).
//
// A routed leaf-spine fabric carrying DELIBERATELY uneven load so the utilization
// overlay, the hot-link ranking and the ECMP-imbalance detector all have real
// signal:
//   • spine1 uplinks run hot (leaf1 92%, leaf3 96% + errors) → saturated.
//   • leaf1/leaf3 ECMP uplinks diverge sharply (92↔61, 96↔44) → imbalanced.
//   • leaf2/leaf4 are balanced and calm → stay quiet by default.
// Every edge carries evidence (never draw a link without it). FLAT canonical
// contract (api/topologyTypes.ts).

import type { TopologyView } from "../api/topologyTypes";

const SEEN = "2026-06-18T00:58:00Z";
const BORN = "2026-05-01T00:00:00Z";

function ev(detail: string, raw: string, conf = 0.97) {
  return [
    { source: "lldp" as const, confidence: conf, detail, observed_at: SEEN, raw_ref: raw, summary: detail },
  ];
}

export const capacityTopology: TopologyView = {
  view_id: "view-capacity-clos-001",
  topology_id: "topo-clos-fabric",
  mode: "capacity",
  scope: { tenant_id: "tenant-acme", site: "dc-east-1" },
  generated_at: "2026-06-18T01:00:00Z",
  time_range: { from: "2026-06-18T00:00:00Z", to: "2026-06-18T01:00:00Z" },
  layout_type: "spine_leaf",
  overlays: ["health", "utilization", "interface_errors"],
  nodes: [
    {
      id: "spine1", label: "spine1", kind: "switch", role: "spine", vendor: "arista", model: "7280R3",
      site: "dc-east-1", mgmt_ip: "10.0.0.11", owner: "neteng", criticality: "critical",
      // spine1 aggregates two saturated uplinks → warning.
      health: "warning", confidence: 0.99, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 47, mem_pct: 58, link_count: 4, alert_count: 1 },
      evidence: ev("LLDP chassis-id resolved spine1 (Arista 7280R3)", "lldp:spine1:chassis", 0.98),
      tags: { plane: "data", role: "spine" },
    },
    {
      id: "spine2", label: "spine2", kind: "switch", role: "spine", vendor: "arista", model: "7280R3",
      site: "dc-east-1", mgmt_ip: "10.0.0.12", owner: "neteng", criticality: "critical",
      health: "ok", confidence: 0.99, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 31, mem_pct: 44, link_count: 4, alert_count: 0 },
      evidence: ev("LLDP chassis-id resolved spine2 (Arista 7280R3)", "lldp:spine2:chassis", 0.98),
      tags: { plane: "data", role: "spine" },
    },
    {
      id: "leaf1", label: "leaf1", kind: "switch", role: "leaf", vendor: "arista", model: "7050X3",
      site: "dc-east-1", mgmt_ip: "10.0.1.11", owner: "neteng", criticality: "high",
      health: "warning", confidence: 0.98, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 28, mem_pct: 39, link_count: 2, alert_count: 1 },
      evidence: ev("LLDP chassis-id resolved leaf1 (Arista 7050X3)", "lldp:leaf1:chassis"),
      tags: { plane: "data", role: "leaf" },
    },
    {
      id: "leaf2", label: "leaf2", kind: "switch", role: "leaf", vendor: "arista", model: "7050X3",
      site: "dc-east-1", mgmt_ip: "10.0.1.12", owner: "neteng", criticality: "high",
      health: "ok", confidence: 0.98, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 24, mem_pct: 37, link_count: 2, alert_count: 0 },
      evidence: ev("LLDP chassis-id resolved leaf2 (Arista 7050X3)", "lldp:leaf2:chassis"),
      tags: { plane: "data", role: "leaf" },
    },
    {
      id: "leaf3", label: "leaf3", kind: "switch", role: "leaf", vendor: "arista", model: "7050X3",
      site: "dc-east-1", mgmt_ip: "10.0.1.13", owner: "neteng", criticality: "high",
      // leaf3's spine1 uplink is saturated AND erroring → critical.
      health: "critical", confidence: 0.98, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 33, mem_pct: 41, link_count: 2, alert_count: 2 },
      evidence: ev("LLDP chassis-id resolved leaf3 (Arista 7050X3)", "lldp:leaf3:chassis"),
      tags: { plane: "data", role: "leaf" },
    },
    {
      id: "leaf4", label: "leaf4", kind: "switch", role: "leaf", vendor: "arista", model: "7050X3",
      site: "dc-east-1", mgmt_ip: "10.0.1.14", owner: "neteng", criticality: "medium",
      health: "ok", confidence: 0.98, resolved: true, first_seen: BORN, last_seen: SEEN,
      change_state: "unchanged", metrics: { cpu_pct: 19, mem_pct: 34, link_count: 2, alert_count: 0 },
      evidence: ev("LLDP chassis-id resolved leaf4 (Arista 7050X3)", "lldp:leaf4:chassis"),
      tags: { plane: "data", role: "leaf" },
    },
  ],
  edges: [
    // leaf1 ECMP uplinks — 92 vs 61 → imbalanced; spine1 side saturated.
    mkEdge("leaf1", "spine1", "Et49", "Et1/1", 92, 0, "2x100G"),
    mkEdge("leaf1", "spine2", "Et50", "Et1/1", 61, 0, "2x100G"),
    // leaf2 ECMP uplinks — 88 vs 84 → balanced.
    mkEdge("leaf2", "spine1", "Et49", "Et1/2", 88, 0, "2x100G"),
    mkEdge("leaf2", "spine2", "Et50", "Et1/2", 84, 0, "2x100G"),
    // leaf3 ECMP uplinks — 96 (errors) vs 44 → badly imbalanced + erroring.
    mkEdge("leaf3", "spine1", "Et49", "Et1/3", 96, 1840, "2x100G"),
    mkEdge("leaf3", "spine2", "Et50", "Et1/3", 44, 0, "2x100G"),
    // leaf4 ECMP uplinks — 35 vs 33 → cool and balanced.
    mkEdge("leaf4", "spine1", "Et49", "Et1/4", 35, 0, "2x100G"),
    mkEdge("leaf4", "spine2", "Et50", "Et1/4", 33, 0, "2x100G"),
  ],
  groups: [],
};

function mkEdge(
  src: string,
  dst: string,
  sPort: string,
  dPort: string,
  util: number,
  errors: number,
  bundle: string,
): import("../api/topologyTypes").TopologyEdge {
  const status = errors > 0 ? "degraded" : util >= 85 ? "warning" : "up";
  return {
    id: `e-${src}-${dst}`,
    source: src,
    target: dst,
    relationship: "connected_to",
    protocol: "lldp",
    source_port: sPort,
    target_port: dPort,
    status,
    confidence: 0.97,
    direction: "bi",
    utilization_pct: util,
    errors,
    bundle_id: bundle,
    bundle_count: 2,
    first_seen: BORN,
    last_seen: SEEN,
    change_state: "unchanged",
    evidence: [
      {
        source: "lldp",
        confidence: 0.97,
        detail: `${src} ${sPort} ↔ ${dst} ${dPort} (${bundle}) — ${util}% util`,
        observed_at: SEEN,
        raw_ref: `lldp:${src}:${sPort}<->${dst}:${dPort}`,
        summary: `bidirectional LLDP ${src} ${sPort} ↔ ${dst} ${dPort}`,
      },
    ],
  };
}
