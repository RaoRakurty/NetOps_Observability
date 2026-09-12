// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// carrierOverlay.test.ts — the cross-cutting carrier overlay is pure, idempotent
// and evidence-backed.

import { describe, it, expect } from "vitest";
import { withCarrierOverlay, CARRIER_NODE_ID } from "./carrierOverlay";
import { cloudNetworkTopology } from "../mock/cloudNetworkTopology";
import type { TopologyView } from "../api/topologyTypes";
import { hasEvidence } from "./topologyHealth";

function emptyView(): TopologyView {
  return {
    view_id: "t", mode: "explore", layout_type: "cloud_grouped",
    generated_at: "2026-07-15T00:00:00Z", nodes: [], edges: [], groups: [], overlays: [],
  };
}

describe("withCarrierOverlay", () => {
  it("appends ONE carrier node + uplinks from egress points, all with evidence", () => {
    const out = withCarrierOverlay(cloudNetworkTopology);
    const carriers = out.nodes.filter((n) => n.id === CARRIER_NODE_ID);
    expect(carriers.length).toBe(1);
    const uplinks = out.edges.filter((e) => e.target === CARRIER_NODE_ID);
    expect(uplinks.length).toBeGreaterThan(0);
    for (const e of uplinks) expect(hasEvidence(e.evidence)).toBe(true);
    // egress = igw / vgw / dx / nva-style boundaries were found
    expect(out.nodes.length).toBe(cloudNetworkTopology.nodes.length + 1);
  });

  it("does not mutate the input view", () => {
    const before = cloudNetworkTopology.nodes.length;
    withCarrierOverlay(cloudNetworkTopology);
    expect(cloudNetworkTopology.nodes.length).toBe(before);
  });

  it("is idempotent — re-applying is a no-op", () => {
    const once = withCarrierOverlay(cloudNetworkTopology);
    const twice = withCarrierOverlay(once);
    expect(twice.nodes.filter((n) => n.id === CARRIER_NODE_ID).length).toBe(1);
    expect(twice.nodes.length).toBe(once.nodes.length);
  });

  it("is a no-op when the view has no egress points (honest)", () => {
    const out = withCarrierOverlay(emptyView());
    expect(out.nodes.some((n) => n.id === CARRIER_NODE_ID)).toBe(false);
  });

  // The discovered cloud role vocabulary (cloud/topology_view.go `gatewayKinds`)
  // must line up with what the overlay calls an egress point. It did not: the
  // substring test missed `vpn_gateway` — which does NOT contain "vpn_gw" — so
  // the standard hybrid interconnect, on BOTH clouds (AWS Site-to-Site VPN and
  // Azure VirtualNetworkGateway), was silently not a carrier uplink. The overlay
  // would have drawn nothing on exactly the topology it exists for.
  function nodeWithRole(id: string, role: string) {
    return {
      id, label: id, kind: "cloud", role, health: "unknown" as const,
      confidence: 0.9, resolved: true, evidence: [{ source: "cloud_api" as const, confidence: 0.9 }],
    };
  }
  function viewWithRoles(roles: string[]): TopologyView {
    return { ...emptyView(), nodes: roles.map((r, i) => nodeWithRole(`n${i}`, r)) } as TopologyView;
  }

  it.each([
    "internet_gateway", "nat_gateway", "vpn_gateway", "transit_gateway",
    "expressroute_gateway", "dx", "egress_only_igw", "carrier_gateway", "local_gateway",
  ])("treats the discovered role %s as a carrier egress point", (role) => {
    const out = withCarrierOverlay(viewWithRoles([role]));
    expect(out.nodes.some((n) => n.id === CARRIER_NODE_ID), `${role} produced no carrier uplink`).toBe(true);
    expect(out.edges.filter((e) => e.target === CARRIER_NODE_ID).length).toBe(1);
  });

  // Deliberate exclusions — attaching these would assert transport we have no
  // evidence for (a peering is VPC↔VPC; an NVA is a workload that may or may not
  // terminate a tunnel, and discovery cannot tell which).
  it.each(["vpc_peering", "nva", "subnet", "vpc_endpoint"])(
    "does NOT invent a carrier uplink from %s",
    (role) => {
      const out = withCarrierOverlay(viewWithRoles([role]));
      expect(out.nodes.some((n) => n.id === CARRIER_NODE_ID)).toBe(false);
    },
  );
});
