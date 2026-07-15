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
});
