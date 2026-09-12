// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// excludeInternalNodes — decision #76: the customer topology canvas must not show the
// platform's own stack (api/correlation/prober). Drops internal nodes + their edges,
// keeps real customer devices.

import { describe, it, expect } from "vitest";
import { excludeInternalNodes } from "./topologyFilters";
import type { TopologyView, TopologyNode, TopologyEdge } from "../api/topologyTypes";

function view(nodes: Array<[string, string]>, edges: Array<[string, string, string]>): TopologyView {
  return {
    view_id: "v", topology_id: "t", mode: "investigate", scope: { tenant_id: "t" },
    generated_at: "", layout_type: "incident",
    nodes: nodes.map(([id, label]) => ({ id, label, kind: "router", health: "ok", confidence: 1, evidence: [] } as TopologyNode)),
    edges: edges.map(([id, source, target]) => ({ id, source, target, evidence: [] } as TopologyEdge)),
    groups: [], overlays: [],
  } as TopologyView;
}

describe("excludeInternalNodes (#76)", () => {
  it("drops platform infra nodes and prunes their edges, keeps customer devices", () => {
    const v = view(
      [["d1", "leaf1"], ["d2", "spine1"], ["api", "api"], ["pr", "prober"]],
      [["e1", "d1", "d2"], ["e2", "d1", "api"], ["e3", "api", "pr"]],
    );
    const out = excludeInternalNodes(v);
    expect(out.nodes.map((n) => n.id).sort()).toEqual(["d1", "d2"]);
    // only the customer-to-customer edge survives; edges touching api/prober pruned
    expect(out.edges.map((e) => e.id)).toEqual(["e1"]);
  });

  it("returns the same view untouched when nothing is internal", () => {
    const v = view([["d1", "leaf1"], ["d2", "spine1"]], [["e1", "d1", "d2"]]);
    expect(excludeInternalNodes(v)).toBe(v);
  });

  it("does not over-match a real device whose name merely contains an infra word", () => {
    // "api-gw-1" is a customer device, not the platform 'api' service.
    const v = view([["d1", "api-gw-1"], ["d2", "core1"]], [["e1", "d1", "d2"]]);
    expect(excludeInternalNodes(v).nodes.map((n) => n.id).sort()).toEqual(["d1", "d2"]);
  });
});
