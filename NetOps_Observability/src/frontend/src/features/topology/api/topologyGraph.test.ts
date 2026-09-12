// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyGraph.test.ts — the persistent-graph read (GET /api/topology/graph).
// Asserts fetchTopologyGraph serves the live reconciled view when it has content
// and returns an HONEST empty view (status "empty" | "error") otherwise — never
// the bundled `physicalTopology` MOCK. The old fallback substituted a fabricated
// spine-leaf fabric on BOTH the catch path and the zero-node path, so an operator
// whose graph service was down was shown a healthy network of devices that were
// not theirs, presented as their live graph.
//
// Mirrors cloudTopology.test.ts, which locks the same rule for the cloud read.

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { TopologyView } from "./topologyTypes";

const topologyGraph = vi.fn();
vi.mock("../../../services/api", () => ({ api: { topologyGraph: () => topologyGraph() } }));

import { fetchTopologyGraph } from "./topologyApi";
import { physicalTopology } from "../mock";

const realView: TopologyView & { coverage?: unknown } = {
  view_id: "topology-graph",
  mode: "explore",
  scope: { tenant_id: "t_acme" },
  layout_type: "spine_leaf",
  generated_at: "2026-07-20T00:00:00Z",
  nodes: [
    {
      id: "wan-r2", label: "wan-r2", kind: "device", role: "router",
      site: "hq", health: "healthy", confidence: 0.95, resolved: true,
      tags: { vendor: "cisco" },
      evidence: [{ source: "snmp", confidence: 0.95, detail: "sysName wan-r2" }],
    },
    {
      id: "lan-sw1", label: "lan-sw1", kind: "device", role: "switch",
      site: "hq", health: "healthy", confidence: 0.9, resolved: true,
      tags: { vendor: "arista" },
      evidence: [{ source: "lldp", confidence: 0.9, detail: "lldp neighbour" }],
    },
  ],
  edges: [
    {
      id: "wan-r2:lan-sw1", source: "wan-r2", target: "lan-sw1",
      relationship: "physical_link", protocol: "lldp", status: "up", confidence: 0.9,
      evidence: [{ source: "lldp", confidence: 0.9, detail: "Gi0/1 ↔ Et1" }],
    },
  ],
  groups: [],
  overlays: ["health"],
  coverage: { nodes: 2, edges: 1, stale_nodes: 0, stale_edges: 0, resolved_edges: 1 },
};

// NB: mockImplementation(() => Promise.resolve/reject(...)) rather than
// mockResolvedValue/mockRejectedValue — see the note in cloudTopology.test.ts.
beforeEach(() => {
  topologyGraph.mockReset();
});

describe("fetchTopologyGraph", () => {
  it("serves the live reconciled graph, with its coverage summary, when it has content", async () => {
    topologyGraph.mockImplementation(() => Promise.resolve(realView));
    const { view, coverage, status } = await fetchTopologyGraph();
    expect(status).toBe("live");
    expect(view.nodes.map((n) => n.id).sort()).toEqual(["lan-sw1", "wan-r2"]);
    expect(coverage?.nodes).toBe(2);
  });

  it("returns an honest EMPTY view (never the mock) when the graph has no nodes", async () => {
    topologyGraph.mockImplementation(() => Promise.resolve({ ...realView, nodes: [], edges: [] }));
    const { view, coverage, status } = await fetchTopologyGraph();
    expect(status).toBe("empty");
    expect(view.nodes.length).toBe(0);
    expect(view.edges.length).toBe(0);
    expect(coverage).toBeUndefined();
  });

  it("returns an honest EMPTY view with status=error on an API error", async () => {
    topologyGraph.mockImplementation(() => Promise.reject(new Error("network")));
    // fetchTopologyGraph owns the rejection and resolves to the empty view — it
    // must never propagate the error, and never substitute a mock.
    const { view, status } = await fetchTopologyGraph();
    expect(status).toBe("error");
    expect(view.nodes.length).toBe(0);
  });

  it("never returns any node from the bundled physical mock, on either failure path", async () => {
    const mockIds = new Set(physicalTopology.nodes.map((n) => n.id));
    expect(mockIds.size).toBeGreaterThan(0); // the mock exists — this is a real guard

    topologyGraph.mockImplementation(() => Promise.reject(new Error("boom")));
    const errored = await fetchTopologyGraph();
    expect(errored.view.nodes.some((n) => mockIds.has(n.id))).toBe(false);

    topologyGraph.mockImplementation(() => Promise.resolve({ ...realView, nodes: [], edges: [] }));
    const emptied = await fetchTopologyGraph();
    expect(emptied.view.nodes.some((n) => mockIds.has(n.id))).toBe(false);
  });
});
