// cloudMerge.test.ts — #131. The cloud projection joins the fabric on ONE canvas.
// The rules that matter are the ones that keep the merge from being a lie: the
// on-prem inventory wins every identity collision, no edge is drawn to a node
// that did not come across, and a tenant with no cloud network gets the exact
// canvas it had before.

import { describe, it, expect } from "vitest";
import { mergeCloudView } from "./cloudMerge";
import type { TopologyView, TopologyNode, TopologyEdge, TopologyGroup } from "../api/topologyTypes";

const ev = [{ source: "lldp" as const, confidence: 0.9 }];

function node(id: string, over: Partial<TopologyNode> = {}): TopologyNode {
  return { id, label: id, kind: "switch", health: "ok", confidence: 1, evidence: ev, ...over } as TopologyNode;
}
function edge(id: string, source: string, target: string, over: Partial<TopologyEdge> = {}): TopologyEdge {
  return { id, source, target, relationship: "connected_to", confidence: 1, evidence: ev, ...over } as TopologyEdge;
}
/** A lateral seam link as cloud/seam_links.go emits it (#131c). */
function seamEdge(id: string, source: string, target: string, over: Partial<TopologyEdge> = {}): TopologyEdge {
  return edge(id, source, target, {
    relationship: "connected_to",
    protocol: "cloud_api",
    status: "up",
    confidence: 0.9,
    tags: { seam_group_id: "aws|vpc=vpc-1,vpc=vpc-2" },
    ...over,
  });
}
function group(id: string, children: string[], over: Partial<TopologyGroup> = {}): TopologyGroup {
  return { id, label: id, group_type: "site", children, health: "unknown", collapsed: false, ...over } as TopologyGroup;
}
function view(over: Partial<TopologyView>): TopologyView {
  return {
    view_id: "base",
    mode: "explore",
    layout_type: "spine_leaf",
    generated_at: "2026-08-02T00:00:00Z",
    nodes: [],
    edges: [],
    groups: [],
    overlays: ["health"],
    ...over,
  } as unknown as TopologyView;
}

const fabric = view({
  nodes: [node("core-1"), node("edge-9")],
  edges: [edge("e-core-edge", "core-1", "edge-9")],
  groups: [group("site:hq", ["core-1", "edge-9"])],
});

const cloud = view({
  view_id: "cloud-network",
  layout_type: "cloud_grouped",
  nodes: [
    node("subnet-app", { kind: "cloud", tags: { provider: "aws", region: "us-west-2", vpc: "vpc-1" } }),
    node("igw-1", { kind: "cloud", tags: { provider: "aws", region: "us-west-2" } }),
  ],
  edges: [edge("route-1", "subnet-app", "igw-1")],
  groups: [
    group("region:aws:us-west-2", [], { group_type: "region" }),
    group("vpc-1", ["subnet-app"], { group_type: "vpc", parent_id: "region:aws:us-west-2" }),
  ],
  overlays: ["health"],
});

describe("mergeCloudView", () => {
  it("puts cloud nodes, edges and the nested region/VPC containers on the same canvas", () => {
    const out = mergeCloudView(fabric, cloud);
    expect(out.nodes.map((n) => n.id).sort()).toEqual(["core-1", "edge-9", "igw-1", "subnet-app"]);
    expect(out.edges.map((e) => e.id).sort()).toEqual(["e-core-edge", "route-1"]);
    expect(out.groups.map((g) => g.id).sort()).toEqual(["region:aws:us-west-2", "site:hq", "vpc-1"]);
    expect(out.groups.find((g) => g.id === "vpc-1")!.parent_id).toBe("region:aws:us-west-2");
  });

  it("keeps the BASE view's identity — layout cache and saved-layout keys stay the canvas's", () => {
    const out = mergeCloudView(fabric, cloud);
    expect(out.view_id).toBe("base");
    expect(out.layout_type).toBe("spine_leaf");
    expect(out.mode).toBe("explore");
  });

  it("is the IDENTITY for a tenant with no discovered cloud network", () => {
    expect(mergeCloudView(fabric, null)).toBe(fabric);
    expect(mergeCloudView(fabric, view({ nodes: [] }))).toBe(fabric);
  });

  it("the on-prem inventory WINS an id collision — a fixture never overwrites a discovered device", () => {
    const clash = view({ nodes: [node("core-1", { kind: "cloud", label: "not-your-device" })] });
    const out = mergeCloudView(fabric, clash);
    expect(out.nodes.filter((n) => n.id === "core-1")).toHaveLength(1);
    expect(out.nodes.find((n) => n.id === "core-1")!.label).toBe("core-1");
  });

  it("drops a cloud edge whose endpoint did not come across — never a link to nowhere", () => {
    const dangling = view({
      nodes: [node("subnet-app", { kind: "cloud" })],
      edges: [edge("route-x", "subnet-app", "tgw-missing")],
    });
    const out = mergeCloudView(fabric, dangling);
    expect(out.edges.map((e) => e.id)).not.toContain("route-x");
  });

  it("un-nests a container whose parent did not come across, rather than losing the VPC", () => {
    const orphan = view({
      nodes: [node("subnet-app", { kind: "cloud" })],
      groups: [group("vpc-1", ["subnet-app"], { group_type: "vpc", parent_id: "region-that-is-not-here" })],
    });
    const out = mergeCloudView(fabric, orphan);
    const vpc = out.groups.find((g) => g.id === "vpc-1");
    expect(vpc).toBeTruthy();
    expect(vpc!.parent_id).toBeUndefined();
  });

  // ── lateral seam links (#131c) ────────────────────────────────────────────
  //
  // The seam link is the answer to "is the problem on my side or theirs", so
  // what matters is that it arrives on the SAME canvas as everything else and
  // still reads as an OBSERVED claim once it is there.

  it("carries a lateral seam link between two cloud gateways onto the canvas", () => {
    const withSeam = view({
      ...cloud,
      nodes: [...cloud.nodes, node("tgw-a", { kind: "cloud" }), node("tgw-b", { kind: "cloud" })],
      edges: [...cloud.edges, seamEdge("seam-tgw_a-tgw_b", "tgw-a", "tgw-b")],
    });
    const out = mergeCloudView(fabric, withSeam);
    const seam = out.edges.find((e) => e.id === "seam-tgw_a-tgw_b");
    expect(seam).toBeTruthy();
    expect(seam!.tags?.seam_group_id).toBe("aws|vpc=vpc-1,vpc=vpc-2");
  });

  it("keeps an ON-PREM↔cloud seam link — both ends are on this canvas now (#130b)", () => {
    const withSeam = view({
      ...cloud,
      nodes: [...cloud.nodes, node("vpn-1", { kind: "cloud" })],
      // The target is an on-prem DEVICE from the fabric half; before the merge it
      // is not in the cloud view at all, which is the whole reason cloud used to
      // be a separate page.
      edges: [...cloud.edges, seamEdge("seam-vpn_1-edge_9", "vpn-1", "edge-9")],
    });
    const out = mergeCloudView(fabric, withSeam);
    expect(out.edges.map((e) => e.id)).toContain("seam-vpn_1-edge_9");
  });

  it("a seam link is OBSERVED, never the inferred class a route edge carries", () => {
    const withSeam = view({
      ...cloud,
      nodes: [...cloud.nodes, node("tgw-a", { kind: "cloud" }), node("tgw-b", { kind: "cloud" })],
      edges: [
        edge("route-2", "subnet-app", "tgw-a", { relationship: "routed_adjacency", confidence: 0.7 }),
        seamEdge("seam-tgw_a-tgw_b", "tgw-a", "tgw-b"),
      ],
    });
    const out = mergeCloudView(fabric, withSeam);
    const seam = out.edges.find((e) => e.id === "seam-tgw_a-tgw_b")!;
    const route = out.edges.find((e) => e.id === "route-2")!;
    // Different relationship classes: `bundleParallelEdges` keys its bundle on
    // the class, so an observed seam can never be collapsed into a route bundle.
    expect(seam.relationship).toBe("connected_to");
    expect(route.relationship).toBe("routed_adjacency");
    expect(seam.confidence).toBeGreaterThan(route.confidence);
  });

  it("drops a seam link whose far end was never discovered — no link to nowhere", () => {
    const dangling = view({
      ...cloud,
      edges: [...cloud.edges, seamEdge("seam-tgw_a-tgw_ghost", "subnet-app", "tgw-ghost")],
    });
    const out = mergeCloudView(fabric, dangling);
    expect(out.edges.map((e) => e.id)).not.toContain("seam-tgw_a-tgw_ghost");
  });

  it("does not mutate either input", () => {
    mergeCloudView(fabric, cloud);
    expect(fabric.nodes).toHaveLength(2);
    expect(cloud.nodes).toHaveLength(2);
  });
});
