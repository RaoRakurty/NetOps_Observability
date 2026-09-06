// topologyRegroup.test.ts — the group-by lens, and #131b's two new dimensions.
//
// Region and VPC bucket from the FACTS the cloud projection stamps on each node
// (tags.region / tags.vpc), which is the whole point: a VPC is a discovered
// field, not a naming convention, and an on-prem node that has no such field must
// stay honestly outside the lens rather than be invented into one.

import { describe, it, expect } from "vitest";
import { regroupView, GROUP_DIMENSIONS } from "./topologyRegroup";
import type { TopologyView, TopologyNode } from "../api/topologyTypes";

function node(id: string, over: Partial<TopologyNode> = {}): TopologyNode {
  return { id, label: id, kind: "switch", health: "ok", confidence: 1, evidence: [], ...over } as TopologyNode;
}

const view: TopologyView = {
  view_id: "v",
  mode: "explore",
  layout_type: "spine_leaf",
  generated_at: "t",
  nodes: [
    node("core-1", { site: "HQ" }), // on-prem: no cloud facts at all
    node("subnet-a", { kind: "cloud", tags: { provider: "aws", region: "us-west-2", vpc: "vpc-1" } }),
    node("subnet-b", { kind: "cloud", tags: { provider: "aws", region: "us-west-2", vpc: "vpc-1" } }),
    node("subnet-c", { kind: "cloud", tags: { provider: "aws", region: "us-east-1", vpc: "vpc-2" } }),
    node("snet-1", { kind: "cloud", tags: { provider: "azure", region: "westeurope", vpc: "vnet-1" } }),
  ],
  edges: [],
  groups: [{ id: "site:HQ", label: "HQ", group_type: "site", children: ["core-1"], health: "ok", collapsed: false }],
  overlays: [],
} as unknown as TopologyView;

describe("GROUP_DIMENSIONS", () => {
  it("offers Region and VPC alongside the on-prem lenses", () => {
    const ids = GROUP_DIMENSIONS.map((d) => d.id);
    expect(ids).toContain("region");
    expect(ids).toContain("vpc");
    // "None" stays last — it is the clear-grouping escape, not a dimension.
    expect(ids[ids.length - 1]).toBe("none");
  });
});

describe("regroupView — region", () => {
  it("buckets cloud nodes by their discovered region", () => {
    const out = regroupView(view, "region");
    const byId = new Map(out.groups.map((g) => [g.id, g]));
    expect([...byId.keys()].sort()).toEqual(["region:us-east-1", "region:us-west-2", "region:westeurope"]);
    expect(byId.get("region:us-west-2")!.children).toEqual(["subnet-a", "subnet-b"]);
    expect(byId.get("region:us-west-2")!.group_type).toBe("region");
  });

  it("qualifies the label with the provider — two providers' 'us-east-1' are two places", () => {
    const out = regroupView(view, "region");
    expect(out.groups.find((g) => g.id === "region:westeurope")!.label).toBe("azure · westeurope");
    expect(out.groups.find((g) => g.id === "region:us-west-2")!.label).toBe("aws · us-west-2");
  });

  it("leaves an on-prem node with no region UNGROUPED — never invented into a region", () => {
    const out = regroupView(view, "region");
    for (const g of out.groups) expect(g.children).not.toContain("core-1");
    // The node itself is still on the canvas; only its grouping is absent.
    expect(out.nodes.map((n) => n.id)).toContain("core-1");
  });
});

describe("regroupView — vpc", () => {
  it("buckets by the discovered VPC/VNet id", () => {
    const out = regroupView(view, "vpc");
    const byId = new Map(out.groups.map((g) => [g.id, g]));
    expect([...byId.keys()].sort()).toEqual(["vpc:vnet-1", "vpc:vpc-1", "vpc:vpc-2"]);
    expect(byId.get("vpc:vpc-1")!.children).toEqual(["subnet-a", "subnet-b"]);
    expect(byId.get("vpc:vpc-1")!.group_type).toBe("vpc");
  });

  it("rolls the worst member health up to the container", () => {
    const unhealthy: TopologyView = {
      ...view,
      nodes: view.nodes.map((n) => (n.id === "subnet-b" ? { ...n, health: "critical" as const } : n)),
    };
    const out = regroupView(unhealthy, "vpc");
    expect(out.groups.find((g) => g.id === "vpc:vpc-1")!.health).toBe("critical");
  });
});

describe("regroupView — the untouched lenses", () => {
  it("site keeps the backend's own grouping (identity)", () => {
    expect(regroupView(view, "site")).toBe(view);
  });
  it("none clears grouping without touching the nodes", () => {
    const out = regroupView(view, "none");
    expect(out.groups).toEqual([]);
    expect(out.nodes).toHaveLength(view.nodes.length);
  });
});
