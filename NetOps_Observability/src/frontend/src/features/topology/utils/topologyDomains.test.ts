// topologyDomains.test.ts — the domain classifier + filter. LAN is the identity
// (default unchanged); SD-WAN/DC slice; cloud nodes route to the cloud domain.

import { describe, it, expect } from "vitest";
import { domainOfNode, filterViewByDomain, DOMAINS } from "./topologyDomains";
import type { TopologyNode, TopologyView } from "../api/topologyTypes";

function node(id: string, kind: TopologyNode["kind"], role?: string, label = id): TopologyNode {
  return { id, label, kind, role, health: "unknown", confidence: 1, evidence: [] };
}

describe("domainOfNode", () => {
  it("routes cloud-kind nodes to the cloud domain", () => {
    expect(domainOfNode(node("v", "cloud", "subnet"))).toBe("cloud");
  });
  it("classifies WAN/SD-WAN edges", () => {
    expect(domainOfNode(node("g", "router", "wan-edge"))).toBe("sdwan");
    expect(domainOfNode(node("t", "router", "vpn-gateway"))).toBe("sdwan");
  });
  it("classifies DC fabric roles", () => {
    expect(domainOfNode(node("s", "switch", "spine"))).toBe("dc");
    expect(domainOfNode(node("l", "switch", "leaf"))).toBe("dc");
  });
  it("falls back to LAN (never drops a node)", () => {
    expect(domainOfNode(node("a", "switch", "access"))).toBe("lan");
  });
});

describe("filterViewByDomain", () => {
  const view: TopologyView = {
    view_id: "v", mode: "explore", layout_type: "campus", generated_at: "t",
    nodes: [
      node("spine1", "switch", "spine"),
      node("leaf1", "switch", "leaf"),
      node("wan1", "router", "wan-edge"),
      node("acc1", "switch", "access"),
    ],
    edges: [
      { id: "e1", source: "spine1", target: "leaf1", relationship: "connected_to", confidence: 1, evidence: [{ source: "lldp", confidence: 1, detail: "", observed_at: "t", raw_ref: "r", summary: "s" }] },
      { id: "e2", source: "leaf1", target: "acc1", relationship: "connected_to", confidence: 1, evidence: [{ source: "lldp", confidence: 1, detail: "", observed_at: "t", raw_ref: "r", summary: "s" }] },
    ],
    groups: [{ id: "g1", label: "DC", group_type: "pod", children: ["spine1", "leaf1"], health: "unknown", collapsed: false }],
    overlays: [],
  };

  it("LAN returns the view UNCHANGED (identity — default is untouched)", () => {
    expect(filterViewByDomain(view, "lan")).toBe(view);
  });

  it("DC keeps only spine/leaf and prunes cross-domain edges", () => {
    const out = filterViewByDomain(view, "dc");
    const ids = out.nodes.map((n) => n.id).sort();
    expect(ids).toEqual(["leaf1", "spine1"]);
    expect(out.edges.map((e) => e.id)).toEqual(["e1"]); // e2 (leaf→access) dropped
    expect(out.groups[0].children).toEqual(["spine1", "leaf1"]);
  });

  it("SD-WAN keeps only the WAN edge", () => {
    const out = filterViewByDomain(view, "sdwan");
    expect(out.nodes.map((n) => n.id)).toEqual(["wan1"]);
    expect(out.edges).toEqual([]);
    expect(out.groups).toEqual([]); // empty group pruned
  });

  it("exposes exactly the four network domains", () => {
    expect(DOMAINS.map((d) => d.id)).toEqual(["lan", "sdwan", "dc", "cloud"]);
  });
});
