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

// ── #131: cloud is classified by FACT, and a nested container survives the slice ──
describe("domainOfNode — cloud by fact, never by name", () => {
  function tagged(id: string, tags: Record<string, string>, role?: string): TopologyNode {
    return { id, label: id, kind: "router", role, health: "unknown", confidence: 1, evidence: [], tags };
  }

  it("a node that DECLARES a provider / vpc / region is cloud, whatever it is called", () => {
    expect(domainOfNode(tagged("i-0abc", { provider: "aws" }))).toBe("cloud");
    expect(domainOfNode(tagged("x", { vpc: "vpc-1" }))).toBe("cloud");
    expect(domainOfNode(tagged("y", { region: "westeurope" }))).toBe("cloud");
  });

  it("a cloud TRANSIT/VPN gateway lands in cloud, not SD-WAN — the fact beats the role regex", () => {
    // "vpn_gateway"/"transit_gateway" match the SD-WAN pattern; without the fact
    // check first, one VPC's gateways scatter across two domains.
    const gw = tagged("tgw-1", { provider: "aws", region: "us-west-2", vpc: "vpc-1" }, "transit_gateway");
    expect(domainOfNode(gw)).toBe("cloud");
    const vgw = tagged("vgw-1", { provider: "aws", vpc: "vpc-1" }, "vpn_gateway");
    expect(domainOfNode(vgw)).toBe("cloud");
  });

  it("an on-prem node with no cloud field is untouched by the fact rule", () => {
    expect(domainOfNode({ id: "wan1", label: "wan1", kind: "router", role: "wan-edge", health: "ok", confidence: 1, evidence: [] })).toBe("sdwan");
  });
});

describe("filterViewByDomain — nested containers survive the cloud slice", () => {
  const cloudNode = (id: string, tags: Record<string, string>): TopologyNode => ({
    id, label: id, kind: "cloud", health: "unknown", confidence: 1, evidence: [], tags,
  });
  const nested: TopologyView = {
    view_id: "v", mode: "explore", layout_type: "spine_leaf", generated_at: "t",
    nodes: [
      node("acc1", "switch", "access"),
      cloudNode("subnet-a", { provider: "aws", region: "us-west-2", vpc: "vpc-1" }),
    ],
    edges: [],
    groups: [
      { id: "site:hq", label: "HQ", group_type: "site", children: ["acc1"], health: "unknown", collapsed: false },
      { id: "region:aws:us-west-2", label: "aws · us-west-2", group_type: "region", children: [], health: "unknown", collapsed: false },
      { id: "vpc-1", label: "VPC · prod", group_type: "vpc", parent_id: "region:aws:us-west-2", children: ["subnet-a"], health: "unknown", collapsed: false },
    ],
    overlays: [],
  };

  it("keeps the REGION container whose only members are other groups", () => {
    const out = filterViewByDomain(nested, "cloud");
    const ids = out.groups.map((g) => g.id).sort();
    // Dropping "groups with no surviving children" deleted every region boundary.
    expect(ids).toEqual(["region:aws:us-west-2", "vpc-1"]);
    expect(out.nodes.map((n) => n.id)).toEqual(["subnet-a"]);
  });

  it("still drops a container with nothing below it at all", () => {
    const out = filterViewByDomain(nested, "cloud");
    expect(out.groups.map((g) => g.id)).not.toContain("site:hq");
  });
});
