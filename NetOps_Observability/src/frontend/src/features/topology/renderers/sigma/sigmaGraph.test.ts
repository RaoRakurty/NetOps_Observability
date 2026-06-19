import { describe, it, expect } from "vitest";
import { buildSigmaGraph, nodeSize, SIGMA_FA2_ITERATIONS } from "./sigmaGraph";
import { topologyToSigma } from "./topologyToSigma";
import { makeEnterpriseScale } from "../../mock/enterpriseScaleTopology";
import type { TopologyView } from "../../api/topologyTypes";

const small: TopologyView = {
  view_id: "v",
  mode: "explore",
  layout_type: "campus",
  generated_at: "t",
  overlays: ["health"],
  groups: [],
  nodes: [
    { id: "a", label: "A", kind: "switch", site: "nyc", health: "ok", confidence: 1, evidence: [] },
    { id: "b", label: "B", kind: "switch", site: "nyc", health: "warning", confidence: 1, evidence: [] },
    { id: "c", label: "C", kind: "server", site: "nyc", health: "critical", confidence: 1, evidence: [] },
  ],
  edges: [
    { id: "ab", source: "a", target: "b", relationship: "connected_to", confidence: 1, evidence: [{ source: "lldp", confidence: 1, observed_at: "t", raw_ref: "r" }] },
    { id: "ac", source: "a", target: "c", relationship: "connected_to", confidence: 1, evidence: [{ source: "lldp", confidence: 1, observed_at: "t", raw_ref: "r" }] },
    { id: "self", source: "a", target: "a", relationship: "connected_to", confidence: 1, evidence: [{ source: "lldp", confidence: 1, observed_at: "t", raw_ref: "r" }] },
  ],
};

describe("topologyToSigma", () => {
  it("clusters by site and carries health/kind", () => {
    const d = topologyToSigma(small);
    expect(d.nodes.find((n) => n.key === "a")!.attributes.cluster).toBe("nyc");
    expect(d.nodes.find((n) => n.key === "c")!.attributes.health).toBe("critical");
  });
});

describe("buildSigmaGraph", () => {
  it("builds an undirected graph, drops self-edges, assigns finite positions", () => {
    const g = buildSigmaGraph(small);
    expect(g.order).toBe(3);
    expect(g.size).toBe(2); // ab + ac, self-loop dropped
    g.forEachNode((_n, attrs) => {
      expect(Number.isFinite(attrs.x)).toBe(true);
      expect(Number.isFinite(attrs.y)).toBe(true);
    });
    // hub 'a' (degree 2) is larger than a leaf (degree 1)
    expect(g.getNodeAttribute("a", "size")).toBeGreaterThan(g.getNodeAttribute("c", "size"));
  });

  it("is deterministic — same view yields identical positions", () => {
    const g1 = buildSigmaGraph(small);
    const g2 = buildSigmaGraph(small);
    expect(g1.getNodeAttribute("a", "x")).toBe(g2.getNodeAttribute("a", "x"));
    expect(g1.getNodeAttribute("b", "y")).toBe(g2.getNodeAttribute("b", "y"));
  });

  it("colours nodes by health", () => {
    const g = buildSigmaGraph(small);
    // ok and critical must differ
    expect(g.getNodeAttribute("a", "color")).not.toBe(g.getNodeAttribute("c", "color"));
  });
});

describe("nodeSize", () => {
  it("grows with degree and clamps", () => {
    expect(nodeSize(0)).toBeLessThan(nodeSize(4));
    expect(nodeSize(10_000)).toBeLessThan(20);
  });
});

describe("makeEnterpriseScale", () => {
  it("generates a large, well-formed graph", () => {
    const v = makeEnterpriseScale();
    expect(v.nodes.length).toBeGreaterThan(300);
    const ids = new Set(v.nodes.map((n) => n.id));
    // every edge connects existing nodes and carries evidence
    for (const e of v.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
      expect(e.evidence.length).toBeGreaterThan(0);
    }
    expect(v.renderer_hints?.preferred).toBe("sigma");
  });

  it("is deterministic", () => {
    const a = makeEnterpriseScale(4, 7);
    const b = makeEnterpriseScale(4, 7);
    expect(a.nodes.length).toBe(b.nodes.length);
    expect(a.edges.length).toBe(b.edges.length);
    expect(a.nodes[10].health).toBe(b.nodes[10].health);
  });
});

it("FA2 iteration budget is sane", () => {
  expect(SIGMA_FA2_ITERATIONS).toBeGreaterThanOrEqual(50);
});
