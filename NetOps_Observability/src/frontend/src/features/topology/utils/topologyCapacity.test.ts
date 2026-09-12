// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import {
  rankHotLinks,
  saturatedEdgeIds,
  ecmpGroups,
  linkHeadroom,
  simulateDrain,
  SATURATION_THRESHOLD,
  ECMP_IMBALANCE_SPREAD,
} from "./topologyCapacity";
import type { TopologyView, TopologyEdge } from "../api/topologyTypes";

// Minimal view builder — only the fields the capacity helpers read.
function edge(p: Partial<TopologyEdge> & { id: string; source: string; target: string }): TopologyEdge {
  return {
    relationship: "connected_to",
    confidence: 0.9,
    evidence: [{ source: "lldp", confidence: 0.9, observed_at: "t", raw_ref: "r" }],
    ...p,
  };
}

function view(edges: TopologyEdge[]): TopologyView {
  const ids = new Set<string>();
  edges.forEach((e) => {
    ids.add(e.source);
    ids.add(e.target);
  });
  return {
    view_id: "v",
    mode: "capacity",
    layout_type: "spine_leaf",
    generated_at: "t",
    nodes: [...ids].map((id) => ({ id, label: id.toUpperCase(), kind: "switch", health: "ok", confidence: 1, evidence: [] })),
    edges,
    groups: [],
    overlays: ["utilization"],
  };
}

describe("rankHotLinks", () => {
  it("ranks measured links busiest-first and excludes unmeasured ones", () => {
    const v = view([
      edge({ id: "a", source: "leaf1", target: "spine1", utilization_pct: 40 }),
      edge({ id: "b", source: "leaf2", target: "spine1", utilization_pct: 92 }),
      edge({ id: "c", source: "leaf3", target: "spine1" }), // unmeasured → excluded
      edge({ id: "d", source: "leaf4", target: "spine1", utilization_pct: 70 }),
    ]);
    const hot = rankHotLinks(v);
    expect(hot.map((h) => h.edge.id)).toEqual(["b", "d", "a"]);
    expect(hot.find((h) => h.edge.id === "c")).toBeUndefined();
  });

  it("flags saturation and errors, and resolves endpoint labels", () => {
    const v = view([
      edge({ id: "x", source: "leaf1", target: "spine1", utilization_pct: SATURATION_THRESHOLD, errors: 1200 }),
      edge({ id: "y", source: "leaf2", target: "spine1", utilization_pct: 84 }),
    ]);
    const hot = rankHotLinks(v);
    const x = hot.find((h) => h.edge.id === "x")!;
    expect(x.saturated).toBe(true);
    expect(x.errored).toBe(true);
    expect(x.sourceLabel).toBe("LEAF1");
    expect(x.targetLabel).toBe("SPINE1");
    expect(hot.find((h) => h.edge.id === "y")!.saturated).toBe(false);
  });

  it("honours the limit", () => {
    const v = view(
      Array.from({ length: 12 }, (_, i) =>
        edge({ id: `e${i}`, source: `leaf${i}`, target: "spine1", utilization_pct: i * 5 }),
      ),
    );
    expect(rankHotLinks(v, 3)).toHaveLength(3);
  });
});

describe("saturatedEdgeIds", () => {
  it("returns only edges at/above the saturation threshold", () => {
    const v = view([
      edge({ id: "hot", source: "l1", target: "s1", utilization_pct: 96 }),
      edge({ id: "edge", source: "l2", target: "s1", utilization_pct: SATURATION_THRESHOLD }),
      edge({ id: "cool", source: "l3", target: "s1", utilization_pct: 30 }),
      edge({ id: "blank", source: "l4", target: "s1" }),
    ]);
    expect([...saturatedEdgeIds(v)].sort()).toEqual(["edge", "hot"]);
  });
});

describe("ecmpGroups", () => {
  it("flags a node whose sibling links diverge past the spread threshold", () => {
    // leaf1 uplinks: 92 vs 61 → spread 31 (imbalanced). leaf2: 88 vs 84 → spread 4 (balanced).
    const v = view([
      edge({ id: "u1", source: "leaf1", target: "spine1", utilization_pct: 92 }),
      edge({ id: "u2", source: "leaf1", target: "spine2", utilization_pct: 61 }),
      edge({ id: "u3", source: "leaf2", target: "spine1", utilization_pct: 88 }),
      edge({ id: "u4", source: "leaf2", target: "spine2", utilization_pct: 84 }),
    ]);
    const groups = ecmpGroups(v);
    const leaf1 = groups.find((g) => g.node === "leaf1");
    expect(leaf1).toBeDefined();
    expect(leaf1!.spread).toBe(31);
    expect(leaf1!.imbalanced).toBe(true);
    // leaf2's spread (4) is below threshold → not returned.
    expect(groups.find((g) => g.node === "leaf2")).toBeUndefined();
    expect(ECMP_IMBALANCE_SPREAD).toBeLessThanOrEqual(31);
  });

  it("ignores single-link nodes and sorts by spread desc", () => {
    const v = view([
      edge({ id: "a", source: "leaf1", target: "spine1", utilization_pct: 95 }),
      edge({ id: "b", source: "leaf1", target: "spine2", utilization_pct: 40 }), // leaf1 spread 55
      edge({ id: "c", source: "leaf2", target: "spine1", utilization_pct: 80 }),
      edge({ id: "d", source: "leaf2", target: "spine2", utilization_pct: 50 }), // leaf2 spread 30
    ]);
    const groups = ecmpGroups(v);
    // spine1 also has incident links (95,80 spread 15 < 25 → out). Top is leaf1 (55).
    expect(groups[0].node).toBe("leaf1");
    expect(groups.map((g) => g.spread)).toEqual([...groups.map((g) => g.spread)].sort((x, y) => y - x));
  });
});

describe("linkHeadroom & simulateDrain (P3 capacity what-if)", () => {
  it("computes headroom to saturation and flags single-points-of-failure", () => {
    const v = view([
      edge({ id: "e1", source: "leaf1", target: "spine1", utilization_pct: 60 }),
      edge({ id: "e2", source: "leaf1", target: "spine2", utilization_pct: 20 }),
      edge({ id: "solo", source: "leaf9", target: "wan", utilization_pct: 10 }),
    ]);
    const hr = linkHeadroom(v);
    const e1 = hr.find((h) => h.edge.id === "e1")!;
    expect(e1.headroom).toBe(SATURATION_THRESHOLD - 60);
    expect(e1.spof).toBe(false); // leaf1 has a sibling uplink (e2)
    expect(hr.find((h) => h.edge.id === "solo")!.spof).toBe(true); // no sibling
    expect(hr[0].headroom).toBeLessThanOrEqual(hr[hr.length - 1].headroom); // least headroom first
  });

  it("redistributes a drained link's load across surviving ECMP siblings and flags saturation", () => {
    const v = view([
      edge({ id: "up1", source: "leaf1", target: "spine1", utilization_pct: 80 }),
      edge({ id: "up2", source: "leaf1", target: "spine2", utilization_pct: 70 }),
    ]);
    const impact = simulateDrain(v, "up1");
    const leaf = impact.find((d) => d.node === "leaf1")!;
    expect(leaf.stranded).toBe(false);
    // up1's 80% moves onto the one surviving sibling up2 → 70 + 80 = 150% → saturates.
    const sib = leaf.redistributed[0];
    expect(sib.edge.id).toBe("up2");
    expect(sib.after).toBe(150);
    expect(sib.saturates).toBe(true);
  });

  it("marks an endpoint stranded when a drained link has no surviving sibling", () => {
    const v = view([edge({ id: "only", source: "leafX", target: "spineX", utilization_pct: 30 })]);
    const impact = simulateDrain(v, "only");
    expect(impact.every((d) => d.stranded)).toBe(true);
  });
});

describe("capacity refuses fake precision (P8 #7, non-negotiable)", () => {
  it("never simulates or ranks an UNMEASURED link", () => {
    const v = view([
      edge({ id: "unmeasured", source: "a", target: "b" }), // no utilization_pct → unknown, not 0
      edge({ id: "measured", source: "a", target: "c", utilization_pct: 50 }),
    ]);
    // can't redistribute load we never measured → empty (no fabricated after-utilization)
    expect(simulateDrain(v, "unmeasured")).toEqual([]);
    // unmeasured links are excluded from headroom + hot-link ranking entirely
    expect(linkHeadroom(v).some((h) => h.edge.id === "unmeasured")).toBe(false);
    expect(rankHotLinks(v).some((l) => l.edge.id === "unmeasured")).toBe(false);
  });
})
