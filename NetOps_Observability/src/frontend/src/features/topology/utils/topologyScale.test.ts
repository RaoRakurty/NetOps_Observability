// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyScale.test.ts — the interactive-canvas scale policy.

import { describe, it, expect } from "vitest";
import type { TopologyView, TopologyNode, TopologyGroup } from "../api/topologyTypes";
import {
  renderedNodeCount,
  allGroupIds,
  canAggregateUnderCeiling,
  expansionWouldExceed,
} from "./topologyScale";
import { makeEnterpriseScale } from "../mock/enterpriseScaleTopology";

function node(id: string): TopologyNode {
  return { id, label: id } as unknown as TopologyNode;
}
function group(id: string, children: string[]): TopologyGroup {
  return { id, label: id, group_type: "site", children, health: "ok", collapsed: false } as unknown as TopologyGroup;
}
function view(nodes: TopologyNode[], groups: TopologyGroup[]): TopologyView {
  return { view_id: "v", nodes, edges: [], groups } as unknown as TopologyView;
}

describe("renderedNodeCount", () => {
  it("counts every device + every group when nothing is collapsed", () => {
    const v = view([node("a"), node("b"), node("c")], [group("g1", ["a", "b"])]);
    // 3 devices + 1 group container = 4
    expect(renderedNodeCount(v, new Set())).toBe(4);
  });

  it("hides a collapsed group's children (aggregate card replaces them)", () => {
    const v = view([node("a"), node("b"), node("c")], [group("g1", ["a", "b"])]);
    // collapsed g1: a,b hidden; visible = c (1) + g1 card (1) = 2
    expect(renderedNodeCount(v, new Set(["g1"]))).toBe(2);
  });

  it("keeps ungrouped devices visible even when every group is collapsed", () => {
    const v = view([node("a"), node("b"), node("c")], [group("g1", ["a"])]);
    // collapse g1: a hidden; b,c ungrouped stay; +1 card → 3
    expect(renderedNodeCount(v, allGroupIds(v))).toBe(3);
  });
});

describe("canAggregateUnderCeiling", () => {
  it("is false for a large FLAT graph (no grouping dimension)", () => {
    const nodes = Array.from({ length: 1500 }, (_, i) => node(`n${i}`));
    expect(canAggregateUnderCeiling(view(nodes, []), 1000)).toBe(false);
  });

  it("is true for a large GROUPED graph that collapses under the ceiling", () => {
    const big = makeEnterpriseScale(40); // > 1000 nodes, 40 site groups
    expect(big.nodes.length).toBeGreaterThan(1000);
    expect(canAggregateUnderCeiling(big, 1000)).toBe(true);
    // fully collapsed, the canvas draws ~40 group cards — far under the ceiling
    expect(renderedNodeCount(big, allGroupIds(big))).toBeLessThanOrEqual(1000);
  });

  it("is false when even fully collapsed the count still exceeds the ceiling", () => {
    // 1500 ungrouped devices + one tiny group: collapsing the group cannot help.
    const nodes = Array.from({ length: 1500 }, (_, i) => node(`n${i}`));
    const v = view(nodes, [group("g1", ["n0", "n1"])]);
    expect(canAggregateUnderCeiling(v, 1000)).toBe(false);
  });
});

describe("expansionWouldExceed (drill-down guard)", () => {
  it("blocks expanding a single group whose devices alone blow the ceiling", () => {
    const nodes = Array.from({ length: 1200 }, (_, i) => node(`n${i}`));
    const v = view(nodes, [group("huge", nodes.map((n) => n.id))]);
    // collapsed: 1 card. Expanding reveals 1200 devices → over 1000.
    expect(expansionWouldExceed(v, allGroupIds(v), "huge", 1000)).toBe(true);
  });

  it("allows expanding a normal-sized group (reveals its devices under budget)", () => {
    const big = makeEnterpriseScale(40);
    const collapsed = allGroupIds(big);
    const someGroup = big.groups[0].id;
    expect(expansionWouldExceed(big, collapsed, someGroup, 1000)).toBe(false);
    // expanding it genuinely reveals more nodes than the fully-collapsed view
    const expanded = new Set(collapsed);
    expanded.delete(someGroup);
    expect(renderedNodeCount(big, expanded)).toBeGreaterThan(renderedNodeCount(big, collapsed));
  });
});
