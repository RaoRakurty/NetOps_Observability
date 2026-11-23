// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { ancestorGroups, dropMovedGroupRects, groupDescendants, moveGroup } from "./groupDrag";
import { topologyToReactFlow } from "../renderers/react-flow/topologyToReactFlow";
import type { TopologyView } from "../api/topologyTypes";
import type { LayoutResult } from "./layoutTypes";

// Two branch sites (50: two edges, 80: one) plus a region → VPC nest, as the
// canvas receives them.
function view(): TopologyView {
  return {
    view_id: "v", mode: "explore", scope: { tenant_id: "t" }, layout_type: "hierarchical",
    generated_at: "2026-11-23T00:00:00Z",
    nodes: ["e51", "e52", "e80", "vm1"].map((id) => ({ id, label: id, kind: "router", health: "ok", confidence: 1, resolved: true })),
    edges: [],
    groups: [
      { id: "site:50", label: "Site 50", group_type: "site", children: ["e51", "e52"], health: "ok", collapsed: false },
      { id: "site:80", label: "Site 80", group_type: "site", children: ["e80"], health: "ok", collapsed: false },
      { id: "region", label: "us-east-1", group_type: "region", children: [], health: "ok", collapsed: false },
      { id: "vpc", label: "vpc-1", group_type: "vpc", children: ["vm1"], health: "ok", collapsed: false, parent_id: "region" },
    ],
    overlays: [],
  } as unknown as TopologyView;
}

const solved: LayoutResult = {
  e51: { x: 100, y: 100 }, e52: { x: 400, y: 100 }, e80: { x: 900, y: 100 }, vm1: { x: 100, y: 600 },
  "site:50": { x: 76, y: 40, w: 600, h: 200 },
  "site:80": { x: 876, y: 40, w: 300, h: 200 },
  vpc: { x: 76, y: 540, w: 300, h: 200 },
  region: { x: 50, y: 500, w: 360, h: 260 },
};

describe("groupDrag", () => {
  it("knows a box's devices and nested boxes, and a device's boxes innermost first", () => {
    expect(groupDescendants(view(), "site:50")).toEqual({ nodes: ["e51", "e52"], groups: [] });
    expect(groupDescendants(view(), "region")).toEqual({ nodes: ["vm1"], groups: ["vpc"] });
    expect(ancestorGroups(view(), "vm1")).toEqual(["vpc", "region"]);
    expect(ancestorGroups(view(), "loose")).toEqual([]);
  });

  it("moving a box moves only ITS devices — the other box stays where it was", () => {
    const r = moveGroup(view(), solved, "site:50", 30, 70);
    expect(r.moved).toEqual({ e51: { x: 130, y: 170 }, e52: { x: 430, y: 170 } });
    expect(r.positions.e80).toEqual(solved.e80);
    expect(r.positions["site:80"]).toEqual(solved["site:80"]);
    // the moved box is re-drawn around its devices, not at the solved rectangle
    expect(r.positions["site:50"]).toBeUndefined();
  });

  it("moving an outer box carries the nested box and its devices", () => {
    const r = moveGroup(view(), solved, "region", -20, 10);
    expect(r.moved).toEqual({ vm1: { x: 80, y: 610 } });
    expect(r.positions.vpc).toBeUndefined();
    expect(r.positions.region).toBeUndefined();
  });

  it("moving an inner box re-fits the box it sits in", () => {
    const r = moveGroup(view(), solved, "vpc", 500, 0);
    expect(r.positions.region).toBeUndefined();
  });

  it("refuses a non-finite delta and never mutates its input", () => {
    const before = JSON.stringify(solved);
    expect(moveGroup(view(), solved, "site:50", NaN, 1).moved).toEqual({});
    moveGroup(view(), solved, "site:50", 5, 5);
    expect(JSON.stringify(solved)).toBe(before);
  });

  it("a hand-placed device drops only the rectangles of the boxes it sits in", () => {
    const p = dropMovedGroupRects(view(), solved, ["vm1"]);
    expect(p.vpc).toBeUndefined();
    expect(p.region).toBeUndefined();
    expect(p["site:50"]).toEqual(solved["site:50"]);
  });
});

const EMPTY = {
  selection: {}, spotlight: new Set<string>(), strongEdges: new Set<string>(), overlay: "health" as const,
  showAllLabels: false, searchMatches: new Set<string>(), collapsedGroups: new Set<string>(), density: "operator" as const,
};

describe("rendered boxes after a move", () => {
  const boxes = (positions: LayoutResult) =>
    Object.fromEntries(
      topologyToReactFlow(view(), positions).nodes
        .filter((n) => n.type === "groupNode")
        .map((n) => [n.id, { x: n.position.x, y: n.position.y, w: n.width as number, h: n.height as number, drag: n.draggable }]),
    );

  it("every box is draggable", () => {
    for (const b of Object.values(boxes(solved))) expect(b.drag).toBe(true);
  });

  it("each expanded box has a label handle drawn ABOVE the links, at its top-left", () => {
    const out = topologyToReactFlow(view(), solved).nodes;
    const label = out.find((n) => n.id === "group-label:site:50");
    expect(label?.type).toBe("groupLabelNode");
    expect(label?.draggable).toBe(true);
    expect(label?.zIndex).toBeGreaterThan(1); // devices are 1; links follow their nodes
    expect(label?.position).toEqual({ x: 76 + 10, y: 40 + 8 });
    // a collapsed box is its own card: no separate handle
    const collapsed = topologyToReactFlow(view(), solved, { ...EMPTY, collapsedGroups: new Set(["site:50"]) }).nodes;
    expect(collapsed.find((n) => n.id === "group-label:site:50")).toBeUndefined();
  });

  it("a moved box is drawn around its devices where they landed; the other box is untouched", () => {
    const r = moveGroup(view(), solved, "site:50", 30, 70);
    const b = boxes(r.positions);
    // devices now span x 130..(430+card), y 170..(170+card); the box encloses them
    expect(b["site:50"].x).toBeLessThan(130);
    expect(b["site:50"].y).toBeLessThan(170);
    expect(b["site:50"].x + b["site:50"].w).toBeGreaterThan(430);
    expect(b["site:80"]).toMatchObject({ x: 876, y: 40, w: 300, h: 200 });
  });

  it("a re-drawn outer box encloses its re-drawn inner box", () => {
    const r = moveGroup(view(), solved, "region", 200, 0);
    const b = boxes(r.positions);
    expect(b.region.x).toBeLessThan(b.vpc.x);
    expect(b.region.y).toBeLessThan(b.vpc.y);
    expect(b.region.x + b.region.w).toBeGreaterThan(b.vpc.x + b.vpc.w);
    expect(b.region.y + b.region.h).toBeGreaterThan(b.vpc.y + b.vpc.h);
  });
});
