// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Pins the "hover shake" fix: a passing hover (SOFT spotlight) must lift only the
// focus set and leave every other card at its NORMAL weight — never dim the whole
// canvas. A deliberate click (HARD spotlight) still dims the out-of-focus cards.
// Regression guard: if a refactor re-couples hover to the heavy dim, these fail.

import { describe, it, expect } from "vitest";
import type { Node } from "@xyflow/react";
import { topologyToReactFlow, type TopologyUIState } from "./topologyToReactFlow";
import { physicalTopology } from "../../mock/physicalTopology";
import type { RFNodeData, RFGroupData } from "./rfTypes";
import type { TopologyView } from "../../api/topologyTypes";

// spine1 is the focus; leaf1 is connected but intentionally left OUT of the focus
// set so we can assert how out-of-focus cards are treated under each mode.
const baseUI: TopologyUIState = {
  selection: {},
  spotlight: new Set<string>(["spine1"]),
  strongEdges: new Set<string>(),
  overlay: "health",
  showAllLabels: false,
  searchMatches: new Set<string>(),
  collapsedGroups: new Set<string>(),
};

function emphasisOf(nodes: Node<RFNodeData | RFGroupData>[], id: string): string | undefined {
  const n = nodes.find((x) => x.id === id);
  return n?.data?.emphasis;
}

describe("topologyToReactFlow — spotlight emphasis", () => {
  it("hard focus (click) dims out-of-focus cards", () => {
    const { nodes } = topologyToReactFlow(physicalTopology, {}, { ...baseUI, spotlightSoft: false });
    expect(emphasisOf(nodes, "spine1")).toBe("spotlight");
    expect(emphasisOf(nodes, "leaf1")).toBe("dim");
  });

  it("soft focus (hover) lifts the focus set but never dims the rest — no canvas shake", () => {
    const { nodes } = topologyToReactFlow(physicalTopology, {}, { ...baseUI, spotlightSoft: true });
    expect(emphasisOf(nodes, "spine1")).toBe("spotlight");
    // The whole-canvas dim/undim on each hover graze is the "shake". Out-of-focus
    // cards must stay NORMAL on a soft hover.
    expect(emphasisOf(nodes, "leaf1")).toBe("normal");
  });

  it("no spotlight at all leaves every card normal", () => {
    const { nodes } = topologyToReactFlow(physicalTopology, {}, { ...baseUI, spotlight: new Set() });
    expect(emphasisOf(nodes, "spine1")).toBe("normal");
    expect(emphasisOf(nodes, "leaf1")).toBe("normal");
  });
});

describe("topologyToReactFlow — RCA overlay edges", () => {
  // An edge carrying an rca_status must route to the dedicated rcaEdge renderer so
  // suspected/confirmed/insufficient get their distinct treatment (not the generic
  // degraded/topology edge).
  const rcaView: TopologyView = {
    view_id: "rca-test",
    mode: "investigate",
    layout_type: "path_first",
    generated_at: "2026-06-21T00:00:00Z",
    nodes: [
      { id: "a", label: "A", kind: "router", health: "warning", confidence: 1, evidence: [{ source: "trace", confidence: 1 }], rca_status: "suspected_down" },
      { id: "b", label: "B", kind: "cloud", health: "ok", confidence: 1, evidence: [{ source: "trace", confidence: 1 }], rca_status: "observed" },
    ],
    edges: [
      { id: "e-sus", source: "a", target: "b", relationship: "path_hop", confidence: 1, evidence: [{ source: "trace", confidence: 1 }], rca_status: "suspected_down" },
    ],
    groups: [],
    overlays: ["health"],
  };

  it("routes an rca_status edge to the rcaEdge type", () => {
    const { edges } = topologyToReactFlow(rcaView, { a: { x: 0, y: 0 }, b: { x: 200, y: 0 } });
    expect(edges.find((e) => e.id === "e-sus")!.type).toBe("rcaEdge");
  });
});

// ── #134: nested containers (region → VPC) ────────────────────────────────────
//
// A group's box used to be derived from its DIRECT node children, and a group
// with none was skipped outright. A REGION declares no node children — its
// members are VPC groups, which nest via `parent_id` — so every region box was
// discarded: the deployed cloud view declares 2 regions and the canvas drew 0.
// ELK already lays the nesting out correctly (containers inside containers);
// only this rendering half was flat. Structural assertions, no snapshot.
describe("topologyToReactFlow — nested groups (region → VPC)", () => {
  const cloudNode = (id: string): TopologyView["nodes"][number] => ({
    id,
    label: id,
    kind: "cloud",
    health: "unknown",
    confidence: 0.9,
    evidence: [{ source: "cloud_api", confidence: 0.9 }],
  });

  // region:aws:us-west-2 ─┬─ vpc-a ── subnet-a1, subnet-a2
  //                       └─ vpc-b ── subnet-b1
  const nestedView: TopologyView = {
    view_id: "nested-groups",
    mode: "explore",
    layout_type: "cloud_grouped",
    generated_at: "2026-08-02T00:00:00Z",
    nodes: [cloudNode("subnet-a1"), cloudNode("subnet-a2"), cloudNode("subnet-b1")],
    edges: [],
    groups: [
      { id: "region:aws:us-west-2", label: "aws · us-west-2", group_type: "region", children: [], health: "unknown", collapsed: false },
      { id: "vpc-a", label: "VPC · a", group_type: "vpc", parent_id: "region:aws:us-west-2", children: ["subnet-a1", "subnet-a2"], health: "unknown", collapsed: false },
      { id: "vpc-b", label: "VPC · b", group_type: "vpc", parent_id: "region:aws:us-west-2", children: ["subnet-b1"], health: "unknown", collapsed: false },
    ],
    overlays: ["health"],
  };

  // What ELK returns: containers carry a solved rect, leaves only a position.
  const positions = {
    "region:aws:us-west-2": { x: 0, y: 0, w: 900, h: 400 },
    "vpc-a": { x: 24, y: 60, w: 400, h: 300 },
    "vpc-b": { x: 470, y: 60, w: 380, h: 300 },
    "subnet-a1": { x: 48, y: 120 },
    "subnet-a2": { x: 220, y: 120 },
    "subnet-b1": { x: 500, y: 120 },
  };

  const groupsOf = (nodes: Node<RFNodeData | RFGroupData>[]) =>
    nodes.filter((n) => n.type === "groupNode");

  it("renders the region container whose only members are other GROUPS", () => {
    const { nodes } = topologyToReactFlow(nestedView, positions);
    const ids = groupsOf(nodes).map((n) => n.id);
    expect(ids).toContain("region:aws:us-west-2");
    expect(ids).toContain("vpc-a");
    expect(ids).toContain("vpc-b");
  });

  it("the region's box ENCLOSES every descendant group box and device card", () => {
    const { nodes } = topologyToReactFlow(nestedView, positions);
    const region = groupsOf(nodes).find((n) => n.id === "region:aws:us-west-2")!;
    const rx = region.position.x;
    const ry = region.position.y;
    const rw = Number(region.style?.width);
    const rh = Number(region.style?.height);
    expect(rw).toBeGreaterThan(0);
    expect(rh).toBeGreaterThan(0);
    for (const child of ["vpc-a", "vpc-b"]) {
      const box = groupsOf(nodes).find((n) => n.id === child)!;
      expect(box.position.x).toBeGreaterThanOrEqual(rx);
      expect(box.position.y).toBeGreaterThanOrEqual(ry);
      expect(box.position.x + Number(box.style?.width)).toBeLessThanOrEqual(rx + rw);
      expect(box.position.y + Number(box.style?.height)).toBeLessThanOrEqual(ry + rh);
    }
  });

  it("falls back to the DESCENDANT bounding box when ELK solved no rect for the region", () => {
    // Same view, but the layout predates container geometry (no w/h anywhere) —
    // the region must still be drawn, around everything below it.
    const flat = {
      "subnet-a1": { x: 48, y: 120 },
      "subnet-a2": { x: 220, y: 120 },
      "subnet-b1": { x: 500, y: 120 },
    };
    const { nodes } = topologyToReactFlow(nestedView, flat);
    const region = groupsOf(nodes).find((n) => n.id === "region:aws:us-west-2")!;
    expect(region).toBeTruthy();
    const rx = region.position.x;
    const rw = Number(region.style?.width);
    // Encloses the leftmost and rightmost descendant cards.
    expect(rx).toBeLessThan(48);
    expect(rx + rw).toBeGreaterThan(500 + 120);
  });

  it("counts the region's DESCENDANT devices, not its (empty) direct children", () => {
    const { nodes } = topologyToReactFlow(nestedView, positions);
    const region = groupsOf(nodes).find((n) => n.id === "region:aws:us-west-2")!;
    expect((region.data as RFGroupData).counts.total).toBe(3);
    expect((region.data as RFGroupData).depth).toBe(0);
    const vpcA = groupsOf(nodes).find((n) => n.id === "vpc-a")!;
    expect((vpcA.data as RFGroupData).counts.total).toBe(2);
    expect((vpcA.data as RFGroupData).depth).toBe(1);
  });

  it("outer containers are emitted BEFORE the containers nested in them", () => {
    const { nodes } = topologyToReactFlow(nestedView, positions);
    const order = groupsOf(nodes).map((n) => n.id);
    expect(order.indexOf("region:aws:us-west-2")).toBeLessThan(order.indexOf("vpc-a"));
    expect(order.indexOf("region:aws:us-west-2")).toBeLessThan(order.indexOf("vpc-b"));
  });

  it("collapsing the REGION hides the nested VPC boxes and every device under them", () => {
    const { nodes } = topologyToReactFlow(nestedView, positions, {
      ...baseUI,
      spotlight: new Set<string>(),
      collapsedGroups: new Set<string>(["region:aws:us-west-2"]),
    });
    const ids = nodes.map((n) => n.id);
    expect(ids).toContain("region:aws:us-west-2");
    expect(ids).not.toContain("vpc-a");
    expect(ids).not.toContain("vpc-b");
    expect(ids).not.toContain("subnet-a1");
    expect(ids).not.toContain("subnet-b1");
  });
});
