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
