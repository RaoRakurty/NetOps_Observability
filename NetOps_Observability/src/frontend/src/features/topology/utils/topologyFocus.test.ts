// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyFocus.test.ts — the escape hatch the >1000-node card advertises.

import { describe, it, expect } from "vitest";
import { focusView, focusSummary } from "./topologyFocus";
import type { TopologyView } from "../api/topologyTypes";

// a — b — c — d, plus an isolated e.
function view(): TopologyView {
  const node = (id: string) => ({ id, label: id }) as TopologyView["nodes"][number];
  const edge = (s: string, t: string) =>
    ({ id: `${s}-${t}`, source: s, target: t }) as TopologyView["edges"][number];
  return {
    nodes: ["a", "b", "c", "d", "e"].map(node),
    edges: [edge("a", "b"), edge("b", "c"), edge("c", "d")],
    groups: [
      { id: "g1", label: "G1", children: ["a", "b"] },
      { id: "g2", label: "G2", children: ["e"] },
    ],
  } as TopologyView;
}

describe("focusView", () => {
  it("keeps the match AND one hop of context", () => {
    // Narrowing to the literal match alone would show a single disconnected
    // dot — the neighbours are what make it a topology.
    const out = focusView(view(), new Set(["b"]));
    expect(out.nodes.map((n) => n.id).sort()).toEqual(["a", "b", "c"]);
    expect(out.edges.map((e) => e.id).sort()).toEqual(["a-b", "b-c"]);
  });

  it("drops edges whose other end was filtered out", () => {
    const out = focusView(view(), new Set(["a"]));
    // a + b kept; the b—c edge must NOT survive with a missing endpoint.
    expect(out.nodes.map((n) => n.id).sort()).toEqual(["a", "b"]);
    expect(out.edges.map((e) => e.id)).toEqual(["a-b"]);
  });

  it("prunes groups that lost every child, and trims the rest", () => {
    const out = focusView(view(), new Set(["a"]));
    expect(out.groups.map((g) => g.id)).toEqual(["g1"]); // g2 held only `e`
    expect(out.groups[0].children.sort()).toEqual(["a", "b"]);
  });

  it("returns the view UNCHANGED when nothing matched", () => {
    // A mistyped search must not blank the canvas — the operator would lose
    // their place on every keystroke.
    const v = view();
    const out = focusView(v, new Set());
    expect(out).toBe(v);
  });

  it("handles an isolated match without inventing edges", () => {
    const out = focusView(view(), new Set(["e"]));
    expect(out.nodes.map((n) => n.id)).toEqual(["e"]);
    expect(out.edges).toEqual([]);
  });

  it("reaches further with more hops", () => {
    const out = focusView(view(), new Set(["a"]), 3);
    expect(out.nodes.map((n) => n.id).sort()).toEqual(["a", "b", "c", "d"]);
  });

  it("terminates on a cycle", () => {
    const v = view();
    v.edges.push({ id: "d-a", source: "d", target: "a" } as TopologyView["edges"][number]);
    const out = focusView(v, new Set(["a"]), 10);
    expect(out.nodes.length).toBe(4); // a,b,c,d — not an infinite walk
  });
});

describe("focusSummary", () => {
  it("says it is a SUBSET, so a narrowed canvas is not mistaken for a small network", () => {
    expect(focusSummary(500, 12, 3)).toBe("12 of 500 nodes — 3 matched, 9 neighbouring");
  });

  it("omits the neighbour clause when there are none", () => {
    expect(focusSummary(500, 3, 3)).toBe("3 of 500 nodes — 3 matched");
  });
});
