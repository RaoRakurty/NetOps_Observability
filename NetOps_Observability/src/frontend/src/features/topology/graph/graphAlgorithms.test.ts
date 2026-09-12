// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// graphAlgorithms.test.ts — the pure traversals every canvas workflow's spotlight
// and blast-radius expansion stands on (firstDegree / nHop / pathEdgeIds /
// edgesWithin) were untested. Pins: undirected adjacency, cycle termination,
// parallel edges, and direction-independent path matching.

import { describe, it, expect } from "vitest";
import { firstDegree, nHop, pathEdgeIds, edgesWithin } from "./graphAlgorithms";
import type { TopologyView, TopologyEdge } from "../api/topologyTypes";

// Only view.edges is read by these functions; build a view from an edge list.
function viewOf(edges: Array<[string, string, string]>): TopologyView {
  return {
    edges: edges.map(([id, source, target]) => ({ id, source, target } as TopologyEdge)),
    nodes: [],
  } as unknown as TopologyView;
}

//   a — b — c
//       |  /        (b-c and c-d and b-d form a cycle; e is isolated;
//       d            a||b has a parallel edge)
const G = viewOf([
  ["e1", "a", "b"],
  ["e1b", "a", "b"], // parallel edge a–b
  ["e2", "b", "c"],
  ["e3", "b", "d"],
  ["e4", "c", "d"], // closes the b-c-d cycle
]);

describe("firstDegree", () => {
  it("returns the node plus its immediate neighbours (undirected)", () => {
    expect(firstDegree(G, "b")).toEqual(new Set(["b", "a", "c", "d"]));
    expect(firstDegree(G, "a")).toEqual(new Set(["a", "b"]));
  });
  it("an unknown or isolated node yields just itself", () => {
    expect(firstDegree(G, "zzz")).toEqual(new Set(["zzz"]));
    expect(firstDegree(viewOf([]), "x")).toEqual(new Set(["x"]));
  });
});

describe("nHop", () => {
  it("0 hops is the seed alone", () => {
    expect(nHop(G, "a", 0)).toEqual(new Set(["a"]));
  });
  it("expands ring by ring", () => {
    expect(nHop(G, "a", 1)).toEqual(new Set(["a", "b"]));
    expect(nHop(G, "a", 2)).toEqual(new Set(["a", "b", "c", "d"]));
  });
  it("terminates on cycles and saturates (no infinite loop, no growth past coverage)", () => {
    const full = new Set(["a", "b", "c", "d"]);
    expect(nHop(G, "a", 3)).toEqual(full);
    expect(nHop(G, "a", 99)).toEqual(full);
  });
});

describe("pathEdgeIds", () => {
  it("collects edges between consecutive hops, including parallels", () => {
    // a→b has two parallel edges; both belong to the path segment.
    expect(pathEdgeIds(G, ["a", "b", "c"])).toEqual(new Set(["e1", "e1b", "e2"]));
  });
  it("is direction-independent", () => {
    expect(pathEdgeIds(G, ["c", "b"])).toEqual(new Set(["e2"]));
    expect(pathEdgeIds(G, ["b", "c"])).toEqual(new Set(["e2"]));
  });
  it("non-adjacent hops or a single-node path contribute no edges", () => {
    expect(pathEdgeIds(G, ["a", "c"])).toEqual(new Set()); // no direct a–c edge
    expect(pathEdgeIds(G, ["a"])).toEqual(new Set());
    expect(pathEdgeIds(G, [])).toEqual(new Set());
  });
});

describe("edgesWithin", () => {
  it("keeps only edges with BOTH endpoints inside the set", () => {
    expect(edgesWithin(G, new Set(["a", "b"]))).toEqual(new Set(["e1", "e1b"]));
    expect(edgesWithin(G, new Set(["b", "c", "d"]))).toEqual(new Set(["e2", "e3", "e4"]));
  });
  it("a single node (only one endpoint) keeps no edges", () => {
    expect(edgesWithin(G, new Set(["a"]))).toEqual(new Set());
  });
});
