// graphAlgorithms.ts — pure graph traversals over the domain TopologyView. No
// renderer, no React. These power neighbour-spotlight, path edges and blast radius.
// (PDF §13: graph algorithms live OUTSIDE React node components.)

import type { TopologyView } from "../api/topologyTypes";

type Adjacency = Map<string, Set<string>>;

function adjacency(view: TopologyView): Adjacency {
  const adj: Adjacency = new Map();
  const add = (a: string, b: string) => {
    if (!adj.has(a)) adj.set(a, new Set());
    adj.get(a)!.add(b);
  };
  for (const e of view.edges) {
    add(e.source, e.target);
    add(e.target, e.source);
  }
  return adj;
}

/** Selected node + its first-degree neighbours (acceptance #2). */
export function firstDegree(view: TopologyView, nodeId: string): Set<string> {
  const adj = adjacency(view);
  const out = new Set<string>([nodeId]);
  for (const n of adj.get(nodeId) ?? []) out.add(n);
  return out;
}

/** N-hop neighbourhood around a seed (Explore expand 1/2/3 hops). */
export function nHop(view: TopologyView, seed: string, hops: number): Set<string> {
  const adj = adjacency(view);
  const seen = new Set<string>([seed]);
  let frontier = [seed];
  for (let h = 0; h < hops; h++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const nb of adj.get(id) ?? []) {
        if (!seen.has(nb)) {
          seen.add(nb);
          next.push(nb);
        }
      }
    }
    frontier = next;
  }
  return seen;
}

/** The set of edge ids whose endpoints are consecutive on an ordered path. */
export function pathEdgeIds(view: TopologyView, path: string[]): Set<string> {
  const want = new Set<string>();
  for (let i = 0; i < path.length - 1; i++) {
    const a = path[i];
    const b = path[i + 1];
    for (const e of view.edges) {
      if ((e.source === a && e.target === b) || (e.source === b && e.target === a)) want.add(e.id);
    }
  }
  return want;
}

/** Edge ids touching any node in a set (used to keep spotlight edges strong). */
export function edgesWithin(view: TopologyView, nodes: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const e of view.edges) {
    if (nodes.has(e.source) && nodes.has(e.target)) out.add(e.id);
  }
  return out;
}
