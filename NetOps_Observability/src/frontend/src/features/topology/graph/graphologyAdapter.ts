// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// graphologyAdapter.ts — bridge the domain TopologyView into a graphology Graph for
// graph-theoretic analysis (centrality, clustering, community detection). This is
// deliberately INDEPENDENT of React Flow: graphology is an analysis substrate, not a
// renderer. Node/edge attributes carry health + confidence so analyses can weight by
// trust.

import Graph from "graphology";
import type { TopologyView } from "../api/topologyTypes";

/**
 * Build an UNDIRECTED graphology Graph from a view. Node attributes: label, kind,
 * health, confidence. Edge attributes: relationship, status, confidence. Parallel
 * domain links between the same pair are merged (mergeUndirectedEdge) — analyses
 * care about adjacency, not multiplicity.
 */
export function toGraphology(view: TopologyView): Graph {
  const g = new Graph({ type: "undirected", multi: false, allowSelfLoops: false });

  for (const n of view.nodes ?? []) {
    g.mergeNode(n.id, {
      label: n.label,
      kind: n.kind,
      health: n.health,
      confidence: n.confidence,
    });
  }

  for (const e of view.edges ?? []) {
    // Skip edges whose endpoints aren't in the graph (defensive).
    if (!g.hasNode(e.source) || !g.hasNode(e.target)) continue;
    if (e.source === e.target) continue;
    g.mergeUndirectedEdge(e.source, e.target, {
      relationship: e.relationship,
      status: e.status,
      confidence: e.confidence,
    });
  }

  return g;
}

/**
 * Degree centrality per node, normalized to [0, 1] (degree / (N-1)). A cheap
 * structural-importance signal: high-degree nodes are aggregation points whose
 * failure has wide blast radius. Returns {} for graphs of <2 nodes.
 */
export function degreeCentrality(view: TopologyView): Record<string, number> {
  const g = toGraphology(view);
  const n = g.order;
  const out: Record<string, number> = {};
  if (n < 2) {
    g.forEachNode((id) => {
      out[id] = 0;
    });
    return out;
  }
  const denom = n - 1;
  g.forEachNode((id) => {
    out[id] = g.degree(id) / denom;
  });
  return out;
}
