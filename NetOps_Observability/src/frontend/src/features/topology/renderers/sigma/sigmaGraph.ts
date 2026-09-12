// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// sigmaGraph.ts — build a laid-out graphology Graph from a TopologyView, ready
// for Sigma's WebGL renderer. Phase 4.
//
// Layout is DETERMINISTIC: nodes are seeded on a circle (graphology-layout
// `circular`, no RNG) and then relaxed with a FIXED number of ForceAtlas2
// iterations. FA2 has no randomness of its own, so the same view always yields
// the same picture — honouring "no random force" (PDF §19) even though we use a
// force layout for the exploration renderer (where the guide explicitly allows
// it, unlike the deterministic physical/routed canvas).
//
// This file imports graphology but NOT sigma — so it runs headless (jsdom) and
// is unit-tested. The React renderer (SigmaTopologyView) owns the WebGL canvas.

import Graph from "graphology";
import { circular } from "graphology-layout";
import forceAtlas2 from "graphology-layout-forceatlas2";
import type { TopologyView, Health } from "../../api/topologyTypes";
import { HEALTH_COLOR } from "../../utils/topologyHealth";
import { topologyToSigma } from "./topologyToSigma";

export const SIGMA_FA2_ITERATIONS = 150;
const DIM_EDGE = "#cbd5e1";

/** Degree → node radius (px). Bigger hubs read first; clamped so it never blobs. */
export function nodeSize(degree: number): number {
  return 3 + Math.min(11, Math.sqrt(degree) * 2.1);
}

/**
 * Build a fully-laid-out, attributed graphology Graph. Skips duplicate nodes and
 * parallel/self edges (the overview collapses them — detail lives in the canvas).
 */
export function buildSigmaGraph(view: TopologyView): Graph {
  const data = topologyToSigma(view);
  const g = new Graph({ multi: false, type: "undirected" });

  // degree first (drives sizing) — count only edges whose endpoints both exist.
  const present = new Set(data.nodes.map((n) => n.key));
  const degree = new Map<string, number>();
  for (const e of data.edges) {
    if (!present.has(e.source) || !present.has(e.target) || e.source === e.target) continue;
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }

  for (const n of data.nodes) {
    if (g.hasNode(n.key)) continue;
    const health = n.attributes.health as Health;
    g.addNode(n.key, {
      label: n.attributes.label,
      health,
      kind: n.attributes.kind,
      cluster: n.attributes.cluster,
      color: HEALTH_COLOR[health] ?? HEALTH_COLOR.unknown,
      size: nodeSize(degree.get(n.key) ?? 0),
      x: 0,
      y: 0,
    });
  }

  for (const e of data.edges) {
    if (!g.hasNode(e.source) || !g.hasNode(e.target)) continue;
    if (e.source === e.target || g.hasEdge(e.source, e.target)) continue;
    g.addEdgeWithKey(e.key, e.source, e.target, { color: DIM_EDGE, size: 0.6 });
  }

  // Deterministic seed → deterministic relaxation.
  circular.assign(g, { scale: 100 });
  if (g.order > 0) {
    const settings = forceAtlas2.inferSettings(g);
    forceAtlas2.assign(g, { iterations: SIGMA_FA2_ITERATIONS, settings });
  }
  return g;
}
