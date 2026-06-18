// Placeholder adapter. The Sigma.js/cosmos.gl WebGL overview renderer (1,000+
// nodes) is Phase 4; this proves the adapter boundary exists and the domain
// graph stays renderer-agnostic.
//
// Nothing here imports sigma/graphology/cosmos — when Phase 4 lands, only this
// file changes; the domain TopologyView contract does not.

import type { TopologyView } from "../../api/topologyTypes";

export type SigmaGraphData = {
  nodes: { key: string; attributes: Record<string, unknown> }[];
  edges: { key: string; source: string; target: string; attributes: Record<string, unknown> }[];
};

/**
 * Map a renderer-agnostic TopologyView into the minimal node/edge shape a
 * Sigma/graphology graph consumes. Real-shaped but intentionally minimal: the
 * Phase-4 renderer will enrich attributes (size, color ramps, LOD) here.
 */
export function topologyToSigma(view: TopologyView): SigmaGraphData {
  return {
    nodes: view.nodes.map((n) => ({
      key: n.id,
      attributes: {
        label: n.label,
        health: n.health,
      },
    })),
    edges: view.edges.map((e) => ({
      key: e.id,
      source: e.source,
      target: e.target,
      attributes: {
        relationship: e.relationship,
        status: e.status,
      },
    })),
  };
}
