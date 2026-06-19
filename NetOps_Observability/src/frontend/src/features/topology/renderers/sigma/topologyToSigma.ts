// Sigma adapter — maps a renderer-agnostic TopologyView into the node/edge shape
// a graphology graph (and therefore Sigma's WebGL renderer) consumes. Phase 4.
//
// Stays renderer-agnostic at the contract boundary: it reads only TopologyView
// fields and emits plain attribute bags. Visual enrichment that needs the WHOLE
// graph (degree-based sizing, FA2 positions) happens in sigmaGraph.ts; here we
// carry the per-node facts the renderer colours/clusters/labels by.

import type { TopologyView } from "../../api/topologyTypes";
import type { Health, NodeKind, EdgeStatus } from "../../api/topologyTypes";

export type SigmaNodeAttrs = {
  label: string;
  health: Health;
  kind: NodeKind;
  /** Cluster key for grouping/colour-by-site (site → group → kind fallback). */
  cluster: string;
};
export type SigmaEdgeAttrs = {
  status: EdgeStatus;
  relationship: string;
};
export type SigmaGraphData = {
  nodes: { key: string; attributes: SigmaNodeAttrs }[];
  edges: { key: string; source: string; target: string; attributes: SigmaEdgeAttrs }[];
};

export function topologyToSigma(view: TopologyView): SigmaGraphData {
  return {
    nodes: view.nodes.map((n) => ({
      key: n.id,
      attributes: {
        label: n.label,
        health: n.health,
        kind: n.kind,
        cluster: n.site ?? n.group_id ?? n.kind,
      },
    })),
    edges: view.edges.map((e) => ({
      key: e.id,
      source: e.source,
      target: e.target,
      attributes: {
        status: e.status ?? "unknown",
        relationship: e.relationship,
      },
    })),
  };
}
