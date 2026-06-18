// rfTypes.ts — the contract BETWEEN the React Flow adapter and the custom
// node/edge components. This is the only place renderer-specific `data` shapes
// live. Domain types (TopologyNode/Edge) flow IN; @xyflow/react flows OUT.
//
// Emphasis is the heart of the "calm by default" rule (PDF §11): almost everything
// is `normal`/`muted`; only selected, neighbour, path, unhealthy, changed or
// searched objects become `spotlight`/`strong`, and unrelated objects `dim`.

import type { TopologyNode, TopologyEdge, OverlayKind } from "../../api/topologyTypes";

export type NodeEmphasis = "normal" | "spotlight" | "dim";
export type EdgeEmphasis = "muted" | "normal" | "strong";

/** `data` payload on every React Flow node. */
export type RFNodeData = {
  node: TopologyNode;
  emphasis: NodeEmphasis;
  /** Label visibility is computed centrally (selected/searched/unhealthy/path/critical). */
  showLabel: boolean;
  /** Active overlay — node renders the matching badge/ring treatment. */
  overlay: OverlayKind;
  /** Precomputed metrics strip, e.g. "CPU 42% · MEM 68% · Links 12 · Alerts 2". */
  metricsLine?: string;
};

/** `data` payload on every React Flow edge. */
export type RFEdgeData = {
  edge: TopologyEdge;
  emphasis: EdgeEmphasis;
  overlay: OverlayKind;
  showLabel: boolean;
};

/** Maps a domain NodeKind to the registered React Flow node `type` key. */
export const NODE_TYPE_FOR_KIND: Record<string, string> = {
  switch: "switchNode",
  router: "routerNode",
  firewall: "firewallNode",
  load_balancer: "deviceNode",
  server: "deviceNode",
  cloud: "cloudNode",
  wan: "cloudNode",
  site: "groupNode",
  group: "groupNode",
  unresolved: "unresolvedNode",
};

/** Maps a domain EdgeVariant to the registered React Flow edge `type` key. */
export const EDGE_TYPE_FOR_VARIANT: Record<string, string> = {
  topology: "topologyEdge",
  path: "pathHighlightEdge",
  inferred: "inferredEdge",
  degraded: "degradedEdge",
  bundled: "bundledEdge",
};
