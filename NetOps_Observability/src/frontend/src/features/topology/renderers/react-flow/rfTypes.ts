// rfTypes.ts — the contract BETWEEN the React Flow adapter and the custom
// node/edge components. This is the only place renderer-specific `data` shapes
// live. Domain types (TopologyNode/Edge) flow IN; @xyflow/react flows OUT.
//
// Emphasis is the heart of the "calm by default" rule (PDF §11): almost everything
// is `normal`/`muted`; only selected, neighbour, path, unhealthy, changed or
// searched objects become `spotlight`/`strong`, and unrelated objects `dim`.

import type { TopologyNode, TopologyEdge, TopologyGroup, OverlayKind, Health } from "../../api/topologyTypes";

export type NodeEmphasis = "normal" | "spotlight" | "dim";
export type EdgeEmphasis = "muted" | "normal" | "strong";

/** Aggregate stats shown on a group container/collapsed node. */
export type GroupCounts = { total: number; critical: number; warning: number; links: number };

/** `data` payload on a group React Flow node (container when expanded, aggregate
 *  when collapsed). Groups are TopologyGroups — distinct from device nodes. */
export type RFGroupData = {
  group: TopologyGroup;
  collapsed: boolean;
  emphasis: NodeEmphasis;
  counts: GroupCounts;
  health: Health;
  /** Toggle collapse/expand — injected by the canvas (stable ref). */
  onToggle?: (groupId: string) => void;
};

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
  // `site` is a plain NODE kind (ProjectGeo emits it with RFNodeData) — routing
  // it to groupNode crashed the canvas: GroupNode dereferences RFGroupData
  // fields the adapter never builds for it (audit S7). Sites render as cards;
  // real containers arrive only as `group` with proper group data.
  site: "deviceNode",
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
  rca: "rcaEdge",
};
