// topologyToReactFlow.ts — THE adapter. Maps the renderer-agnostic TopologyView +
// a computed layout + transient UI state into @xyflow/react nodes & edges. This is
// the ONLY file that knows both the domain contract and React Flow. Sigma/deck get
// their own adapters; the domain graph never changes.
//
// Rule enforced here: an edge with no evidence is DROPPED (PDF §3 rule 6).

import type { Node, Edge } from "@xyflow/react";
import type { TopologyView, OverlayKind, TopologySelection } from "../../api/topologyTypes";
import type { LayoutResult } from "../../layout/layoutTypes";
import type { RFNodeData, RFEdgeData, NodeEmphasis, EdgeEmphasis } from "./rfTypes";
import { NODE_TYPE_FOR_KIND, EDGE_TYPE_FOR_VARIANT } from "./rfTypes";
import { edgeVariant, hasEvidence } from "../../utils/topologyHealth";

/** Transient UI state — kept SEPARATE from the domain graph (PDF §13 rerender rule). */
export type TopologyUIState = {
  selection: TopologySelection;
  /** Node ids to spotlight (selected + neighbours / path / search / unhealthy). */
  spotlight: Set<string>;
  /** Edge ids to force-strong (path edges, selected edge). */
  strongEdges: Set<string>;
  overlay: OverlayKind;
  /** Show every label (engineer/debug density) — otherwise labels are sparse. */
  showAllLabels: boolean;
  /** Node ids that matched the current search. */
  searchMatches: Set<string>;
};

const EMPTY_UI: TopologyUIState = {
  selection: {},
  spotlight: new Set(),
  strongEdges: new Set(),
  overlay: "health",
  showAllLabels: false,
  searchMatches: new Set(),
};

/** Precompute the compact metrics strip shown on a node card. */
function metricsLine(metrics: Record<string, number | string>): string | undefined {
  const order: [string, string][] = [
    ["cpu", "CPU"],
    ["mem", "MEM"],
    ["links", "Links"],
    ["alerts", "Alerts"],
  ];
  const parts: string[] = [];
  for (const [key, label] of order) {
    const v = metrics[key];
    if (v === undefined || v === null || v === "") continue;
    const pctish = key === "cpu" || key === "mem";
    parts.push(`${label} ${v}${pctish ? "%" : ""}`);
  }
  return parts.length ? parts.join(" · ") : undefined;
}

/**
 * Build React Flow nodes & edges. Emphasis encodes "calm by default": with an empty
 * spotlight everything is normal/muted; with a spotlight, in-set objects brighten and
 * the rest dim.
 */
export function topologyToReactFlow(
  view: TopologyView,
  positions: LayoutResult,
  ui: TopologyUIState = EMPTY_UI,
): { nodes: Node<RFNodeData>[]; edges: Edge<RFEdgeData>[] } {
  const spotlightActive = ui.spotlight.size > 0 || ui.searchMatches.size > 0;
  const focus = new Set<string>([...ui.spotlight, ...ui.searchMatches]);

  const nodes: Node<RFNodeData>[] = view.nodes.map((n) => {
    const inFocus = focus.has(n.id);
    let emphasis: NodeEmphasis = "normal";
    if (spotlightActive) emphasis = inFocus ? "spotlight" : "dim";

    const unhealthy = n.health === "critical" || n.health === "warning";
    const critical = n.ownership?.criticality === "critical";
    const showLabel =
      ui.showAllLabels ||
      ui.selection.nodeId === n.id ||
      inFocus ||
      unhealthy ||
      critical ||
      ui.searchMatches.has(n.id);

    return {
      id: n.id,
      type: NODE_TYPE_FOR_KIND[n.kind] ?? "deviceNode",
      position: positions[n.id] ?? { x: 0, y: 0 },
      data: { node: n, emphasis, showLabel, overlay: ui.overlay, metricsLine: metricsLine(n.metrics) },
      // selection is tracked in our own state; don't let RF fight us over it.
      selectable: true,
      draggable: true,
    };
  });

  const edges: Edge<RFEdgeData>[] = view.edges
    // hard rule: no evidence → no edge.
    .filter((e) => hasEvidence(e.evidence))
    .map((e) => {
      const variant = edgeVariant(e);
      const onPath = ui.strongEdges.has(e.id);
      const bothFocused = focus.has(e.source) && focus.has(e.target);
      let emphasis: EdgeEmphasis = "muted";
      if (onPath || ui.selection.edgeId === e.id) emphasis = "strong";
      else if (!spotlightActive) emphasis = "normal";
      else if (bothFocused) emphasis = "strong";

      const showLabel = ui.showAllLabels || emphasis === "strong" || ui.selection.edgeId === e.id;

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: EDGE_TYPE_FOR_VARIANT[variant] ?? "topologyEdge",
        data: { edge: e, emphasis, overlay: ui.overlay, showLabel },
      };
    });

  return { nodes, edges };
}
