// topologyToReactFlow.ts — THE adapter. Maps the renderer-agnostic TopologyView +
// a computed layout + transient UI state into @xyflow/react nodes & edges. This is
// the ONLY file that knows both the domain contract and React Flow. Sigma/deck get
// their own adapters; the domain graph never changes.
//
// Rules enforced here: an edge with no evidence is DROPPED; groups render as
// background containers (expanded) or aggregate nodes (collapsed); a collapsed
// group hides its children and reroutes their edges to the group (anti-hairball).

import type { Node, Edge } from "@xyflow/react";
import type { TopologyView, OverlayKind, TopologySelection, Health } from "../../api/topologyTypes";
import type { LayoutResult } from "../../layout/layoutTypes";
import { NODE_SIZE } from "../../layout/layoutTypes";
import type { RFNodeData, RFEdgeData, RFGroupData, NodeEmphasis, EdgeEmphasis } from "./rfTypes";
import { NODE_TYPE_FOR_KIND, EDGE_TYPE_FOR_VARIANT } from "./rfTypes";
import { edgeVariant, hasEvidence, rollupHealth } from "../../utils/topologyHealth";

/** Transient UI state — kept SEPARATE from the domain graph (rerender rule). */
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
  /** Group ids currently collapsed (children hidden, edges rerouted to the group). */
  collapsedGroups: Set<string>;
  /** Collapse/expand toggle, injected onto group node data (stable ref). */
  onToggleGroup?: (groupId: string) => void;
};

const EMPTY_UI: TopologyUIState = {
  selection: {},
  spotlight: new Set(),
  strongEdges: new Set(),
  overlay: "health",
  showAllLabels: false,
  searchMatches: new Set(),
  collapsedGroups: new Set(),
};

/** Precompute the compact metrics strip shown on a node card. Skill metric keys. */
function metricsLine(metrics: Record<string, number | string> | undefined): string | undefined {
  if (!metrics) return undefined;
  const order: [string, string, boolean][] = [
    ["cpu_pct", "CPU", true],
    ["mem_pct", "MEM", true],
    ["link_count", "Links", false],
    ["alert_count", "Alerts", false],
  ];
  const parts: string[] = [];
  for (const [key, label, pctish] of order) {
    const v = metrics[key];
    if (v === undefined || v === null || v === "") continue;
    parts.push(`${label} ${v}${pctish ? "%" : ""}`);
  }
  return parts.length ? parts.join(" · ") : undefined;
}

type BBox = { minX: number; minY: number; maxX: number; maxY: number; w: number; h: number; cx: number; cy: number };
function bboxOf(ids: string[], positions: LayoutResult): BBox | null {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  let any = false;
  for (const id of ids) {
    const p = positions[id];
    if (!p) continue;
    any = true;
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + NODE_SIZE.width);
    maxY = Math.max(maxY, p.y + NODE_SIZE.height);
  }
  if (!any) return null;
  return { minX, minY, maxX, maxY, w: maxX - minX, h: maxY - minY, cx: (minX + maxX) / 2, cy: (minY + maxY) / 2 };
}

/**
 * Build React Flow nodes & edges. Emphasis encodes "calm by default": with an empty
 * spotlight everything is normal/muted; with a spotlight, in-set objects brighten and
 * the rest dim. Groups are emitted first so they render behind device cards.
 */
export function topologyToReactFlow(
  view: TopologyView,
  positions: LayoutResult,
  ui: TopologyUIState = EMPTY_UI,
): { nodes: Node<RFNodeData | RFGroupData>[]; edges: Edge<RFEdgeData>[] } {
  const collapsed = ui.collapsedGroups ?? new Set<string>();
  const spotlightActive = ui.spotlight.size > 0 || ui.searchMatches.size > 0;
  const focus = new Set<string>([...ui.spotlight, ...ui.searchMatches]);

  // node → group membership, and helpers for collapse hiding / edge rerouting.
  const nodeGroup = new Map<string, string>();
  for (const g of view.groups) for (const c of g.children) nodeGroup.set(c, g.id);
  const isHidden = (nodeId: string) => {
    const g = nodeGroup.get(nodeId);
    return !!(g && collapsed.has(g));
  };
  const resolveEndpoint = (nodeId: string) => {
    const g = nodeGroup.get(nodeId);
    return g && collapsed.has(g) ? g : nodeId;
  };

  // ── group nodes (container when expanded, aggregate card when collapsed) ──────
  const groupNodes: Node<RFGroupData>[] = [];
  for (const g of view.groups) {
    const memberNodes = g.children.map((id) => view.nodes.find((n) => n.id === id)).filter(Boolean) as typeof view.nodes;
    const bbox = bboxOf(g.children, positions);
    if (memberNodes.length === 0 || !bbox) continue;

    const critical = memberNodes.filter((n) => n.health === "critical").length;
    const warning = memberNodes.filter((n) => n.health === "warning").length;
    const links = view.edges.filter((e) => g.children.includes(e.source) || g.children.includes(e.target)).length;
    const worst: Health = rollupHealth(memberNodes);
    const counts = { total: memberNodes.length, critical, warning, links };
    const isCollapsed = collapsed.has(g.id);
    const emphasis: NodeEmphasis = ui.selection.groupId === g.id ? "spotlight" : "normal";

    if (isCollapsed) {
      groupNodes.push({
        id: g.id,
        type: "groupNode",
        position: { x: bbox.cx - 104, y: bbox.cy - 44 },
        data: { group: g, collapsed: true, emphasis, counts, health: worst, onToggle: ui.onToggleGroup },
        zIndex: 2,
        selectable: true,
        draggable: true,
      });
    } else {
      const pad = 28;
      const top = 16; // room for the label chip above the children
      groupNodes.push({
        id: g.id,
        type: "groupNode",
        position: { x: bbox.minX - pad, y: bbox.minY - pad - top },
        data: { group: g, collapsed: false, emphasis, counts, health: worst, onToggle: ui.onToggleGroup },
        style: { width: bbox.w + pad * 2, height: bbox.h + pad * 2 + top },
        zIndex: 0,
        selectable: true,
        draggable: false,
      });
    }
  }

  // ── device nodes (hide those inside a collapsed group) ───────────────────────
  const deviceNodes: Node<RFNodeData>[] = view.nodes
    .filter((n) => !isHidden(n.id))
    .map((n) => {
      const inFocus = focus.has(n.id);
      let emphasis: NodeEmphasis = "normal";
      if (spotlightActive) emphasis = inFocus ? "spotlight" : "dim";

      const unhealthy = n.health === "critical" || n.health === "warning";
      const critical = n.criticality === "critical";
      const showLabel =
        ui.showAllLabels || ui.selection.nodeId === n.id || inFocus || unhealthy || critical || ui.searchMatches.has(n.id);

      return {
        id: n.id,
        type: NODE_TYPE_FOR_KIND[n.kind] ?? "deviceNode",
        position: positions[n.id] ?? { x: 0, y: 0 },
        data: { node: n, emphasis, showLabel, overlay: ui.overlay, metricsLine: metricsLine(n.metrics) },
        zIndex: 1,
        selectable: true,
        draggable: true,
      };
    });

  // ── edges: drop no-evidence; reroute collapsed endpoints to the group; drop
  //    intra-collapsed-group edges; dedupe the rerouted parallels. ──────────────
  const seen = new Set<string>();
  const edges: Edge<RFEdgeData>[] = [];
  for (const e of view.edges) {
    if (!hasEvidence(e.evidence)) continue;
    const s = resolveEndpoint(e.source);
    const t = resolveEndpoint(e.target);
    if (s === t) continue; // collapsed inside a single group → hidden

    const rerouted = s !== e.source || t !== e.target;
    const variant = edgeVariant(e);
    // when rerouted to a group, collapse parallels to one edge per (s,t,variant)
    if (rerouted) {
      const key = `${s}|${t}|${variant}`;
      if (seen.has(key)) continue;
      seen.add(key);
    }

    const onPath = ui.strongEdges.has(e.id);
    const bothFocused = focus.has(e.source) && focus.has(e.target);
    let emphasis: EdgeEmphasis = "muted";
    if (onPath || ui.selection.edgeId === e.id) emphasis = "strong";
    else if (!spotlightActive) emphasis = "normal";
    else if (bothFocused) emphasis = "strong";

    const showLabel = ui.showAllLabels || emphasis === "strong" || ui.selection.edgeId === e.id;

    edges.push({
      id: e.id,
      source: s,
      target: t,
      type: EDGE_TYPE_FOR_VARIANT[variant] ?? "topologyEdge",
      data: { edge: e, emphasis, overlay: ui.overlay, showLabel },
    });
  }

  // groups first → they render behind the device cards.
  return { nodes: [...groupNodes, ...deviceNodes], edges };
}
