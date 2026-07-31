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
import { labelDensityForZoom } from "../../utils/semanticZoom";
import { CARD_W, CARD_H } from "./nodes/DeviceNode";

/** Invisible hover/click band around each edge (React Flow default is 20px). */
const EDGE_INTERACTION_WIDTH = 12;

/** Transient UI state — kept SEPARATE from the domain graph (rerender rule). */
export type TopologyUIState = {
  selection: TopologySelection;
  /** Node ids to spotlight (selected + neighbours / path / search / unhealthy). */
  spotlight: Set<string>;
  /**
   * SOFT spotlight (a transient hover): brighten the in-focus set but leave every
   * other node/edge at its normal weight — never dim the rest. Dimming the whole
   * canvas on each hover graze is what reads as a "shake". A deliberate
   * click-selection leaves this false, so it still dims for real focus.
   */
  spotlightSoft?: boolean;
  /** Edge ids to force-strong (path edges, selected edge). */
  strongEdges: Set<string>;
  overlay: OverlayKind;
  /** Show every label (engineer/debug density) — otherwise labels are sparse. */
  showAllLabels: boolean;
  /**
   * Current canvas zoom (bucketed by the caller). Drives semantic-zoom label
   * density (skill §10 / audit: "do not show all labels at once"): the operator
   * density names every node only from "fabric" detail (zoom ≥ 0.8) inward —
   * zoomed out, only trouble + selection carry names. Undefined = zoomed-in
   * behaviour (tests, static renders).
   */
  zoom?: number;
  /** Node ids that matched the current search. */
  searchMatches: Set<string>;
  /** Group ids currently collapsed (children hidden, edges rerouted to the group). */
  collapsedGroups: Set<string>;
  /** Collapse/expand toggle, injected onto group node data (stable ref). */
  onToggleGroup?: (groupId: string) => void;
  /**
   * Operator DETAIL LEVEL (the toolbar Exec/Operator/Engineer/Incident control).
   * Drives label + metric density and incident emphasis so the four levels are
   * visibly distinct — executive = sparsest wallboard, engineer = every label/port,
   * incident = dim the calm fabric and spotlight trouble. Defaults to operator.
   */
  density?: "executive" | "operator" | "engineer" | "incident";
};

const EMPTY_UI: TopologyUIState = {
  selection: {},
  spotlight: new Set(),
  strongEdges: new Set(),
  overlay: "health",
  showAllLabels: false,
  searchMatches: new Set(),
  collapsedGroups: new Set(),
  density: "operator",
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
    // Never render a fake reading: a non-finite number (NaN/Inf from a missing VM
    // series) or the literal "NaN" is "no data", not a value the operator can use.
    if (typeof v === "number" && !isFinite(v)) continue;
    if (typeof v === "string" && (v === "NaN" || !v.trim())) continue;
    const shown = pctish && typeof v === "number" ? Math.round(v) : v;
    parts.push(`${label} ${shown}${pctish ? "%" : ""}`);
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
  const density = ui.density ?? "operator";

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
        // A group's position is always re-derived from its children's bbox, so a
        // drag was a no-op that snapped back — while still writing a junk pin
        // into the saved layout (audit S8). Groups are not draggable.
        draggable: false,
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
      const unhealthy = n.health === "critical" || n.health === "warning";
      const critical = n.criticality === "critical";
      // RCA-flagged = a node the engine marked as trouble (anything but a clean
      // "observed"/internal hop); used by Incident detail to spotlight the fault.
      const rcaFlag = !!n.rca_status && n.rca_status !== "observed" && n.rca_status !== "internal_only";
      const selected = ui.selection.nodeId === n.id;

      // Incident detail dims the calm fabric and lifts trouble even with NO selection
      // — "calm except trouble" by default. A real click/search spotlight still wins.
      const incidentDim = density === "incident" && !spotlightActive;
      // Historical-diff overlay: spotlight what CHANGED in the window, dim the rest —
      // the tractable "what changed" slice of topology time-travel.
      const changed = !!n.change_state && n.change_state !== "unchanged" && n.change_state !== "unknown";
      const diffMode = ui.overlay === "historical_diff" && !spotlightActive;
      let emphasis: NodeEmphasis = "normal";
      // A soft (hover) spotlight lifts the focus set but keeps everyone else normal;
      // only a hard focus (click / search) dims the out-of-focus cards.
      if (spotlightActive) emphasis = inFocus ? "spotlight" : ui.spotlightSoft ? "normal" : "dim";
      else if (diffMode) emphasis = changed ? "spotlight" : "dim";
      else if (incidentDim) emphasis = unhealthy || critical || rcaFlag ? "spotlight" : "dim";

      // Label density is a MONOTONIC ramp so every level is visibly distinct
      // regardless of data state (the manual Labels toggle forces all on):
      //   executive → only trouble + selection (wallboard, fewest marks)
      //   operator  → EVERY node named (the working map) — always more than executive
      //   engineer  → every node named (+ the metric strip below)
      //   incident  → calm dimmed, trouble + RCA + selection lifted (re-focused view)
      // This guarantees executive≠operator≠engineer on a calm graph too — the prior
      // logic tied the difference to trouble/metrics that may all be absent, so the
      // levels collapsed to look identical (the "Exec vs Operator shows the same" bug).
      const labelByDensity =
        density === "engineer"
          ? true
          : density === "operator"
            // Semantic zoom (skill §10): the working map names EVERYTHING at
            // fabric detail and closer, but zoomed out to the global/site level
            // only trouble + selection carry names — 100+ hostnames at once is
            // the clutter that kills big canvases. The ramp stays monotonic:
            // executive never names calm nodes at any zoom; engineer always does.
            ? ui.zoom === undefined || labelDensityForZoom(ui.zoom) || unhealthy || critical || selected
            : density === "incident"
              ? unhealthy || critical || rcaFlag || selected
              : /* executive */ unhealthy || critical || selected;
      const showLabel = ui.showAllLabels || labelByDensity;
      // The per-node metric strip is the engineer/incident detail tier — names alone
      // at operator, names + telemetry at engineer, so operator≠engineer is visible
      // too; wallboard clutter is kept off the executive view.
      const showMetrics = density === "engineer" || density === "incident";

      return {
        id: n.id,
        type: NODE_TYPE_FOR_KIND[n.kind] ?? "deviceNode",
        position: positions[n.id] ?? { x: 0, y: 0 },
        // Declared dimensions = the card's FIXED size, so React Flow never
        // re-measures the node when the array is rebuilt on hover (the device
        // card renders at exactly CARD_W × CARD_H). This is what keeps a hovered
        // node from shaking as spotlight recomputes.
        width: CARD_W,
        height: CARD_H,
        data: { node: n, emphasis, showLabel, overlay: ui.overlay, metricsLine: showMetrics ? metricsLine(n.metrics) : undefined },
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
    // soft hover: leave the rest of the links at full weight (don't mute the graph).
    else if (ui.spotlightSoft) emphasis = "normal";

    const showLabel = ui.showAllLabels || emphasis === "strong" || ui.selection.edgeId === e.id;

    edges.push({
      id: e.id,
      source: s,
      target: t,
      type: EDGE_TYPE_FOR_VARIANT[variant] ?? "topologyEdge",
      // Tighten React Flow's invisible hover/click band (default 20px). A topology
      // criss-crosses the gaps between devices with edges, so a wide band makes
      // "empty" space hover-reactive; 12px keeps the line easy to hit without the
      // cursor lighting up edges it's merely passing near.
      interactionWidth: EDGE_INTERACTION_WIDTH,
      data: { edge: e, emphasis, overlay: ui.overlay, showLabel },
    });
  }

  // groups first → they render behind the device cards.
  return { nodes: [...groupNodes, ...deviceNodes], edges };
}
