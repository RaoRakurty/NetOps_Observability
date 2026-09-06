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
import { GROUP_PAD, LABEL_BAND } from "../../layout/groupGeometry";
import { NODE_SIZE } from "../../layout/layoutTypes";
import type { RFNodeData, RFEdgeData, RFGroupData, NodeEmphasis, EdgeEmphasis } from "./rfTypes";
import { NODE_TYPE_FOR_KIND, EDGE_TYPE_FOR_VARIANT, CLOUD_RESOURCE_NODE_TYPE } from "./rfTypes";
import { edgeVariant, hasEvidence, rollupHealth } from "../../utils/topologyHealth";
import { labelDensityForZoom, tierForZoom } from "../../utils/semanticZoom";
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

/**
 * Union of the boxes occupied by `nodeIds` (device cards, NODE_SIZE) and
 * `groupIds` (container rectangles ELK solved, when it solved one).
 *
 * The group ids matter for NESTING: a REGION's members are not devices, they are
 * other GROUPS (VPCs, which nest via `parent_id`). Measuring only the device
 * cards would still work for a region whose VPCs contain devices, but it would
 * clip a nested container that ELK padded — and it returned null outright for a
 * container whose descendants are all groups, which is how every region box was
 * silently dropped (#134).
 */
function bboxOf(nodeIds: string[], positions: LayoutResult, groupIds: string[] = []): BBox | null {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  let any = false;
  for (const id of nodeIds) {
    const p = positions[id];
    if (!p) continue;
    any = true;
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + NODE_SIZE.width);
    maxY = Math.max(maxY, p.y + NODE_SIZE.height);
  }
  for (const id of groupIds) {
    const p = positions[id];
    if (!p || !p.w || !p.h) continue;
    any = true;
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + p.w);
    maxY = Math.max(maxY, p.y + p.h);
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

  // node → its DIRECT group, plus the group hierarchy (parent_id). Both are needed:
  // membership is declared on the leaf group, nesting only on `parent_id`.
  const nodeGroup = new Map<string, string>();
  for (const g of view.groups) for (const c of g.children) nodeGroup.set(c, g.id);
  const groupById = new Map(view.groups.map((g) => [g.id, g]));
  // parent → child GROUPS. A region's members are groups, not nodes.
  const childGroups = new Map<string, string[]>();
  for (const g of view.groups) {
    const p = g.parent_id;
    if (!p || p === g.id || !groupById.has(p)) continue;
    const arr = childGroups.get(p);
    if (arr) arr.push(g.id);
    else childGroups.set(p, [g.id]);
  }

  /**
   * Every node and every group BELOW `id` in the container tree. Iterative with a
   * visited set so a malformed cycle (`a.parent=b`, `b.parent=a`) cannot hang the
   * renderer — the same bounded-walk discipline `depthOf` uses.
   */
  const descendantCache = new Map<string, { nodes: string[]; groups: string[] }>();
  const descendantsOf = (id: string): { nodes: string[]; groups: string[] } => {
    const hit = descendantCache.get(id);
    if (hit) return hit;
    const nodes: string[] = [];
    const groups: string[] = [];
    const seen = new Set<string>([id]);
    const stack = [id];
    while (stack.length > 0) {
      const cur = stack.pop() as string;
      for (const c of groupById.get(cur)?.children ?? []) nodes.push(c);
      for (const kid of childGroups.get(cur) ?? []) {
        if (seen.has(kid)) continue;
        seen.add(kid);
        groups.push(kid);
        stack.push(kid);
      }
    }
    const out = { nodes, groups };
    descendantCache.set(id, out);
    return out;
  };

  /**
   * The OUTERMOST collapsed container above a node, or undefined. Collapse has to
   * look at ancestors, not just the direct group: collapsing a region must hide the
   * devices inside its VPCs (and reroute their edges to the region card), otherwise
   * the aggregate card floats beside the members it claims to have swallowed.
   */
  const collapsedRootCache = new Map<string, string | undefined>();
  const collapsedRootOf = (nodeId: string): string | undefined => {
    if (collapsedRootCache.has(nodeId)) return collapsedRootCache.get(nodeId);
    let cur: string | undefined = nodeGroup.get(nodeId);
    let out: string | undefined;
    let d = 0;
    while (cur && d < 8) {
      if (collapsed.has(cur)) out = cur;
      cur = groupById.get(cur)?.parent_id;
      d++;
    }
    collapsedRootCache.set(nodeId, out);
    return out;
  };
  const isHidden = (nodeId: string) => collapsedRootOf(nodeId) !== undefined;
  const resolveEndpoint = (nodeId: string) => collapsedRootOf(nodeId) ?? nodeId;

  // ── group nodes (container when expanded, aggregate card when collapsed) ──────
  const groupNodes: Node<RFGroupData>[] = [];
  // Nesting depth per group, from parent_id. Bounded walk: a malformed cycle
  // must not hang the renderer.
  const depthOf = (id: string): number => {
    let d = 0;
    let cur = groupById.get(id)?.parent_id;
    while (cur && d < 8) {
      d++;
      cur = groupById.get(cur)?.parent_id;
    }
    return d;
  };
  /** True when some PROPER ancestor of `id` is collapsed (this box is swallowed). */
  const hasCollapsedAncestor = (id: string): boolean => {
    let cur = groupById.get(id)?.parent_id;
    let d = 0;
    while (cur && d < 8) {
      if (collapsed.has(cur)) return true;
      cur = groupById.get(cur)?.parent_id;
      d++;
    }
    return false;
  };

  const nodeById = new Map(view.nodes.map((n) => [n.id, n]));
  for (const g of view.groups) {
    // A container's members are its DESCENDANTS, not only its direct children: a
    // region declares no node children at all (its VPCs do), so measuring direct
    // children dropped every region box — the canvas drew 0 region boundaries for
    // a cloud view that declares 2 (#134). ELK already nests the containers
    // correctly; only this derivation was flat.
    const desc = descendantsOf(g.id);
    const memberNodes = desc.nodes.map((id) => nodeById.get(id)).filter(Boolean) as typeof view.nodes;
    const bbox = bboxOf(desc.nodes, positions, desc.groups);
    // A box that is inside a collapsed ancestor is not drawn at all — the ancestor's
    // aggregate card stands for it.
    if (hasCollapsedAncestor(g.id)) continue;
    // DRAW THE RECT ELK SOLVED when it solved one (single-source geometry rule
    // below); it is also what lets a region render whose descendants are groups.
    const solved = positions[g.id];
    const solvedRect = solved?.w && solved?.h ? { x: solved.x, y: solved.y, w: solved.w, h: solved.h } : null;
    if (memberNodes.length === 0 && desc.groups.length === 0) continue; // genuinely empty
    if (!bbox && !solvedRect) continue; // nothing laid out yet

    const critical = memberNodes.filter((n) => n.health === "critical").length;
    const warning = memberNodes.filter((n) => n.health === "warning").length;
    const memberSet = new Set(desc.nodes);
    const links = view.edges.filter((e) => memberSet.has(e.source) || memberSet.has(e.target)).length;
    const worst: Health = rollupHealth(memberNodes);
    const counts = { total: memberNodes.length, critical, warning, links };
    const isCollapsed = collapsed.has(g.id);
    const emphasis: NodeEmphasis = ui.selection.groupId === g.id ? "spotlight" : "normal";
    // Centre for the collapsed aggregate card: the measured descendants when we
    // have them, else the rect ELK solved.
    const cx = bbox ? bbox.cx : (solvedRect as { x: number; w: number }).x + (solvedRect as { w: number }).w / 2;
    const cy = bbox ? bbox.cy : (solvedRect as { y: number; h: number }).y + (solvedRect as { h: number }).h / 2;

    if (isCollapsed) {
      groupNodes.push({
        id: g.id,
        type: "groupNode",
        position: { x: cx - 104, y: cy - 44 },
        // No declared size: the aggregate card's height is content-driven
        // (GroupNode sets a min, not a fixed height), and declaring a guess would
        // hand React Flow a box that is not the one on screen. The expanded
        // container below CAN declare its size, because ELK solved it exactly.
        data: { group: g, collapsed: true, emphasis, counts, health: worst, onToggle: ui.onToggleGroup, depth: depthOf(g.id) },
        zIndex: 2,
        selectable: true,
        // A group's position is always re-derived from its children's bbox, so a
        // drag was a no-op that snapped back — while still writing a junk pin
        // into the saved layout (audit S8). Groups are not draggable.
        draggable: false,
      });
    } else {
      // DRAW THE RECT ELK SOLVED. Re-deriving it here from member positions —
      // with padding constants that differed from the ones ELK reserved with —
      // is what produced asymmetric padding and sibling boxes that nearly
      // touched despite a clean layout. The fallback keeps a view whose layout
      // predates container geometry rendering rather than dropping the group,
      // and measures DESCENDANTS (nested container rects included) so a region's
      // fallback box still encloses its VPCs.
      const rect = solvedRect ?? {
        x: (bbox as BBox).minX - GROUP_PAD,
        y: (bbox as BBox).minY - GROUP_PAD - LABEL_BAND,
        w: (bbox as BBox).w + GROUP_PAD * 2,
        h: (bbox as BBox).h + GROUP_PAD * 2 + LABEL_BAND,
      };
      groupNodes.push({
        id: g.id,
        type: "groupNode",
        position: { x: rect.x, y: rect.y },
        data: {
          group: g, collapsed: false, emphasis, counts, health: worst,
          onToggle: ui.onToggleGroup,
          // Nesting depth drives per-level styling (region shaded, VPC outlined,
          // subnet dashed) — identical styling at every level is why nested
          // containers were unreadable.
          depth: depthOf(g.id),
        },
        style: { width: rect.w, height: rect.h },
        // DECLARE the container's size as well as styling it. Without this React
        // Flow measures the box from the DOM a frame later, so fit-to-view (which
        // runs 60ms after the layout lands) computed its bounds from placeholder
        // sizes — the fitted canvas then no longer matched the drawn one and the
        // network hung off the stage. This is the container half of the
        // no-re-measure rule the device card already follows.
        width: rect.w,
        height: rect.h,
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
            // A7: a search match is named at ANY zoom — a zoomed-out search that
            // highlights anonymous badges answers "where" but not "which".
            ? ui.zoom === undefined || labelDensityForZoom(ui.zoom) || unhealthy || critical || selected || ui.searchMatches.has(n.id)
            : density === "incident"
              ? unhealthy || critical || rcaFlag || selected
              : /* executive */ unhealthy || critical || selected;
      const showLabel = ui.showAllLabels || labelByDensity;
      // The per-node metric strip is the engineer/incident detail tier — names alone
      // at operator, names + telemetry at engineer, so operator≠engineer is visible
      // too; wallboard clutter is kept off the executive view.
      const showMetrics = density === "engineer" || density === "incident";

      // A cloud resource that DECLARES a provider renders as the provider-marked
      // card; everything else keeps the type its KIND maps to. Decided by fact,
      // in the one place that already knows both the domain and the renderer, so
      // the unified canvas needs no second nodeTypes registry (#131d).
      const type =
        n.kind === "cloud" && n.tags?.provider
          ? CLOUD_RESOURCE_NODE_TYPE
          : NODE_TYPE_FOR_KIND[n.kind] ?? "deviceNode";

      return {
        id: n.id,
        type,
        position: positions[n.id] ?? { x: 0, y: 0 },
        // Declared dimensions = the card's FIXED size, so React Flow never
        // re-measures the node when the array is rebuilt on hover (the device
        // card renders at exactly CARD_W × CARD_H). This is what keeps a hovered
        // node from shaking as spotlight recomputes.
        width: CARD_W,
        height: CARD_H,
        data: {
          node: n,
          emphasis,
          showLabel,
          overlay: ui.overlay,
          metricsLine: showMetrics ? metricsLine(n.metrics) : undefined,
          // Adaptive tier from the semantic-zoom bucket: shapes at distance,
          // names at working zoom, full anatomy up close. Undefined zoom
          // (tests/static renders) keeps the full card.
          // A6: the tier comes from the SHARED ladder (semanticZoom.ts), so the
          // canvas's bucket boundaries and the render tiers can never disagree.
          // Density is an EXPLICIT operator choice; zoom is implicit context, so
          // density wins. Engineer/incident asked for maximum detail, and
          // gating that behind a zoom threshold is why "Engineer" could look
          // identical to "Operator" — the control appeared to do nothing at the
          // zoom the canvas happens to fit to (1.15 → "fabric" → token tier,
          // which omits the metric strip entirely).
          tier: density === "engineer" || density === "incident" ? "card" : tierForZoom(ui.zoom),
        },
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

    // Edge labels obey the SAME zoom ladder node labels do. Without this, the
    // Labels toggle (and engineer density, which implies it) rendered every port
    // chip at global zoom — the all-labels-at-once pile the skill forbids, just
    // on edges instead of nodes, where it is worse because chips overlap the
    // links themselves.
    //
    // A focused edge — on the RCA path, or explicitly selected — is still named
    // at any zoom: that is the one the operator is looking at, and hiding it
    // because they zoomed out defeats the purpose of selecting it.
    const focusedEdge = emphasis === "strong" || ui.selection.edgeId === e.id;
    const labelLegibleAtZoom = ui.zoom === undefined || labelDensityForZoom(ui.zoom);
    const showLabel = focusedEdge || (ui.showAllLabels && labelLegibleAtZoom);

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

  // groups first → they render behind the device cards; OUTER containers before
  // inner ones (equal zIndex ⇒ array order decides), so a region never paints
  // over the VPC boxes nested inside it.
  groupNodes.sort((a, b) => ((a.data.depth ?? 0) - (b.data.depth ?? 0)));
  return { nodes: [...groupNodes, ...deviceNodes], edges };
}
