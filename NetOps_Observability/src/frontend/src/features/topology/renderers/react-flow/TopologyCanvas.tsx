// TopologyCanvas.tsx — the Phase-1 React Flow operator canvas. It is the ONLY
// renderer wired in Phase 1; it consumes a renderer-agnostic TopologyView, lays it
// out with ELK, and maps it through topologyToReactFlow. Sigma/geo adapters exist
// but are not mounted (prepared, not implemented).
//
// Performance discipline (PDF §13): selection/spotlight live in their OWN state,
// separate from the node/edge arrays; layout is computed in an effect (cached in
// elkLayout) — never recomputed on every render; the RF node/edge arrays are derived
// via useMemo and only rebuilt when the view, layout, or UI state actually change.

import { useCallback, useEffect, useMemo, useRef, useState, lazy, Suspense } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  BackgroundVariant,
  useReactFlow,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeMouseHandler,
  type EdgeMouseHandler,
  type OnNodeDrag,
} from "@xyflow/react";
import type { Padding, PaddingWithUnit } from "@xyflow/system";
import "@xyflow/react/dist/style.css";

import type { OverlayKind, TopologySelection, WorkflowMode, TopologyView } from "../../api/topologyTypes";
import { fetchTopologyView, fetchTopologyGraph, fetchRcaPathView, type TopologyCoverage, type TopologyGraphStatus, type TopologyViewStatus } from "../../api/topologyApi";
import { api, type CorrObject } from "../../../../services/api";
import { layoutView, viewSignature } from "../../layout/elkLayout";
import { bucketForZoom } from "../../utils/semanticZoom";
import { CARD_W, CARD_H } from "./nodes/DeviceNode";

/** Skill graph-scale-policy: past this, the WebGL overview owns the fabric. */
const MAX_CANVAS_NODES = 1000;

/** Width the Devices inventory overlay occupies (252px panel + 10px offset). */
const INVENTORY_W = 262;

/**
 * fitPadding — viewport insets that ACCOUNT FOR DOCKED CHROME.
 *
 * The inventory panel is an absolutely-positioned overlay ON the canvas, so the
 * viewport has no idea it exists: a uniform padding fits content into the whole
 * stage and the leftmost ~262px lands underneath the panel. That is the group
 * box "going under the rail".
 *
 * React Flow ≥12.5 accepts per-side padding with units, so the inset can simply
 * be told about the panel. Note this fixes FIT; it does not stop a user PANNING
 * content under the panel — the structural cure is making the panel a flex
 * sibling so the canvas element itself is narrower, which is a larger change.
 */
function fitPadding(showInventory: boolean): Padding {
  const left: PaddingWithUnit = showInventory ? `${INVENTORY_W + 16}px` : "24px";
  return { left, top: "60px", right: "24px", bottom: "24px" };
}


import { detectArchetype, archetypeLayout, ARCHETYPES, type Archetype } from "../../utils/topologyArchetype";
import { TopologyInventoryPanel } from "../../components/TopologyInventoryPanel";
import type { LayoutResult } from "../../layout/layoutTypes";
import { loadSavedLayout, saveNodePosition, clearSavedLayoutsMatching } from "../../layout/savedLayoutStore";
import { topologyToReactFlow } from "./topologyToReactFlow";
import type { RFNodeData, RFEdgeData, RFGroupData } from "./rfTypes";

type AnyNodeData = RFNodeData | RFGroupData;
import { nodeTypes } from "./nodes";
import { edgeTypes } from "./edges";
import { WORKFLOWS, workflowById } from "../../workflows";
import { enterpriseScaleTopology, geoWanTopology } from "../../mock/index";

// Phase 4 WebGL overview — heavy (sigma + graphology layout). Lazy-loaded so it
// only enters the bundle when the operator opens the overview.
const SigmaTopologyView = lazy(() => import("../sigma/SigmaTopologyView"));
// Phase 5 geographic / WAN map — heavy (echarts world basemap). Lazy-loaded so
// it only enters the bundle when the operator opens the geo view.
const GeoTopologyMap = lazy(() => import("../geo/GeoTopologyMap"));
import { EMPTY_SPOTLIGHT } from "../../workflows/workflowTypes";
import { availableOverlays } from "../../utils/topologyOverlays";
import { regroupView, GROUP_DIMENSIONS, type GroupDimension } from "../../utils/topologyRegroup";
import { bundleParallelEdges } from "../../utils/edgeBundling";
import {
  readCanvasUrlState,
  writeCanvasUrlState,
  CANVAS_URL_DEFAULTS,
  type Arrangement,
} from "../../utils/canvasUrlState";
import { renderedNodeCount, allGroupIds, canAggregateUnderCeiling, expansionWouldExceed } from "../../utils/topologyScale";
import { focusSummary, focusView } from "../../utils/topologyFocus";
import { excludeInternalNodes } from "../../utils/topologyFilters";
import { filterViewByDomain, DOMAINS, type NetworkDomain } from "../../utils/topologyDomains";
import { withCarrierOverlay } from "../../utils/carrierOverlay";
import CloudTopologyView from "./CloudTopologyView";
import { pathEdgeIds, firstDegree, edgesWithin } from "../../graph/graphAlgorithms";
import {
  TopologyToolbar,
  TopologySearch,
  TopologySideDrawer,
  TopologyLegend,
  OverlaySelector,
  MapWorkflowSelector,
  PathAnalysisPanel,
  NetworkPathView,
  EvidencePopover,
  CapacityPanel,
  RcaVerdictBanner,
} from "../../components";
import type { RcaPathView } from "../../../../services/api";


type Density = "executive" | "operator" | "engineer" | "incident";

// nodeTypes/edgeTypes MUST be module-stable (imported consts) — never inline.

// Verdict-tier ranking for "which incident does Investigate land on?" — confirmed
// outranks suspected outranks undetermined (strings match the corr_objects Enum8).
const TIER_RANK: Record<string, number> = { confirmed: 3, suspected: 2, undetermined: 1 };

// mostActionableIncident picks the incident Investigate should auto-open: highest
// verdict tier, then highest confidence, then most recent. Without this, Investigate
// with nothing pinned renders the SAME graph as Explore (the backend projection is
// identical; only a pinned incident's RCA path differentiates it). Returns "" when
// the list is empty.
function mostActionableIncident(incidents: CorrObject[]): string {
  let best: CorrObject | undefined;
  for (const c of incidents) {
    if (!best) {
      best = c;
      continue;
    }
    const dt = (TIER_RANK[c.verdict_tier] ?? 0) - (TIER_RANK[best.verdict_tier] ?? 0);
    if (dt > 0) best = c;
    else if (dt === 0) {
      const dc = (c.top_confidence ?? 0) - (best.top_confidence ?? 0);
      if (dc > 0) best = c;
      else if (dc === 0 && (c.created_at ?? "") > (best.created_at ?? "")) best = c;
    }
  }
  return best?.correlation_id ?? "";
}

function CanvasInner({
  domain: domainProp,
  carrier: carrierProp,
  onDomain,
  onCarrier,
}: {
  domain?: NetworkDomain;
  carrier?: boolean;
  onDomain?: (d: NetworkDomain) => void;
  onCarrier?: (v: boolean) => void;
}) {
  const rf = useReactFlow();

  // Shareable canvas state (#133a). mode / overlay / domain / group-by /
  // arrangement / selection are read from the ROUTE once at mount and written back
  // on every change, so an investigation survives F5 and can be handed to a
  // colleague as a link instead of a screenshot. Read once (a ref, not state):
  // the canvas OWNS these values after mount, and re-reading the hash it just
  // wrote would fight its own controls.
  const urlState = useRef(readCanvasUrlState(typeof location !== "undefined" ? location.hash : "")).current;
  // A selection from the link is applied only once the view has loaded AND it
  // actually names something in it — an id from a stale/hand-edited link must not
  // open an inspector on a node that is not there.
  const pendingSelection = useRef(
    urlState.nodeId || urlState.edgeId || urlState.groupId
      ? { nodeId: urlState.nodeId, edgeId: urlState.edgeId, groupId: urlState.groupId }
      : null,
  );

  // CONTROLLED-OR-NOT. These were prop-only with a `"lan"` default and an
  // optional `onDomain?.()`. The canvas is mounted from the nav as
  // `<TopologyCanvas />` with NO props — so `onDomain` was undefined and every
  // domain click was a silent no-op. The domain could never leave "lan", which
  // meant the Cloud tab never mounted and `/api/topology/cloud` was never
  // called: the Cloud page was unreachable, not broken.
  //
  // Nothing errored, which is why it survived — an optional callback that is
  // never supplied fails silently by design. Now the component owns the state
  // when it is not given any, and still defers to a parent that does control it.
  const [domainSelf, setDomainSelf] = useState<NetworkDomain>(urlState.domain ?? CANVAS_URL_DEFAULTS.domain);
  const [carrierSelf, setCarrierSelf] = useState(false);
  const domain = domainProp ?? domainSelf;
  const carrier = carrierProp ?? carrierSelf;
  const setDomain = useCallback(
    (d: NetworkDomain) => { setDomainSelf(d); onDomain?.(d); },
    [onDomain],
  );
  const setCarrier = useCallback(
    (v: boolean) => { setCarrierSelf(v); onCarrier?.(v); },
    [onCarrier],
  );

  const [mode, setMode] = useState<WorkflowMode>(urlState.mode ?? CANVAS_URL_DEFAULTS.mode);
  const [overlay, setOverlay] = useState<OverlayKind>(urlState.overlay ?? CANVAS_URL_DEFAULTS.overlay);
  const [selection, setSelection] = useState<TopologySelection>({});
  const [searchMatches, setSearchMatches] = useState<Set<string>>(new Set());
  // Focus NARROWS the canvas to the matches (plus a hop of context); search
  // alone only spotlights. This is the escape hatch the >1000-node card
  // advertises — without it, a large tenant's canvas is unreachable.
  const [focusOn, setFocusOn] = useState(false);
  const [labelsToggle, setLabelsToggle] = useState(false);
  const [density, setDensity] = useState<Density>("operator");
  const [positions, setPositions] = useState<LayoutResult>({});
  const [laidOutKey, setLaidOutKey] = useState<string>("");
  // pure ELK result (for "reset layout") + whether any operator pin is active.
  const elkPositions = useRef<LayoutResult>({});
  const [layoutPinned, setLayoutPinned] = useState(false);
  // Hover state is transient and SEPARATE from click-selection: hover spotlights
  // first-degree neighbours (skill design-tokens) without opening the drawer.
  const [hoverNode, setHoverNode] = useState<string | undefined>();
  const [hoverEdge, setHoverEdge] = useState<string | undefined>();
  // Cursor position of the current hover — drives the EvidencePopover peek (a hover
  // glance at WHY a node/edge is here, without a click into the drawer).
  const [hoverPos, setHoverPos] = useState<{ x: number; y: number } | undefined>();
  const [fullscreen, setFullscreen] = useState(false);
  // ContainerLab-style inventory sidebar (vendor research §b). Default ON — the
  // list + canvas dual-pane is the point; one click hides it for wallboards.
  const [showInventory, setShowInventory] = useState(true);
  // Semantic-zoom bucket (skill §10): the ONLY zoom-derived state, bucketed at
  // the level boundaries so panning never re-derives nodes and zoom re-derives
  // them at most once per level crossing.
  const [zoomBucket, setZoomBucket] = useState(1);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  // Renderer toggle: the scoped React Flow canvas (default) vs. the WebGL
  // enterprise overview (Phase 4) vs. the geographic / WAN map (Phase 5).
  // Orthogonal to the workflow mode.
  const [renderer, setRenderer] = useState<"canvas" | "overview" | "geo">("canvas");
  // Group-by lens for the canvas (site default = the backend's own grouping).
  const [groupBy, setGroupBy] = useState<GroupDimension>(urlState.groupBy ?? CANVAS_URL_DEFAULTS.groupBy);

  // Data source: "live" = the per-mode projection (GET /api/topology/view); other
  // value "persisted" = the reconciler-maintained graph with stable ids + stale +
  // coverage (GET /api/topology/graph, #77). The fetched view overrides the
  // workflow's bundled sample.
  //
  // It does NOT fall back to a mock on failure — that is the point of
  // topologyApi's honesty contract: a failed fetch returns an EMPTY view plus a
  // status discriminator, and the canvas renders the error state rather than a
  // fabricated network presented as the operator's own. (This comment claimed
  // the opposite long after the behaviour changed; corrected 2026-08-01.)
  const [source, setSource] = useState<"live" | "persisted">("live");
  const [fetched, setFetched] = useState<TopologyView | null>(null);
  // Load-flash guard: true until the FIRST fetch for the current request identity
  // (mode/source/incident/path — NOT a background refresh) resolves. While loading
  // the stage shows a placeholder, never the previous network or the bundled
  // workflow sample — that stale fallback (fetched ?? workflow.view) was the flash.
  const [loading, setLoading] = useState(true);
  // A drill-down expansion the scale guard refused (a single group too large to
  // draw inline) — surfaces the WebGL-overview / search escape hatch for it.
  const [expandBlocked, setExpandBlocked] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<TopologyCoverage | null>(null);
  // Why the persistent graph is empty: nothing reconciled yet vs the read failed.
  // The two must never render as the same state (a failed read used to render a
  // MOCK fabric — someone else's devices — as the operator's live graph).
  const [graphStatus, setGraphStatus] = useState<TopologyGraphStatus | null>(null);
  // Same discriminator for the LIVE source (audit S2): a failed /view fetch used
  // to be indistinguishable from an empty network.
  const [viewStatus, setViewStatus] = useState<TopologyViewStatus | null>(null);
  // Freshness (audit S5): the canvas refetches on a cadence and shows data age —
  // a board left open for hours must never silently present stale health as now.
  const [refreshTick, setRefreshTick] = useState(0);
  // Investigate mode can pin a REAL incident: its RCA fault path (GET
  // /api/correlations/{id}/rca-path-view) is converted to a view and rendered on
  // the canvas, overriding the live projection. Empty = the live/mock projection.
  const [incidents, setIncidents] = useState<CorrObject[]>([]);
  const [incidentId, setIncidentId] = useState<string>("");
  // Auto-pin guard: Investigate lands on the most actionable incident ONCE per entry
  // into the mode, so it never silently mirrors Explore — but a later switch to "Live
  // projection" is the operator's call and must not be overridden.
  const autoPinnedRef = useRef(false);
  // Path Trace endpoints: without a src+dst the backend can't resolve a path, so
  // path_trace would look identical to Explore. These drive a real A→B trace.
  const [pathSrc, setPathSrc] = useState<string>("");
  const [pathDst, setPathDst] = useState<string>("");
  // The src>dst the latest path_trace view was actually resolved for. Lets the stage
  // tell apart "still resolving" from "resolved, but no path exists" — so a failed
  // trace shows an honest 'no path found' state instead of silently falling back to
  // the full topology (which is indistinguishable from Explore).
  const [tracedKey, setTracedKey] = useState<string>("");
  // Raw overlay for the pinned incident — drives the verdict banner (the WHY).
  const [incidentOverlay, setIncidentOverlay] = useState<RcaPathView | null>(null);

  // Load the recent incident list once when Investigate mode is entered, to
  // populate the picker. Best-effort: a failure just leaves the picker empty.
  useEffect(() => {
    if (mode !== "investigate") return;
    let alive = true;
    (async () => {
      try {
        const r = await api.correlations(50);
        if (!alive) return;
        const list = r.data ?? [];
        setIncidents(list);
        // Land on the most actionable incident the first time we enter Investigate,
        // so the mode opens on a real RCA path instead of an Explore look-alike.
        if (!autoPinnedRef.current && list.length > 0) {
          autoPinnedRef.current = true;
          setIncidentId((cur) => (cur === "" ? mostActionableIncident(list) : cur));
        }
      } catch {
        if (alive) setIncidents([]);
      }
    })();
    return () => {
      alive = false;
    };
  }, [mode]);

  useEffect(() => {
    let alive = true;
    (async () => {
      // A pinned incident wins: render its RCA fault path. On a missing/empty path
      // fall through to the live projection so the canvas still shows something.
      if (mode === "investigate" && incidentId) {
        const rca = await fetchRcaPathView(incidentId);
        if (!alive) return;
        if (rca) {
          setFetched(rca.view);
          setIncidentOverlay(rca.overlay);
          setCoverage(null);
          setLoading(false);
          return;
        }
      }
      setIncidentOverlay(null); // no pinned incident (or path unavailable) → no banner
      if (source === "persisted") {
        const r = await fetchTopologyGraph();
        if (!alive) return;
        setFetched(r.view);
        setCoverage(r.coverage ?? null);
        setGraphStatus(r.status);
        setViewStatus(null);
      } else {
        const v = await fetchTopologyView(mode, mode === "path_trace" ? { src: pathSrc, dst: pathDst } : undefined);
        if (!alive) return;
        setFetched(v.view);
        setViewStatus(v.status);
        setCoverage(null);
        setGraphStatus(null); // graph status only describes the persisted source
        // Record what this view resolved for, so the stage can distinguish a resolved
        // empty path (no route) from one still in flight.
        setTracedKey(mode === "path_trace" && pathSrc && pathDst ? `${pathSrc}>${pathDst}` : "");
      }
      setLoading(false);
    })();
    return () => {
      alive = false;
    };
  }, [mode, source, incidentId, pathSrc, pathDst, refreshTick]);

  // Re-enter the loading state whenever the REQUEST IDENTITY changes (a new mode,
  // source, pinned incident or path endpoints) — but NOT on the 60s background
  // refresh (refreshTick is deliberately absent), so a wallboard keeps its current
  // view during a refetch instead of blinking a placeholder. This is what stops the
  // stage from flashing the prior network (or the bundled sample) on load/switch.
  useEffect(() => {
    setLoading(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, source, incidentId, pathSrc, pathDst]);

  // Periodic refetch (audit S5). 60s matches the backend reconciler cadence;
  // paused while the tab is hidden so a background wallboard doesn't hammer the
  // API. Operator pins live in `positions`/savedLayout and survive a refetch,
  // and the content-keyed layout cache means an unchanged graph re-renders
  // byte-identically.
  useEffect(() => {
    const t = setInterval(() => {
      if (!document.hidden) setRefreshTick((n) => n + 1);
    }, 60_000);
    return () => clearInterval(t);
  }, []);

  // Drop the pinned incident (and re-arm the auto-pin) when leaving Investigate mode,
  // so a fresh entry lands on the current top incident again.
  useEffect(() => {
    if (mode !== "investigate") {
      setIncidentId("");
      autoPinnedRef.current = false;
    }
  }, [mode]);

  const workflow = workflowById(mode);
  // Decision #76: the customer topology canvas shows the CUSTOMER's network — drop the
  // platform's own stack (api/correlation/prober/etc.) so it never pollutes the map.
  const baseView = useMemo(() => {
    // The render source is the FETCHED view only — never `workflow?.view`. That
    // bundled per-mode sample used to fill in before the first fetch resolved,
    // which is exactly the previous-network flash on load; the stage shows a
    // loading placeholder during that window instead (see `loading`).
    const v = fetched;
    if (!v) return v;
    // LAN + carrier-off is the IDENTITY path — the default canvas is byte-for-byte
    // unchanged. SD-WAN / DC apply a client-side domain slice; the carrier overlay
    // (any tab) appends the shared transport node + uplinks.
    let out = excludeInternalNodes(v);
    if (domain !== "lan") out = filterViewByDomain(out, domain);
    if (carrier) out = withCarrierOverlay(out);
    // LAG / parallel links collapse into ONE bundled edge (#133b). `edgeBundling`
    // shipped fully built and called by nothing, so a 4-member port-channel drew
    // as four stacked parallel curves the operator had to count by eye. It is a
    // pure view transform — the member links stay in the facts/evidence — and it
    // refuses to merge anything whose difference is the answer (a degraded or
    // RCA-flagged member, or links of different relationship classes).
    out = bundleParallelEdges(out);
    return out;
  }, [fetched, domain, carrier]);
  // Tag-dimension regrouping: re-bucket the canvas by site/role/vendor/owner (or none)
  // — the operator's lens, not just the backend's fixed site hierarchy.
  const groupedView = useMemo(
    () => (baseView ? regroupView(baseView, groupBy) : baseView),
    [baseView, groupBy],
  );
  // Focus is applied LAST and BEFORE the ceiling check, so narrowing can bring
  // an over-ceiling tenant back under it — that is the whole point.
  const view = useMemo(
    () => (groupedView && focusOn ? focusView(groupedView, searchMatches) : groupedView),
    [groupedView, focusOn, searchMatches],
  );
  // Group ids change with the lens, so any collapse state from the old grouping is
  // stale — clear it when the lens changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setCollapsedGroups(new Set()), [groupBy]);

  // Apply a selection carried in the link, ONCE, and only if the loaded view really
  // contains that id — a shared investigation opens on the object it named, and a
  // stale link degrades to the plain canvas instead of an inspector on nothing.
  useEffect(() => {
    const want = pendingSelection.current;
    if (!want || !view) return;
    pendingSelection.current = null;
    if (want.nodeId && view.nodes.some((n) => n.id === want.nodeId)) setSelection({ nodeId: want.nodeId });
    else if (want.edgeId && view.edges.some((e) => e.id === want.edgeId)) setSelection({ edgeId: want.edgeId });
    else if (want.groupId && view.groups.some((g) => g.id === want.groupId)) setSelection({ groupId: want.groupId });
  }, [view]);

  const showAllLabels = labelsToggle || density === "engineer";

  // Owner Step 2 — topology ARCHETYPE: detect the network's textbook shape
  // (ring/star/bus/mesh/leaf-spine) and arrange it the way an engineer would
  // draw it. "auto" applies the detected shape only when the structure matches
  // cleanly (confidence ≥ 0.8); the operator can force any shape.
  const [arrange, setArrange] = useState<Arrangement>(urlState.arrange ?? CANVAS_URL_DEFAULTS.arrange);

  // Write the shareable state back onto the route (#133a). replaceState, so the
  // back button is not filled with one entry per overlay flick.
  useEffect(() => {
    writeCanvasUrlState(
      { mode, overlay, domain, groupBy, arrange, nodeId: selection.nodeId, edgeId: selection.edgeId, groupId: selection.groupId },
      typeof location !== "undefined" ? location.hash : "",
    );
  }, [mode, overlay, domain, groupBy, arrange, selection]);
  // Scale policy. The ceiling that matters is NOT the raw node count but the
  // number of nodes React Flow RENDERS: when a large fabric is auto-collapsed to
  // its groups (below), the canvas draws a few dozen aggregate cards and is fully
  // interactive. `rawOverCeiling` = the raw fabric is too big to draw node-by-node;
  // `aggregateAtScale` = it CAN be shown as a sub-ceiling aggregate (has groups
  // that collapse under budget) — the default at scale; `overCeiling` = the ACTUAL
  // rendered count is over budget (gates the heavy ELK/RF-array compute, and — only
  // when aggregation is impossible — the last-resort "too many nodes" card).
  const rawOverCeiling = !!view && view.nodes.length > MAX_CANVAS_NODES;
  const aggregateAtScale = !!view && rawOverCeiling && canAggregateUnderCeiling(view, MAX_CANVAS_NODES);
  const renderCount = view ? renderedNodeCount(view, collapsedGroups) : 0;
  const overCeiling = !!view && renderCount > MAX_CANVAS_NODES;
  // A5: the ceiling gates COMPUTE too — a large tenant must not pay a main-thread
  // ELK run + full RF-array build every refetch just to show the fallback card.
  // Archetype detection is skipped on the RAW over-ceiling fabric (analysing
  // thousands of nodes is pointless once we aggregate — groups get default layout).
  const detected = useMemo(
    () => (view && !rawOverCeiling ? detectArchetype(view) : null),
    [view, rawOverCeiling],
  );
  const effectiveArchetype: Archetype | null =
    arrange !== "auto"
      ? arrange
      : detected && detected.confidence >= 0.8 && detected.archetype !== "irregular"
        ? detected.archetype
        : null;

  // saved-layout key: invalidated when the view, layout type, arrangement, or
  // CONTENT changes. Content-keyed (audit S4): node cardinality alone let pins
  // bleed between the domain lenses (SD-WAN vs DC slices with equal counts
  // shared one key).
  const layoutKey = view
    ? `${view.view_id}:${view.layout_type}:${effectiveArchetype ?? "elk"}:${viewSignature(view)}`
    : "";

  // (Re)compute layout only when the active view/arrangement changes. Analytic
  // archetype layouts (ring/star/bus/mesh — deterministic, no physics) place
  // synchronously; everything else runs the cached ELK layered presets. A forced
  // leaf-spine re-runs ELK with the spine_leaf role-tiered preset.
  useEffect(() => {
    let alive = true;
    if (!view || overCeiling) {
      setPositions({});
      return;
    }
    const finish = (pos: LayoutResult) => {
      if (!alive) return;
      elkPositions.current = pos;
      // operator pins override the computed layout for the nodes they cover (skill §3).
      const saved = loadSavedLayout(layoutKey);
      const pinCount = Object.keys(saved).length;
      setLayoutPinned(pinCount > 0);
      setPositions(pinCount > 0 ? { ...pos, ...saved } : pos);
      setLaidOutKey(`${view.view_id}:${effectiveArchetype ?? "elk"}`);
    };
    const analytic = effectiveArchetype ? archetypeLayout(view, effectiveArchetype) : null;
    if (analytic) {
      finish(analytic);
      return;
    }
    const elkView = arrange === "leaf_spine" ? { ...view, layout_type: "spine_leaf" as const } : view;
    layoutView(elkView).then(finish);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, layoutKey, effectiveArchetype, overCeiling]);

  // Persist a dragged node and keep it pinned for this session. Group nodes are
  // excluded (their position is derived from children — audit S8): they are no
  // longer draggable, and the guard keeps a junk pin out even if that changes.
  const onNodeDragStop = useCallback<OnNodeDrag<Node<AnyNodeData>>>(
    (_e, n) => {
      if (!layoutKey || n.type === "groupNode") return;
      saveNodePosition(layoutKey, n.id, n.position);
      setPositions((p) => ({ ...p, [n.id]: n.position }));
      setLayoutPinned(true);
    },
    [layoutKey],
  );

  const onResetLayout = useCallback(() => {
    // Sweep EVERY pin-set for this view, not just the current content-keyed
    // one: topology refreshes re-key the store (signature includes node/edge
    // ids), so pins routinely live under stale keys the old single-key clear
    // never touched — which is why Reset "stopped working" (2026-08-25).
    if (view) clearSavedLayoutsMatching(`${view.view_id}:`);
    setPositions({ ...elkPositions.current });
    setLayoutPinned(false);
    setTimeout(() => rf.fitView({ padding: fitPadding(showInventory), duration: 300 }), 40);
  }, [view, rf, showInventory]);

  // Reset transient selection when the workflow changes. Capacity opens on the
  // utilization overlay (its whole point); other modes default to health.
  useEffect(() => {
    setSelection({});
    setSearchMatches(new Set());
    setHoverNode(undefined);
    setHoverEdge(undefined);
    setHoverPos(undefined);
    setCollapsedGroups(new Set());
    setOverlay(mode === "capacity" ? "utilization" : "health");
    setPathSrc("");
    setPathDst("");
    setTracedKey("");
    setExpandBlocked(null);
  }, [mode]);

  // Aggregate-by-default at scale. When the raw fabric is over the interactive
  // ceiling but CAN be shown as its groups (default lens = site), auto-collapse
  // every group: the canvas draws a few dozen aggregate cards — interactive and
  // under the ceiling — instead of the dead-end "too many nodes" card. The
  // operator drills in by expanding a group (guarded by onToggleGroup). Declared
  // AFTER the group-by / mode reset effects so it wins the commit-phase ordering,
  // and keyed on the view IDENTITY + lens (not the object) so a 60s background
  // refetch doesn't undo the operator's manual expands.
  useEffect(() => {
    if (aggregateAtScale && view) setCollapsedGroups(allGroupIds(view));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aggregateAtScale, view?.view_id, groupBy]);

  // Endpoint options for the Path Trace picker: every node, by label, sorted.
  const endpointOptions = useMemo(
    () =>
      (view?.nodes ?? [])
        .map((n) => ({ id: n.id, label: n.label || n.id }))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [view],
  );

  // node → group lookup, for collapse hiding + search-to-expand.
  const nodeGroup = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of view?.groups ?? []) for (const c of g.children) m.set(c, g.id);
    return m;
  }, [view]);

  const onToggleGroup = useCallback((groupId: string) => {
    if (collapsedGroups.has(groupId)) {
      // Expanding (drill-down). Guard the interactive ceiling: if revealing this
      // group's devices would push the rendered count over budget — a single huge
      // group — keep it collapsed and surface the overview/search escape hatch.
      if (view && expansionWouldExceed(view, collapsedGroups, groupId, MAX_CANVAS_NODES)) {
        setExpandBlocked(groupId);
        return;
      }
      setExpandBlocked(null);
      const next = new Set(collapsedGroups);
      next.delete(groupId);
      setCollapsedGroups(next);
    } else {
      const next = new Set(collapsedGroups);
      next.add(groupId);
      setCollapsedGroups(next);
    }
  }, [collapsedGroups, view]);

  // Search-to-expand: if a matched node sits inside a collapsed group, reveal it.
  useEffect(() => {
    if (searchMatches.size === 0 || collapsedGroups.size === 0) return;
    let changed = false;
    const next = new Set(collapsedGroups);
    for (const id of searchMatches) {
      const g = nodeGroup.get(id);
      if (g && next.has(g)) {
        next.delete(g);
        changed = true;
      }
    }
    if (changed) setCollapsedGroups(next);
  }, [searchMatches, nodeGroup, collapsedGroups]);

  // Spotlight priority: a click-selection wins (and opens the drawer); else a hover
  // spotlights first-degree neighbours (no drawer); else the workflow's default
  // (Investigate/PathTrace pre-spotlight their RCA/trace path; Explore stays calm).
  const spotlight = useMemo(() => {
    if (!view) return { ...EMPTY_SPOTLIGHT, soft: false };
    if (selection.edgeId) {
      const e = view.edges.find((x) => x.id === selection.edgeId);
      return { nodes: new Set(e ? [e.source, e.target] : []), edges: new Set(e ? [e.id] : []), soft: false };
    }
    if (selection.nodeId && workflow?.computeSpotlight) return { ...workflow.computeSpotlight(view, selection), soft: false };
    if (hoverNode) {
      const nodes = firstDegree(view, hoverNode);
      // SOFT spotlight: a passing hover brightens the node + its neighbours but must
      // NOT dim every other card — that all-at-once dim/undim on each graze is what
      // read as a "shake". Heavy dim is reserved for a deliberate click-selection.
      return { nodes, edges: edgesWithin(view, nodes), soft: true };
    }
    if (workflow?.computeSpotlight) return { ...workflow.computeSpotlight(view, {}), soft: false };
    return { ...EMPTY_SPOTLIGHT, soft: false };
  }, [view, workflow, selection, hoverNode]);

  // Derive React Flow nodes/edges. Pure, memoized on the inputs that matter.
  const derived = useMemo(() => {
    if (!view || overCeiling) return { nodes: [] as Node<AnyNodeData>[], edges: [] as Edge<RFEdgeData>[] };
    const strongEdges = new Set<string>(spotlight.edges);
    if (selection.edgeId) strongEdges.add(selection.edgeId);
    if (hoverEdge) strongEdges.add(hoverEdge);
    if (view.path && (mode === "investigate" || mode === "path_trace")) {
      for (const id of pathEdgeIds(view, view.path)) strongEdges.add(id);
    }
    return topologyToReactFlow(view, positions, {
      selection,
      spotlight: spotlight.nodes,
      spotlightSoft: spotlight.soft,
      strongEdges,
      overlay,
      showAllLabels,
      searchMatches,
      collapsedGroups,
      onToggleGroup,
      density,
      zoom: zoomBucket,
    });
  }, [view, positions, spotlight, selection, overlay, showAllLabels, searchMatches, mode, hoverEdge, collapsedGroups, onToggleGroup, density, zoomBucket, overCeiling]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node<AnyNodeData>>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge<RFEdgeData>>([]);

  useEffect(() => {
    setRfNodes(derived.nodes);
    setRfEdges(derived.edges);
  }, [derived, setRfNodes, setRfEdges]);

  // Fit the view once a fresh layout lands. maxZoom caps the fit so a SMALL graph (a
  // 2–3 node incident path) opens at a sensible default zoom instead of blowing up to
  // fill the viewport.
  const fittedFor = useRef<string>("");
  useEffect(() => {
    if (laidOutKey && laidOutKey !== fittedFor.current && rfNodes.length) {
      fittedFor.current = laidOutKey;
      const t = setTimeout(() => rf.fitView({ padding: fitPadding(showInventory), duration: 320, maxZoom: 1.15 }), 60);
      return () => clearTimeout(t);
    }
  }, [laidOutKey, rfNodes.length, rf]);

  // Fullscreen: toggle a class on the root and re-fit; Escape exits.
  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: fitPadding(showInventory), duration: 260 }), 80);
    return () => clearTimeout(t);
  }, [fullscreen, rf]);
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFullscreen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [fullscreen]);

  const onNodeClick = useCallback<NodeMouseHandler>((_e, n) => {
    // group nodes select as a group (drawer shows aggregate); devices select as nodes.
    if (n.type === "groupNode") setSelection({ groupId: n.id });
    else setSelection({ nodeId: n.id });
  }, []);
  const onEdgeClick = useCallback<EdgeMouseHandler>((_e, ed) => {
    setSelection({ edgeId: ed.id });
  }, []);
  const onPaneClick = useCallback(() => setSelection({}), []);
  // Bucket zoom at the semantic-level boundaries (semanticZoom.ts §10) so the
  // node array re-derives only when a LEVEL is crossed, never per wheel tick.
  const onMove = useCallback((_e: unknown, viewport: { zoom: number }) => {
    // A6: ONE ladder owns the zoom→detail mapping (semanticZoom.ts §10). The
    // bucket is the level's representative zoom, so the tier thresholds in the
    // adapter and the label-density rule can never disagree about where a
    // boundary is.
    setZoomBucket((prev) => {
      const next = bucketForZoom(viewport.zoom);
      return prev === next ? prev : next;
    });
  }, []);
  const onNodeMouseEnter = useCallback<NodeMouseHandler>((e, n) => {
    setHoverNode(n.id);
    setHoverPos({ x: e.clientX, y: e.clientY });
  }, []);
  const onNodeMouseLeave = useCallback(() => { setHoverNode(undefined); setHoverPos(undefined); }, []);
  const onEdgeMouseEnter = useCallback<EdgeMouseHandler>((e, ed) => {
    setHoverEdge(ed.id);
    setHoverPos({ x: e.clientX, y: e.clientY });
  }, []);
  const onEdgeMouseLeave = useCallback(() => { setHoverEdge(undefined); setHoverPos(undefined); }, []);

  const onPick = useCallback(
    (nodeId: string) => {
      setSelection({ nodeId });
      // A8: a pick that lands inside a COLLAPSED group would centre on a hidden
      // node and highlight nothing — reveal the group first (the same courtesy
      // search-to-expand already does for matches).
      const g = nodeGroup.get(nodeId);
      if (g && collapsedGroups.has(g)) {
        setCollapsedGroups((prev) => {
          const next = new Set(prev);
          next.delete(g);
          return next;
        });
      }
      const p = positions[nodeId];
      // A3: centre on the CARD's centre. The old +100/+44 were half of a 200×88
      // cell that no longer exists, so every inventory/search pick landed ~40px
      // off. Derived from the card constants so it cannot drift again.
      if (p) rf.setCenter(p.x + CARD_W / 2, p.y + CARD_H / 2, { zoom: 1.1, duration: 400 });
    },
    [positions, rf, nodeGroup, collapsedGroups],
  );

  const overlays = useMemo(() => (view ? availableOverlays(view) : []), [view]);
  // The overlay picker only shows AVAILABLE overlays; if the selected one stops being
  // available (e.g. switching to a view with no utilization), fall back to health so
  // the canvas never renders a stale overlay the operator can't change.
  useEffect(() => {
    if (overlay !== "health" && !overlays.some((o) => o.kind === overlay && o.available)) {
      setOverlay("health");
    }
  }, [overlays, overlay]);
  // Only the IMPLEMENTED workflows reach the selector — a greyed, do-nothing tab is a
  // dead control. Placeholder modes (change_review → covered by the Historical-diff
  // overlay; executive_geo → covered by the Geo renderer) stay defined for re-enable
  // but are not shown until they actually do something.
  const workflowMeta = useMemo(
    () => WORKFLOWS.filter((w) => w.implemented).map((w) => ({ id: w.id, label: w.label, implemented: w.implemented, blurb: w.blurb })),
    [],
  );

  // Path Trace resolution state (drives the guided stage). A non-empty traceKey means
  // both endpoints are chosen; traceResolving = the fetch for that pair is still in
  // flight; traceNoPath = it resolved with no route between them (LLDP/IGP gap) — that
  // is reported honestly rather than silently showing the full topology.
  // Only the live per-mode projection resolves an A→B path; the persisted graph is
  // mode-agnostic, so the guided trace states don't apply there.
  const traceMode = mode === "path_trace" && source === "live";
  const traceKey = pathSrc && pathDst ? `${pathSrc}>${pathDst}` : "";
  const traceResolving = traceMode && traceKey !== "" && tracedKey !== traceKey;
  const traceNoPath =
    traceMode && traceKey !== "" && tracedKey === traceKey && !(view?.path && view.path.length >= 2);
  const labelFor = (id: string) => endpointOptions.find((o) => o.id === id)?.label ?? id;

  return (
    <div className={`topo-root${fullscreen ? " topo-fullscreen" : ""}`}>
      <TopologyToolbar
        onFit={() => rf.fitView({ padding: fitPadding(showInventory), duration: 320 })}
        onZoomIn={() => rf.zoomIn({ duration: 200 })}
        onZoomOut={() => rf.zoomOut({ duration: 200 })}
        showAllLabels={showAllLabels}
        onToggleLabels={() => setLabelsToggle((v) => !v)}
        density={density}
        onDensityChange={setDensity}
        onResetLayout={onResetLayout}
        layoutPinned={layoutPinned}
      >
        {/* Network domain — a SELECT, not four buttons (owner 2026-08-01).
            Four side-by-side options spend a fixed strip of toolbar width on
            three choices that are not currently active; a dropdown spends one
            control's worth and lets the rest of the row breathe. The label
            stays visible on the closed control, so "where am I looking" is
            still answerable at a glance without opening it. */}
        <label className="topo-select-wrap" title="Network domain — which part of the estate the canvas is showing">
          <span className="topo-select-label">Domain</span>
          <select
            className="topo-select"
            aria-label="Network domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value as NetworkDomain)}
          >
            {DOMAINS.map((d) => (
              <option key={d.id} value={d.id} title={d.blurb}>
                {d.label}
              </option>
            ))}
          </select>
        </label>
        <button
          className={`topo-render-toggle topo-carrier${carrier ? " on" : ""}`}
          role="switch"
          aria-checked={carrier}
          onClick={() => setCarrier(!carrier)}
          title="Overlay the shared carrier / transport network — the fabric that ties LAN, SD-WAN, DC and Cloud together."
        >
          Carrier
        </button>
        {renderer === "canvas" && (
          <button
            className={`topo-render-toggle topo-carrier${showInventory ? " on" : ""}`}
            role="switch"
            aria-checked={showInventory}
            onClick={() => setShowInventory((v) => !v)}
            title="Device inventory beside the map — status, management IP, first observed."
          >
            Devices
          </button>
        )}
        <MapWorkflowSelector value={mode} onChange={setMode} workflows={workflowMeta} />
        {/* Data source: live per-mode projection vs the persistent reconciled graph. */}
        <div className="topo-render-toggle" role="tablist" aria-label="Data source">
          <button role="tab" aria-selected={source === "live"} className={source === "live" ? "on" : ""} onClick={() => setSource("live")} title="Live per-mode projection (recomputed each load)">
            Live
          </button>
          <button role="tab" aria-selected={source === "persisted"} className={source === "persisted" ? "on" : ""} onClick={() => setSource("persisted")} title="Persistent reconciled graph: stable ids, freshness and coverage">
            Persisted
          </button>
        </div>
        {source === "persisted" && coverage && (
          <span className="topo-coverage" title="Coverage of the persistent graph">
            {coverage.nodes} nodes · {coverage.edges} edges
            {coverage.stale_nodes + coverage.stale_edges > 0 && (
              <span className="topo-coverage-stale"> · {coverage.stale_nodes + coverage.stale_edges} stale</span>
            )}
          </span>
        )}
        {/* Freshness (audit S5): data age from the view's own generated_at, with
            an explicit stale warning past two refresh cycles. Never a wall clock. */}
        {fetched?.generated_at && viewStatus !== "sample" && (() => {
          const ageMs = Date.now() - Date.parse(fetched.generated_at);
          const stale = Number.isFinite(ageMs) && ageMs > 150_000;
          const ageLabel = !Number.isFinite(ageMs) || ageMs < 0 ? "" : ageMs < 90_000 ? "" : `${Math.round(ageMs / 60_000)}m old`;
          return (
            <span
              className="topo-coverage"
              style={stale ? { color: "var(--warn)" } : undefined}
              title={`Topology data generated at ${fetched.generated_at}; auto-refreshes every 60s`}
            >
              {stale ? `⚠ data ${ageLabel || "stale"}` : ageLabel || "live"}
            </span>
          );
        })()}
        {viewStatus === "sample" && (
          <span className="topo-coverage" style={{ color: "var(--warn)" }}
            title="No live data for this view yet — a sample is shown.">
            Sample data
          </span>
        )}
        {mode === "investigate" && (
          /* Pin a real incident to render its RCA fault path on the canvas. */
          <label className="topo-incident-picker" title="Render a real incident's RCA fault path on the canvas">
            <span className="topo-incident-picker-label">Incident</span>
            <select value={incidentId} onChange={(e) => setIncidentId(e.target.value)} aria-label="Pin an incident's RCA path">
              <option value="">Live projection</option>
              {incidents.map((c) => (
                <option key={c.correlation_id} value={c.correlation_id}>
                  {(c.verdict_tier ? `[${c.verdict_tier}] ` : "") + (c.top_hypothesis || c.correlation_id)}
                </option>
              ))}
            </select>
            {incidents.length === 0 && (
              <span className="topo-incident-picker-empty" title="No open correlations — Investigate is showing the live topology">
                No active incidents
              </span>
            )}
          </label>
        )}
        {mode === "path_trace" && pathSrc && pathDst && (
          /* Compact control once a path is active (the empty state lives in the
             stage as a guided card). Lets the operator re-aim the trace. */
          <label className="topo-incident-picker" title="Trace the path between two devices">
            <span className="topo-incident-picker-label">Path</span>
            <select value={pathSrc} onChange={(e) => setPathSrc(e.target.value)} aria-label="Path source device">
              <option value="">Source…</option>
              {endpointOptions.map((o) => (
                <option key={o.id} value={o.id} disabled={o.id === pathDst}>
                  {o.label}
                </option>
              ))}
            </select>
            <span className="topo-incident-picker-label" aria-hidden="true">→</span>
            <select value={pathDst} onChange={(e) => setPathDst(e.target.value)} aria-label="Path destination device">
              <option value="">Destination…</option>
              {endpointOptions.map((o) => (
                <option key={o.id} value={o.id} disabled={o.id === pathSrc}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        )}
        {view && renderer === "canvas" && <OverlaySelector value={overlay} overlays={overlays} onChange={setOverlay} />}
        {renderer === "canvas" && (
          <label className="topo-incident-picker" title="Regroup the canvas by a node dimension — Zone segregates by ownership border (LAN · WAN · DC · Cloud · ISP · DX/ExpressRoute)">
            <span className="topo-incident-picker-label">Group</span>
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupDimension)} aria-label="Group the canvas by">
              {GROUP_DIMENSIONS.map((d) => (
                <option key={d.id} value={d.id}>{d.label}</option>
              ))}
            </select>
          </label>
        )}
        {renderer === "canvas" && (
          /* Owner Step 2: arrange by topology archetype. Auto names what was
             detected and WHY (tooltip); forcing a shape redraws deterministically. */
          <label
            className="topo-incident-picker"
            title={detected ? `Detected: ${detected.archetype.replace("_", "-")} — ${detected.reason}` : "Arrange the canvas by topology shape"}
          >
            <span className="topo-incident-picker-label">Shape</span>
            <select value={arrange} onChange={(e) => setArrange(e.target.value as Arrangement)} aria-label="Arrange by topology shape">
              <option value="auto">
                Auto{detected && detected.archetype !== "irregular" && detected.confidence >= 0.8 ? ` (${ARCHETYPES.find((a) => a.id === detected.archetype)?.label ?? detected.archetype})` : ""}
              </option>
              {ARCHETYPES.map((a) => (
                <option key={a.id} value={a.id}>{a.label}</option>
              ))}
            </select>
          </label>
        )}
        <div className="topo-render-toggle" role="tablist" aria-label="Renderer">
          <button role="tab" aria-selected={renderer === "canvas"} className={renderer === "canvas" ? "on" : ""} onClick={() => setRenderer("canvas")}>
            Canvas
          </button>
          <button role="tab" aria-selected={renderer === "overview"} className={renderer === "overview" ? "on" : ""} onClick={() => setRenderer("overview")}>
            Overview
          </button>
          <button role="tab" aria-selected={renderer === "geo"} className={renderer === "geo" ? "on" : ""} onClick={() => setRenderer("geo")}>
            Geo
          </button>
        </div>
      </TopologyToolbar>

      {domain === "cloud" ? (
        /* Cloud tab: the SAME toolbar above; only the stage content is the cloud
           network canvas (own nodeTypes/official icons, but the shared ELK layout,
           node-card shell, legend and drawer — so it looks and behaves natively). */
        <CloudTopologyView carrier={carrier} />
      ) : (
      <div className="topo-stage">
        <button
          className="topo-fs-btn"
          onClick={() => setFullscreen((f) => !f)}
          title={fullscreen ? "Exit full screen (Esc)" : "Full screen"}
          aria-label={fullscreen ? "Exit full screen" : "Full screen"}
        >
          {fullscreen ? "⤡ Exit" : "⤢ Full screen"}
        </button>
        {renderer === "overview" ? (
          /* Audit S1: the overview renders the operator's REAL graph. The bundled
             synthetic fabric survives ONLY as an explicitly-badged sample when no
             real data exists — never presented as the live network. */
          <Suspense fallback={<div className="topo-sigma-loading">Loading enterprise overview…</div>}>
            <SigmaTopologyView view={view && view.nodes.length > 0 ? view : enterpriseScaleTopology} />
            {(!view || view.nodes.length === 0) && (
              <span className="topo-coverage" role="status"
                style={{ position: "absolute", top: 10, left: 10, color: "var(--warn)", background: "var(--panel)", padding: "3px 8px", borderRadius: 6, border: "1px solid var(--border)" }}
                title="No live topology resolved for this view — a sample fabric is shown instead.">
                Sample data — not your network
              </span>
            )}
          </Suspense>
        ) : renderer === "geo" ? (
          <Suspense fallback={<div className="topo-geo-loading">Loading geographic map…</div>}>
            <GeoTopologyMap view={geoWanTopology} />
          </Suspense>
        ) : loading ? (
          // Load-flash guard: while the live view for this request is still
          // resolving, show a placeholder — NEVER the previous network or the
          // bundled workflow sample. (Matches the sigma/geo loading patterns.)
          //
          // A TRACE in flight gets the trace-specific wording. The generic gate
          // used to win unconditionally, which made PathTraceResolving
          // unreachable: `loading` is set by the same endpoint change that starts
          // the trace, and by the time it clears the pair is already resolved. An
          // operator who has just picked two devices is told what is being
          // resolved, not merely that something is.
          traceMode && traceKey && view ? (
            <PathTraceResolving srcLabel={labelFor(pathSrc)} dstLabel={labelFor(pathDst)} />
          ) : (
            <div className="topo-canvas-loading" role="status" aria-live="polite">
              Loading topology…
            </div>
          )
        ) : !view ? (
          <PlaceholderWorkflow blurb={workflow?.blurb ?? "This workflow arrives in a later phase."} label={workflow?.label ?? ""} />
        ) : mode === "path_trace" && !(pathSrc && pathDst) ? (
          <PathTracePrompt
            options={endpointOptions}
            src={pathSrc}
            dst={pathDst}
            onSrc={setPathSrc}
            onDst={setPathDst}
          />
        ) : traceResolving ? (
          <PathTraceResolving srcLabel={labelFor(pathSrc)} dstLabel={labelFor(pathDst)} />
        ) : traceNoPath ? (
          <PathTraceNoPath
            srcLabel={labelFor(pathSrc)}
            dstLabel={labelFor(pathDst)}
            options={endpointOptions}
            src={pathSrc}
            dst={pathDst}
            onSrc={setPathSrc}
            onDst={setPathDst}
          />
        ) : mode === "path_trace" && view.path && view.path.length >= 2 ? (
          // Dedicated source→destination view (#77): the resolved path as a clean
          // L→R ribbon, NOT the full topology with the path merely highlighted.
          <NetworkPathView view={view} />
        ) : overCeiling && !aggregateAtScale ? (
          // Last-resort scale fallback (audit S10). We only reach here when the raw
          // fabric is over the ceiling AND cannot be aggregated under it — no
          // grouping dimension (Group = None), or even fully collapsed the group +
          // ungrouped count is still over budget. Otherwise the canvas shows the
          // auto-collapsed AGGREGATE (group cards) — see aggregateAtScale.
          <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ maxWidth: 520, textAlign: "center", padding: "18px 22px", border: "1px dashed var(--border)", borderRadius: 10, background: "var(--panel)" }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                {view.nodes.length.toLocaleString()} nodes — too many for the interactive canvas
              </div>
              <div style={{ fontSize: 12, color: "var(--fg-muted)", lineHeight: 1.5, marginBottom: 10 }}>
                Pick a grouping dimension to aggregate the fabric into sites/regions,
                search for the part you care about and focus the canvas on it, or open
                the WebGL overview for the whole fabric.
              </div>
              {/* The search dock lives in the OTHER branch, so an over-ceiling
                  tenant previously had no way to act on the advice above. Mount
                  it here too: this is the advertised escape hatch. */}
              <div style={{ marginBottom: 10 }}>
                <TopologySearch view={view} onMatches={setSearchMatches} onPick={onPick} />
              </div>
              <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
                <button
                  className="btn btn-sm btn-primary"
                  disabled={searchMatches.size === 0}
                  onClick={() => setFocusOn(true)}
                  title={searchMatches.size === 0
                    ? "Search first — focus narrows the canvas to what you matched"
                    : `Focus on ${searchMatches.size} matched node(s) and their neighbours`}
                >
                  Focus on {searchMatches.size || "matches"}
                </button>
                <button className="btn btn-sm" onClick={() => setRenderer("overview")}>
                  Open enterprise overview
                </button>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* Search shifts clear of the inventory rail when it is open. */}
            <div className={`topo-search-dock${showInventory ? " with-inventory" : ""}`}>
              <TopologySearch view={groupedView ?? view} onMatches={setSearchMatches} onPick={onPick} />
              {/* Focus turns a spotlight into a filter. Offered only when there
                  is something to focus ON, so it never reads as a dead control. */}
              {searchMatches.size > 0 && !focusOn && (
                <button className="btn btn-xs" onClick={() => setFocusOn(true)}
                  title="Narrow the canvas to these matches and their neighbours">
                  Focus on {searchMatches.size}
                </button>
              )}
            </div>

            {/* ContainerLab-style device inventory beside the canvas (vendor
                research §b): same resolved view, bidirectional selection sync.
                The toggle lives in the TOOLBAR (not docked on the stage) — an
                overlay button at top-left collided with the search dock. */}
            {focusOn && groupedView && (
              <div className="topo-focus-banner">
                <span>
                  Focused — {focusSummary(groupedView.nodes.length, view.nodes.length, searchMatches.size)}
                </span>
                <button className="btn btn-xs" onClick={() => setFocusOn(false)}>
                  Show everything
                </button>
              </div>
            )}
            {/* Aggregated at scale: the canvas shows sites/regions (auto-collapsed)
                so the fabric is interactive. A hint + the escape hatches; drill in
                by expanding a group. */}
            {aggregateAtScale && !focusOn && (
              <div className="topo-focus-banner">
                <span>
                  {view.nodes.length.toLocaleString()} devices — showing {view.groups.length} groups. Expand a group to drill in.
                </span>
                <button className="btn btn-xs" onClick={() => setRenderer("overview")}>
                  WebGL overview
                </button>
              </div>
            )}
            {/* A group too large to expand inline (audit S10 drill-down guard):
                keep it collapsed, steer to the overview / search. */}
            {expandBlocked && (
              <div className="topo-focus-banner" role="status">
                <span>That group is too large to expand here.</span>
                <button className="btn btn-xs" onClick={() => { setExpandBlocked(null); setRenderer("overview"); }}>
                  WebGL overview
                </button>
                <button className="btn btn-xs" onClick={() => setExpandBlocked(null)}>
                  Dismiss
                </button>
              </div>
            )}
            {/* The flat device inventory is suppressed while aggregated at scale —
                a 2,500-row list is not the tool; use search to reach a device. */}
            {showInventory && !aggregateAtScale && (
              <TopologyInventoryPanel view={view} selection={selection} onPick={onPick} />
            )}

            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onEdgeClick={onEdgeClick}
              onPaneClick={onPaneClick}
              onNodeDragStop={onNodeDragStop}
              onMove={onMove}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onEdgeMouseEnter={onEdgeMouseEnter}
              onEdgeMouseLeave={onEdgeMouseLeave}
              minZoom={0.2}
              maxZoom={2.4}
              proOptions={{ hideAttribution: true }}
              fitView
            >
              <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="var(--border)" />
              <Controls showInteractive={false} />
            </ReactFlow>

            {/* Honest empty state — a mode that resolves no nodes (e.g. Dependency
                with no flow attribution, or a too-narrow window) must SAY so, never
                leave a silent blank canvas the operator can't read. */}
            {view && view.nodes.length === 0 && (() => {
              // Audit S2: BOTH sources carry a status discriminator now — a
              // failed read must never render as "you have no devices".
              const readFailed = source === "persisted" ? graphStatus === "error" : viewStatus === "error";
              return (
              <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
                <div style={{ maxWidth: 440, textAlign: "center", padding: "18px 22px", border: `1px dashed ${readFailed ? "var(--bad)" : "var(--border)"}`, borderRadius: 10, background: "var(--panel)", pointerEvents: "auto" }}
                  role={readFailed ? "alert" : undefined}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: readFailed ? "var(--bad)" : "var(--fg)", marginBottom: 6 }}>
                    {readFailed
                      ? "The topology could not be read"
                      : mode === "dependency" ? "No service dependencies in this window" : "Nothing to show for this view yet"}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--fg-muted)", lineHeight: 1.5 }}>
                    {readFailed
                      ? "The topology service did not answer, so the shape of your network is unknown — this is NOT an empty network. Retry, or check the topology service."
                      : mode === "dependency"
                        ? "Dependency edges appear when flows are attributed to services. Widen the time range, or confirm flow collection is active."
                        : "No nodes resolved for the current mode, data source and time range."}
                  </div>
                </div>
              </div>
              );
            })()}

            {/* Hover peek: WHY this node/edge is here (health/verdict + evidence),
                without a click into the drawer. Suppressed while a drawer is open. */}
            {hoverPos && (hoverNode || hoverEdge) && !(selection.nodeId || selection.edgeId || selection.groupId) && (
              <EvidencePopover view={view} nodeId={hoverNode} edgeId={hoverEdge} x={hoverPos.x} y={hoverPos.y} />
            )}

            <TopologyLegend overlay={overlay} showRca={mode === "investigate" && !!incidentOverlay} />

            {mode === "investigate" && incidentOverlay && (
              <div className="topo-rca-dock">
                <RcaVerdictBanner overlay={incidentOverlay} onClear={() => setIncidentId("")} />
              </div>
            )}

            {/* Investigate keeps the floating hop-ladder dock; path_trace's detail
                now lives inside the dedicated NetworkPathView (above). */}
            {mode === "investigate" && (
              <div className="topo-path-dock">
                <PathAnalysisPanel view={view} />
              </div>
            )}

            {mode === "capacity" && (
              <div className="topo-path-dock">
                <CapacityPanel view={view} />
              </div>
            )}

            {(selection.nodeId || selection.edgeId || selection.groupId) && (
              <TopologySideDrawer
                view={view}
                selection={selection}
                onClose={() => setSelection({})}
                collapsedGroups={collapsedGroups}
                onToggleGroup={onToggleGroup}
              />
            )}
          </>
        )}
      </div>
      )}
    </div>
  );
}

// Path Trace guided empty state. Without a source AND destination the backend has
// nothing to trace, so the canvas would otherwise fall back to the full topology —
// indistinguishable from Explore. This makes the mode's intent explicit and lets
// the operator pick both endpoints in one place; the path renders once both are set.
function PathTracePrompt({
  options,
  src,
  dst,
  onSrc,
  onDst,
}: {
  options: { id: string; label: string }[];
  src: string;
  dst: string;
  onSrc: (v: string) => void;
  onDst: (v: string) => void;
}) {
  return (
    <div className="topo-placeholder">
      <div className="topo-pathprompt-card">
        <div className="topo-pathprompt-icon" aria-hidden="true">
          <svg width={30} height={30} viewBox="0 0 24 24" fill="none">
            <circle cx={5} cy={12} r={2.4} fill="currentColor" />
            <circle cx={19} cy={12} r={2.4} fill="currentColor" />
            <path d="M7.4 12h9.2" stroke="currentColor" strokeWidth={1.6} strokeDasharray="2 2.4" strokeLinecap="round" />
            <path d="M13.6 9.2 16.6 12l-3 2.8" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <div className="topo-pathprompt-title">Trace a network path</div>
        <p className="topo-pathprompt-body">
          Choose a <strong>source</strong> and <strong>destination</strong> device — the path between them is resolved
          hop&#8209;by&#8209;hop over the discovered topology (LLDP / IGP), with the ingress&nbsp;/&nbsp;egress interface on each hop.
        </p>
        <div className="topo-pathprompt-row">
          <select value={src} onChange={(e) => onSrc(e.target.value)} aria-label="Path source device">
            <option value="">Source…</option>
            {options.map((o) => (
              <option key={o.id} value={o.id} disabled={o.id === dst}>
                {o.label}
              </option>
            ))}
          </select>
          <span className="topo-pathprompt-arrow" aria-hidden="true">→</span>
          <select value={dst} onChange={(e) => onDst(e.target.value)} aria-label="Path destination device">
            <option value="">Destination…</option>
            {options.map((o) => (
              <option key={o.id} value={o.id} disabled={o.id === src}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        {src && !dst && <div className="topo-pathprompt-hint">Now pick a destination to trace the path.</div>}
      </div>
    </div>
  );
}

// Shown while the A→B trace for the chosen endpoints is being resolved, so the stage
// doesn't briefly flash the full topology (an Explore look-alike) before the path lands.
function PathTraceResolving({ srcLabel, dstLabel }: { srcLabel: string; dstLabel: string }) {
  return (
    <div className="topo-placeholder">
      <div className="topo-pathprompt-card">
        <div className="topo-pathprompt-title">Resolving path…</div>
        <p className="topo-pathprompt-body">
          Tracing <strong>{srcLabel}</strong> → <strong>{dstLabel}</strong> over the discovered topology.
        </p>
      </div>
    </div>
  );
}

// Honest "no path" state: the trace resolved but no route exists between the endpoints
// over the discovered LLDP/IGP adjacency. We say so explicitly (and let the operator
// re-aim) instead of silently dropping back to the full graph, which read as Explore.
function PathTraceNoPath({
  srcLabel,
  dstLabel,
  options,
  src,
  dst,
  onSrc,
  onDst,
}: {
  srcLabel: string;
  dstLabel: string;
  options: { id: string; label: string }[];
  src: string;
  dst: string;
  onSrc: (v: string) => void;
  onDst: (v: string) => void;
}) {
  return (
    <div className="topo-placeholder">
      <div className="topo-pathprompt-card">
        <div className="topo-pathprompt-icon topo-pathprompt-icon-warn" aria-hidden="true">
          <svg width={30} height={30} viewBox="0 0 24 24" fill="none">
            <circle cx={5} cy={12} r={2.4} fill="currentColor" />
            <circle cx={19} cy={12} r={2.4} fill="currentColor" />
            <path d="M7.4 12h9.2" stroke="currentColor" strokeWidth={1.6} strokeDasharray="2 2.4" strokeLinecap="round" />
            <path d="m9.6 9.6 4.8 4.8M14.4 9.6l-4.8 4.8" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" />
          </svg>
        </div>
        <div className="topo-pathprompt-title">No path found</div>
        <p className="topo-pathprompt-body">
          No route between <strong>{srcLabel}</strong> and <strong>{dstLabel}</strong> over the discovered topology — the
          LLDP/IGP adjacency between them is incomplete or they sit in separate fabrics. Re-aim the trace, or widen
          discovery so the intervening hops are learned.
        </p>
        <div className="topo-pathprompt-row">
          <select value={src} onChange={(e) => onSrc(e.target.value)} aria-label="Path source device">
            <option value="">Source…</option>
            {options.map((o) => (
              <option key={o.id} value={o.id} disabled={o.id === dst}>
                {o.label}
              </option>
            ))}
          </select>
          <span className="topo-pathprompt-arrow" aria-hidden="true">→</span>
          <select value={dst} onChange={(e) => onDst(e.target.value)} aria-label="Path destination device">
            <option value="">Destination…</option>
            {options.map((o) => (
              <option key={o.id} value={o.id} disabled={o.id === src}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

function PlaceholderWorkflow({ label, blurb }: { label: string; blurb: string }) {
  return (
    <div className="topo-placeholder">
      <div className="topo-placeholder-card">
        <div className="topo-placeholder-eyebrow">Workflow · {label}</div>
        <div className="topo-placeholder-title">Prepared, not yet implemented</div>
        <p className="topo-placeholder-body">{blurb}</p>
        <p className="topo-placeholder-note">
          Phase 1 ships the React Flow + ELK operator canvas (Explore · Investigate · Path Trace · Dependency). The
          remaining workflows and the Sigma/cosmos &amp; MapLibre/deck renderers are scaffolded behind clean adapter
          boundaries.
        </p>
      </div>
    </div>
  );
}

export default function TopologyCanvas() {
  // Network domain (LAN · SD-WAN · DC · Cloud) — the primary "where am I looking"
  // control. It lives INSIDE the canvas toolbar (see CanvasInner) as the same
  // native segmented toggle as Data source / Renderer, so the cloud additions
  // read as one seamless canvas, not a bolted-on strip. LAN (default) +
  // carrier-off renders the existing canvas byte-for-byte unchanged.
  // Seeded from the route so a shared link opens on the domain it names (#133a);
  // CanvasInner reads the same value and owns the write-back.
  const [domain, setDomain] = useState<NetworkDomain>(
    () => readCanvasUrlState(typeof location !== "undefined" ? location.hash : "").domain ?? CANVAS_URL_DEFAULTS.domain,
  );
  const [carrier, setCarrier] = useState(false);
  return (
    <ReactFlowProvider>
      <CanvasInner domain={domain} carrier={carrier} onDomain={setDomain} onCarrier={setCarrier} />
    </ReactFlowProvider>
  );
}
