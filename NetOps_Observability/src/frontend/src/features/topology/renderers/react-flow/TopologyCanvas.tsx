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
import "@xyflow/react/dist/style.css";

import type { OverlayKind, TopologySelection, WorkflowMode, TopologyView } from "../../api/topologyTypes";
import { fetchTopologyView, fetchTopologyGraph, fetchRcaPathView, type TopologyCoverage } from "../../api/topologyApi";
import { api, type CorrObject } from "../../../../services/api";
import { layoutView } from "../../layout/elkLayout";
import type { LayoutResult } from "../../layout/layoutTypes";
import { loadSavedLayout, saveNodePosition, clearSavedLayout } from "../../layout/savedLayoutStore";
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
import { excludeInternalNodes } from "../../utils/topologyFilters";
import { pathEdgeIds, firstDegree, edgesWithin } from "../../graph/graphAlgorithms";
import {
  TopologyToolbar,
  TopologySearch,
  TopologySideDrawer,
  TopologyLegend,
  OverlaySelector,
  MapWorkflowSelector,
  PathAnalysisPanel,
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

function CanvasInner() {
  const rf = useReactFlow();

  const [mode, setMode] = useState<WorkflowMode>("explore");
  const [overlay, setOverlay] = useState<OverlayKind>("health");
  const [selection, setSelection] = useState<TopologySelection>({});
  const [searchMatches, setSearchMatches] = useState<Set<string>>(new Set());
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
  const [fullscreen, setFullscreen] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  // Renderer toggle: the scoped React Flow canvas (default) vs. the WebGL
  // enterprise overview (Phase 4) vs. the geographic / WAN map (Phase 5).
  // Orthogonal to the workflow mode.
  const [renderer, setRenderer] = useState<"canvas" | "overview" | "geo">("canvas");
  // Group-by lens for the canvas (site default = the backend's own grouping).
  const [groupBy, setGroupBy] = useState<GroupDimension>("site");

  // Data source: "live" = the per-mode projection (GET /api/topology/view); other
  // value "persisted" = the reconciler-maintained graph with stable ids + stale +
  // coverage (GET /api/topology/graph, #77). The fetched view overrides the
  // workflow's bundled sample; on an empty/errored fetch the fetcher returns the
  // mock so the canvas never blanks.
  const [source, setSource] = useState<"live" | "persisted">("live");
  const [fetched, setFetched] = useState<TopologyView | null>(null);
  const [coverage, setCoverage] = useState<TopologyCoverage | null>(null);
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
          return;
        }
      }
      setIncidentOverlay(null); // no pinned incident (or path unavailable) → no banner
      if (source === "persisted") {
        const r = await fetchTopologyGraph();
        if (!alive) return;
        setFetched(r.view);
        setCoverage(r.coverage ?? null);
      } else {
        const v = await fetchTopologyView(mode, mode === "path_trace" ? { src: pathSrc, dst: pathDst } : undefined);
        if (!alive) return;
        setFetched(v);
        setCoverage(null);
        // Record what this view resolved for, so the stage can distinguish a resolved
        // empty path (no route) from one still in flight.
        setTracedKey(mode === "path_trace" && pathSrc && pathDst ? `${pathSrc}>${pathDst}` : "");
      }
    })();
    return () => {
      alive = false;
    };
  }, [mode, source, incidentId, pathSrc, pathDst]);

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
    const v = fetched ?? workflow?.view;
    return v ? excludeInternalNodes(v) : v;
  }, [fetched, workflow?.view]);
  // Tag-dimension regrouping: re-bucket the canvas by site/role/vendor/owner (or none)
  // — the operator's lens, not just the backend's fixed site hierarchy.
  const view = useMemo(() => (baseView ? regroupView(baseView, groupBy) : baseView), [baseView, groupBy]);
  // Group ids change with the lens, so any collapse state from the old grouping is
  // stale — clear it when the lens changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setCollapsedGroups(new Set()), [groupBy]);
  const showAllLabels = labelsToggle || density === "engineer";
  // saved-layout key: invalidated when the view, layout type, or node cardinality
  // (a proxy for topology generation) changes.
  const layoutKey = view ? `${view.view_id}:${view.layout_type}:${view.nodes.length}` : "";

  // (Re)compute ELK layout only when the active view changes. Cached in elkLayout.
  useEffect(() => {
    let alive = true;
    if (!view) {
      setPositions({});
      return;
    }
    layoutView(view).then((pos) => {
      if (!alive) return;
      elkPositions.current = pos;
      // operator pins override ELK for the nodes they cover (skill §3).
      const saved = loadSavedLayout(layoutKey);
      const pinCount = Object.keys(saved).length;
      setLayoutPinned(pinCount > 0);
      setPositions(pinCount > 0 ? { ...pos, ...saved } : pos);
      setLaidOutKey(view.view_id);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, layoutKey]);

  // Persist a dragged node and keep it pinned for this session.
  const onNodeDragStop = useCallback<OnNodeDrag<Node<AnyNodeData>>>(
    (_e, n) => {
      if (!layoutKey) return;
      saveNodePosition(layoutKey, n.id, n.position);
      setPositions((p) => ({ ...p, [n.id]: n.position }));
      setLayoutPinned(true);
    },
    [layoutKey],
  );

  const onResetLayout = useCallback(() => {
    if (layoutKey) clearSavedLayout(layoutKey);
    setPositions({ ...elkPositions.current });
    setLayoutPinned(false);
    setTimeout(() => rf.fitView({ padding: 0.2, duration: 300 }), 40);
  }, [layoutKey, rf]);

  // Reset transient selection when the workflow changes. Capacity opens on the
  // utilization overlay (its whole point); other modes default to health.
  useEffect(() => {
    setSelection({});
    setSearchMatches(new Set());
    setHoverNode(undefined);
    setHoverEdge(undefined);
    setCollapsedGroups(new Set());
    setOverlay(mode === "capacity" ? "utilization" : "health");
    setPathSrc("");
    setPathDst("");
    setTracedKey("");
  }, [mode]);

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
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  }, []);

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
    if (!view) return { nodes: [] as Node<AnyNodeData>[], edges: [] as Edge<RFEdgeData>[] };
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
    });
  }, [view, positions, spotlight, selection, overlay, showAllLabels, searchMatches, mode, hoverEdge, collapsedGroups, onToggleGroup, density]);

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
      const t = setTimeout(() => rf.fitView({ padding: 0.2, duration: 320, maxZoom: 1.15 }), 60);
      return () => clearTimeout(t);
    }
  }, [laidOutKey, rfNodes.length, rf]);

  // Fullscreen: toggle a class on the root and re-fit; Escape exits.
  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.2, duration: 260 }), 80);
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
  const onNodeMouseEnter = useCallback<NodeMouseHandler>((_e, n) => setHoverNode(n.id), []);
  const onNodeMouseLeave = useCallback(() => setHoverNode(undefined), []);
  const onEdgeMouseEnter = useCallback<EdgeMouseHandler>((_e, ed) => setHoverEdge(ed.id), []);
  const onEdgeMouseLeave = useCallback(() => setHoverEdge(undefined), []);

  const onPick = useCallback(
    (nodeId: string) => {
      setSelection({ nodeId });
      const p = positions[nodeId];
      if (p) rf.setCenter(p.x + 100, p.y + 44, { zoom: 1.1, duration: 400 });
    },
    [positions, rf],
  );

  const overlays = useMemo(() => (view ? availableOverlays(view) : []), [view]);
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
        onFit={() => rf.fitView({ padding: 0.2, duration: 320 })}
        onZoomIn={() => rf.zoomIn({ duration: 200 })}
        onZoomOut={() => rf.zoomOut({ duration: 200 })}
        showAllLabels={showAllLabels}
        onToggleLabels={() => setLabelsToggle((v) => !v)}
        density={density}
        onDensityChange={setDensity}
        onResetLayout={onResetLayout}
        layoutPinned={layoutPinned}
      >
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
          <label className="topo-incident-picker" title="Regroup the canvas by a node dimension">
            <span className="topo-incident-picker-label">Group</span>
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupDimension)} aria-label="Group the canvas by">
              {GROUP_DIMENSIONS.map((d) => (
                <option key={d.id} value={d.id}>{d.label}</option>
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
          <Suspense fallback={<div className="topo-sigma-loading">Loading enterprise overview…</div>}>
            <SigmaTopologyView view={enterpriseScaleTopology} />
          </Suspense>
        ) : renderer === "geo" ? (
          <Suspense fallback={<div className="topo-geo-loading">Loading geographic map…</div>}>
            <GeoTopologyMap view={geoWanTopology} />
          </Suspense>
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
        ) : (
          <>
            <div className="topo-search-dock">
              <TopologySearch view={view} onMatches={setSearchMatches} onPick={onPick} />
            </div>

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

            <TopologyLegend overlay={overlay} showRca={mode === "investigate" && !!incidentOverlay} />

            {mode === "investigate" && incidentOverlay && (
              <div className="topo-rca-dock">
                <RcaVerdictBanner overlay={incidentOverlay} onClear={() => setIncidentId("")} />
              </div>
            )}

            {(mode === "path_trace" || mode === "investigate") && (
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
  return (
    <ReactFlowProvider>
      <CanvasInner />
    </ReactFlowProvider>
  );
}
