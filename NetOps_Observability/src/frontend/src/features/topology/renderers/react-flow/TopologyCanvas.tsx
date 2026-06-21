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
        if (alive) setIncidents(r.data ?? []);
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
        const v = await fetchTopologyView(mode);
        if (!alive) return;
        setFetched(v);
        setCoverage(null);
      }
    })();
    return () => {
      alive = false;
    };
  }, [mode, source, incidentId]);

  // Drop the pinned incident when leaving Investigate mode.
  useEffect(() => {
    if (mode !== "investigate") setIncidentId("");
  }, [mode]);

  const workflow = workflowById(mode);
  const view = fetched ?? workflow?.view;
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
  }, [mode]);

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
    });
  }, [view, positions, spotlight, selection, overlay, showAllLabels, searchMatches, mode, hoverEdge, collapsedGroups, onToggleGroup]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node<AnyNodeData>>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge<RFEdgeData>>([]);

  useEffect(() => {
    setRfNodes(derived.nodes);
    setRfEdges(derived.edges);
  }, [derived, setRfNodes, setRfEdges]);

  // Fit the view once a fresh layout lands.
  const fittedFor = useRef<string>("");
  useEffect(() => {
    if (laidOutKey && laidOutKey !== fittedFor.current && rfNodes.length) {
      fittedFor.current = laidOutKey;
      const t = setTimeout(() => rf.fitView({ padding: 0.2, duration: 320 }), 60);
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
  const workflowMeta = useMemo(
    () => WORKFLOWS.map((w) => ({ id: w.id, label: w.label, implemented: w.implemented, blurb: w.blurb })),
    [],
  );

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
          </label>
        )}
        {view && renderer === "canvas" && <OverlaySelector value={overlay} overlays={overlays} onChange={setOverlay} />}
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
