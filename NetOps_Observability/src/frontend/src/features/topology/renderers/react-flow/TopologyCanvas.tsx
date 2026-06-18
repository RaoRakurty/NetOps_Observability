// TopologyCanvas.tsx — the Phase-1 React Flow operator canvas. It is the ONLY
// renderer wired in Phase 1; it consumes a renderer-agnostic TopologyView, lays it
// out with ELK, and maps it through topologyToReactFlow. Sigma/geo adapters exist
// but are not mounted (prepared, not implemented).
//
// Performance discipline (PDF §13): selection/spotlight live in their OWN state,
// separate from the node/edge arrays; layout is computed in an effect (cached in
// elkLayout) — never recomputed on every render; the RF node/edge arrays are derived
// via useMemo and only rebuilt when the view, layout, or UI state actually change.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { OverlayKind, TopologySelection, WorkflowMode } from "../../api/topologyTypes";
import { layoutView } from "../../layout/elkLayout";
import type { LayoutResult } from "../../layout/layoutTypes";
import { topologyToReactFlow } from "./topologyToReactFlow";
import type { RFNodeData, RFEdgeData } from "./rfTypes";
import { nodeTypes } from "./nodes";
import { edgeTypes } from "./edges";
import { WORKFLOWS, workflowById } from "../../workflows";
import { EMPTY_SPOTLIGHT } from "../../workflows/workflowTypes";
import { availableOverlays } from "../../utils/topologyOverlays";
import { pathEdgeIds, firstDegree, edgesWithin } from "../../graph/graphAlgorithms";
import {
  TopologyToolbar,
  TopologySearch,
  TopologySideDrawer,
  TopologyLegend,
  TopologyMiniMap,
  OverlaySelector,
  MapWorkflowSelector,
  PathAnalysisPanel,
} from "../../components";

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
  // Hover state is transient and SEPARATE from click-selection: hover spotlights
  // first-degree neighbours (skill design-tokens) without opening the drawer.
  const [hoverNode, setHoverNode] = useState<string | undefined>();
  const [hoverEdge, setHoverEdge] = useState<string | undefined>();
  const [fullscreen, setFullscreen] = useState(false);

  const workflow = workflowById(mode);
  const view = workflow?.view;
  const showAllLabels = labelsToggle || density === "engineer";

  // (Re)compute ELK layout only when the active view changes. Cached in elkLayout.
  useEffect(() => {
    let alive = true;
    if (!view) {
      setPositions({});
      return;
    }
    layoutView(view).then((pos) => {
      if (alive) {
        setPositions(pos);
        setLaidOutKey(view.view_id);
      }
    });
    return () => {
      alive = false;
    };
  }, [view]);

  // Reset transient selection when the workflow changes.
  useEffect(() => {
    setSelection({});
    setSearchMatches(new Set());
    setHoverNode(undefined);
    setHoverEdge(undefined);
  }, [mode]);

  // Spotlight priority: a click-selection wins (and opens the drawer); else a hover
  // spotlights first-degree neighbours (no drawer); else the workflow's default
  // (Investigate/PathTrace pre-spotlight their RCA/trace path; Explore stays calm).
  const spotlight = useMemo(() => {
    if (!view) return EMPTY_SPOTLIGHT;
    if (selection.edgeId) {
      const e = view.edges.find((x) => x.id === selection.edgeId);
      return { nodes: new Set(e ? [e.source, e.target] : []), edges: new Set(e ? [e.id] : []) };
    }
    if (selection.nodeId && workflow?.computeSpotlight) return workflow.computeSpotlight(view, selection);
    if (hoverNode) {
      const nodes = firstDegree(view, hoverNode);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    if (workflow?.computeSpotlight) return workflow.computeSpotlight(view, {});
    return EMPTY_SPOTLIGHT;
  }, [view, workflow, selection, hoverNode]);

  // Derive React Flow nodes/edges. Pure, memoized on the inputs that matter.
  const derived = useMemo(() => {
    if (!view) return { nodes: [] as Node<RFNodeData>[], edges: [] as Edge<RFEdgeData>[] };
    const strongEdges = new Set<string>(spotlight.edges);
    if (selection.edgeId) strongEdges.add(selection.edgeId);
    if (hoverEdge) strongEdges.add(hoverEdge);
    if (view.path && (mode === "investigate" || mode === "path_trace")) {
      for (const id of pathEdgeIds(view, view.path)) strongEdges.add(id);
    }
    return topologyToReactFlow(view, positions, {
      selection,
      spotlight: spotlight.nodes,
      strongEdges,
      overlay,
      showAllLabels,
      searchMatches,
    });
  }, [view, positions, spotlight, selection, overlay, showAllLabels, searchMatches, mode, hoverEdge]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node<RFNodeData>>([]);
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
    setSelection({ nodeId: n.id });
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
      >
        <MapWorkflowSelector value={mode} onChange={setMode} workflows={workflowMeta} />
        {view && <OverlaySelector value={overlay} overlays={overlays} onChange={setOverlay} />}
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
        {!view ? (
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
              <TopologyMiniMap />
            </ReactFlow>

            <TopologyLegend overlay={overlay} />

            {(mode === "path_trace" || mode === "investigate") && (
              <div className="topo-path-dock">
                <PathAnalysisPanel view={view} />
              </div>
            )}

            {(selection.nodeId || selection.edgeId) && (
              <TopologySideDrawer view={view} selection={selection} onClose={() => setSelection({})} />
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
