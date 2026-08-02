// CloudTopologyView.tsx — the CLOUD tab renderer.
//
// A self-contained cloud NETWORK canvas (VPC/VNet → subnets → gateways/NVAs →
// route-egress + hybrid seams + transit), rendered with the OFFICIAL provider
// marks. It reuses the shared pipeline (ELK layoutView → topologyToReactFlow →
// TopologySideDrawer / TopologyLegend) but mounts its OWN nodeTypes registry
// (cloudNodeTypes: cloudNode → CloudResourceNode) so the default LAN canvas and
// every other view are untouched.
//
// Data: GET /api/topology/cloud — the REAL in-cloud network (VPC/VNet → subnets →
// route-table egress → gateways/NVAs), discovered from the provider APIs and mapped
// server-side to this same TopologyView contract. HONESTY (2026-07 product review):
// when the API returns nothing (no connected cloud account / a tenant that owns no
// discovered network / discovery off) or errors, the tab renders an honest empty /
// error state with the next action — NEVER a fabricated sample network presented as
// the operator's own (the old mock fallback is gone). An explicit `view` prop still
// wins (tests / embedding). The carrier overlay is a pure view transform toggled by
// the parent tab bar.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  BackgroundVariant,
  useReactFlow,
  useNodesState,
  type OnNodeDrag,
  type Node,
  type Edge,
  type NodeMouseHandler,
  type EdgeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { TopologyView, TopologySelection } from "../../api/topologyTypes";
import type { LayoutResult } from "../../layout/layoutTypes";
import { layoutView } from "../../layout/elkLayout";
import { topologyToReactFlow } from "./topologyToReactFlow";
import type { RFNodeData, RFEdgeData, RFGroupData } from "./rfTypes";
import { cloudNodeTypes } from "./nodes";
import { edgeTypes } from "./edges";
import { TopologySideDrawer, TopologyLegend } from "../../components";
import { fetchCloudTopology, type CloudTopologyStatus } from "../../api/topologyApi";
import { withCarrierOverlay } from "../../utils/carrierOverlay";

type AnyNodeData = RFNodeData | RFGroupData;

// Fit insets in PIXELS, not the old `padding: 0.2`. A relative padding spends 20%
// of BOTH axes on empty margin — on a 1224px-wide stage that is ~490px of nothing,
// and the map shrinks to match. Fixed insets keep the same breathing room at any
// window size and hand the rest to the network. The bigger bottom inset is the
// docked legend + zoom controls, which sit ON the canvas (the LAN canvas does the
// same thing in fitPadding()).
const CLOUD_FIT_PADDING = { top: "24px", right: "24px", bottom: "56px", left: "24px" } as const;

// A well-formed zero-node view: what the canvas holds while loading and when the
// tenant owns no discovered cloud network. Rendering nothing honest beats
// rendering a fabricated sample network.
const EMPTY_CLOUD_VIEW: TopologyView = {
  view_id: "cloud-network-empty",
  mode: "explore",
  scope: { tenant_id: "" },
  layout_type: "cloud_grouped",
  generated_at: "",
  nodes: [],
  edges: [],
  groups: [],
  overlays: ["health"],
} as unknown as TopologyView;

// Honest non-live states for the Cloud tab (loading / nothing discovered / read
// failed) — plain ds-token styling, one next action, no fake canvas.
function CloudTopologyState({ status }: { status: "loading" | "empty" | "error" }) {
  const copy = {
    loading: {
      title: "Loading the cloud network…",
      hint: "reading the discovered VPC/VNet → subnet → gateway topology",
    },
    empty: {
      title: "No cloud network discovered yet",
      hint: "connect an AWS / Azure / GCP account and enable discovery — the VPC/VNet → subnet → route-table → gateway graph appears here as it is discovered",
    },
    error: {
      title: "Unable to load the cloud network",
      hint: "the topology read failed — retry, or check the cloud data sources",
    },
  }[status];
  return (
    <div className="topo-stage" style={{ display: "grid", placeItems: "center" }}>
      <div style={{ maxWidth: 460, textAlign: "center", padding: 24 }}>
        <div style={{ fontWeight: 600, color: "var(--fg)", marginBottom: 6 }}>{copy.title}</div>
        <div style={{ fontSize: 12.5, color: "var(--fg-subtle)", lineHeight: 1.5 }}>{copy.hint}</div>
        {status !== "loading" && (
          <button
            className="ao-btn ao-btn--primary"
            style={{ marginTop: 14 }}
            onClick={() => { location.hash = "#/monitoring/appobs/datasources"; }}
          >
            Open Data sources
          </button>
        )}
      </div>
    </div>
  );
}

export default function CloudTopologyView({
  view: viewProp,
  carrier = false,
}: {
  /** The cloud-network view to render (default: fetched live from /api/topology/cloud). */
  view?: TopologyView;
  /** Attach the shared carrier/transport overlay. */
  carrier?: boolean;
}) {
  const rf = useReactFlow();

  // Real cloud topology from GET /api/topology/cloud. Until it resolves the tab
  // shows a loading state; nothing discovered / a failed read renders the honest
  // empty / error card below — never a fabricated sample network. An explicit
  // `view` prop always wins and skips the fetch (tests / embedding).
  const [fetched, setFetched] = useState<TopologyView | null>(null);
  const [status, setStatus] = useState<CloudTopologyStatus | "loading">(viewProp ? "live" : "loading");
  useEffect(() => {
    if (viewProp) return;
    let alive = true;
    fetchCloudTopology().then(({ view, status: st }) => {
      if (!alive) return;
      setFetched(view);
      setStatus(st);
    });
    return () => {
      alive = false;
    };
  }, [viewProp]);

  const base = viewProp ?? fetched ?? EMPTY_CLOUD_VIEW;
  // Carrier is a pure, memoized view transform — no effect on the base data.
  const view = useMemo(() => (carrier ? withCarrierOverlay(base) : base), [base, carrier]);

  const [selection, setSelection] = useState<TopologySelection>({});
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [positions, setPositions] = useState<LayoutResult>({});
  const [laidOut, setLaidOut] = useState<string>("");

  const layoutKey = `${view.view_id}:${view.layout_type}:${view.nodes.length}`;

  useEffect(() => {
    let alive = true;
    layoutView(view).then((pos) => {
      if (!alive) return;
      setPositions(pos);
      setLaidOut(layoutKey);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutKey]);

  const onToggleGroup = useCallback((groupId: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  }, []);

  // Spotlight the selected node + its direct neighbours (calm by default).
  const spotlight = useMemo(() => {
    if (!selection.nodeId) return new Set<string>();
    const s = new Set<string>([selection.nodeId]);
    for (const e of view.edges) {
      if (e.source === selection.nodeId) s.add(e.target);
      if (e.target === selection.nodeId) s.add(e.source);
    }
    return s;
  }, [selection.nodeId, view.edges]);

  const derived = useMemo(
    () =>
      topologyToReactFlow(view, positions, {
        selection,
        spotlight,
        spotlightSoft: false,
        strongEdges: new Set(),
        overlay: "health",
        showAllLabels: false,
        searchMatches: new Set(),
        collapsedGroups,
        onToggleGroup,
        density: "operator",
      }),
    [view, positions, selection, spotlight, collapsedGroups, onToggleGroup],
  );

  // DRAGGABLE NODES. React Flow only persists a drag if the position change is
  // applied to state — this view rendered `derived.nodes` straight from a memo,
  // so every drag was discarded on the next render and nodes appeared frozen.
  //
  // Operator-moved positions are kept in `moved` and survive re-derives (a 30s
  // refetch must not shove a hand-arranged canvas back to the ELK layout), but
  // are dropped when the LAYOUT identity changes, because coordinates from a
  // different topology are meaningless.
  const [moved, setMoved] = useState<Record<string, { x: number; y: number }>>({});
  useEffect(() => setMoved({}), [layoutKey]);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node<AnyNodeData>>([]);
  useEffect(() => {
    setRfNodes(
      (derived.nodes as Node<AnyNodeData>[]).map((n) =>
        moved[n.id] ? { ...n, position: moved[n.id] } : n,
      ),
    );
  }, [derived.nodes, moved, setRfNodes]);
  const onNodeDragStop = useCallback<OnNodeDrag>((_e, n) => {
    setMoved((m) => ({ ...m, [n.id]: { x: n.position.x, y: n.position.y } }));
  }, []);

  const fittedFor = useRef<string>("");
  useEffect(() => {
    if (laidOut && laidOut !== fittedFor.current && derived.nodes.length) {
      fittedFor.current = laidOut;
      const t = setTimeout(() => rf.fitView({ padding: CLOUD_FIT_PADDING, duration: 320, maxZoom: 1.2 }), 60);
      return () => clearTimeout(t);
    }
  }, [laidOut, derived.nodes.length, rf]);

  const onNodeClick = useCallback<NodeMouseHandler>((_e, n) => {
    if (n.type === "groupNode") setSelection({ groupId: n.id });
    else setSelection({ nodeId: n.id });
  }, []);
  const onEdgeClick = useCallback<EdgeMouseHandler>((_e, ed) => setSelection({ edgeId: ed.id }), []);
  const onPaneClick = useCallback(() => setSelection({}), []);

  // Honest non-live states (after every hook, so hook order is stable): while
  // loading, and when nothing real is available, the canvas is replaced by the
  // state card — never a fabricated sample network.
  if (!viewProp && status !== "live") {
    return <CloudTopologyState status={status} />;
  }

  return (
    <div className="topo-stage">
      <ReactFlow
        nodes={rfNodes}
        edges={derived.edges as Edge<RFEdgeData>[]}
        onNodesChange={onNodesChange}
        onNodeDragStop={onNodeDragStop}
        nodesDraggable
        nodeTypes={cloudNodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onPaneClick={onPaneClick}
        minZoom={0.2}
        maxZoom={2.4}
        proOptions={{ hideAttribution: true }}
        fitView
      >
        <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="var(--border)" />
        <Controls showInteractive={false} />
      </ReactFlow>

      <TopologyLegend overlay="health" />

      {(selection.nodeId || selection.edgeId || selection.groupId) && (
        <TopologySideDrawer
          view={view}
          selection={selection}
          onClose={() => setSelection({})}
          collapsedGroups={collapsedGroups}
          onToggleGroup={onToggleGroup}
        />
      )}
    </div>
  );
}
