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
// server-side to this same TopologyView contract. Graceful degradation: when the API
// returns nothing (no fixtures / a tenant that doesn't own them / discovery off) or
// errors, it falls back to the grounded `cloudNetworkTopology` mock so the tab is
// never blank in dev (see fetchCloudTopology). An explicit `view` prop still wins
// (tests / embedding). The carrier overlay is a pure view transform toggled by the
// parent tab bar.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  BackgroundVariant,
  useReactFlow,
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
import { cloudNetworkTopology } from "../../mock/cloudNetworkTopology";
import { fetchCloudTopology } from "../../api/topologyApi";
import { withCarrierOverlay } from "../../utils/carrierOverlay";

type AnyNodeData = RFNodeData | RFGroupData;

export default function CloudTopologyView({
  view: viewProp,
  carrier = false,
}: {
  /** The cloud-network view to render (defaults to the grounded mock). */
  view?: TopologyView;
  /** Attach the shared carrier/transport overlay. */
  carrier?: boolean;
}) {
  const rf = useReactFlow();

  // Real cloud topology from GET /api/topology/cloud, with the grounded mock as
  // the fallback until it resolves (and if it returns nothing/errors). An explicit
  // `view` prop always wins and skips the fetch (tests / embedding).
  const [fetched, setFetched] = useState<TopologyView | null>(null);
  useEffect(() => {
    if (viewProp) return;
    let alive = true;
    fetchCloudTopology().then(({ view }) => {
      if (alive) setFetched(view);
    });
    return () => {
      alive = false;
    };
  }, [viewProp]);

  const base = viewProp ?? fetched ?? cloudNetworkTopology;
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

  const fittedFor = useRef<string>("");
  useEffect(() => {
    if (laidOut && laidOut !== fittedFor.current && derived.nodes.length) {
      fittedFor.current = laidOut;
      const t = setTimeout(() => rf.fitView({ padding: 0.2, duration: 320, maxZoom: 1.2 }), 60);
      return () => clearTimeout(t);
    }
  }, [laidOut, derived.nodes.length, rf]);

  const onNodeClick = useCallback<NodeMouseHandler>((_e, n) => {
    if (n.type === "groupNode") setSelection({ groupId: n.id });
    else setSelection({ nodeId: n.id });
  }, []);
  const onEdgeClick = useCallback<EdgeMouseHandler>((_e, ed) => setSelection({ edgeId: ed.id }), []);
  const onPaneClick = useCallback(() => setSelection({}), []);

  return (
    <div className="topo-stage">
      <ReactFlow
        nodes={derived.nodes as Node<AnyNodeData>[]}
        edges={derived.edges as Edge<RFEdgeData>[]}
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
