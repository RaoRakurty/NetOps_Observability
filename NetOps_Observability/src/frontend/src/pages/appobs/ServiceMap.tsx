// ServiceMap.tsx — the OBSERVED cloud service dependency canvas (Wave 3 #9
// carried, tracker #110). Renders GET /api/cloud/service-map: volume-weighted
// talks_to edges from cloud flow-pair telemetry, REJECT evidence as a distinct
// blocked treatment, and unattributed endpoints styled honestly as what they
// are — observed addresses no inventory claims, never disguised as services.
//
// Rendering follows the platform's Phase-1 topology stack (topology-ui skill):
// React Flow (@xyflow/react) + a deterministic ELK layered layout — never a
// random force layout, never hardcoded positions, no all-labels-at-once (only
// blocked evidence is labeled on the canvas; everything else explains itself
// on click). The data layer is ./serviceMap.ts — React Flow types never leak
// into it, and its view model is the only thing rendered here.
//
// HONESTY LABELS (mandatory): the caption states the server-honored window,
// pair signals aggregated, resolved/unresolved endpoint counts, the
// unattributed truncation (top-N shown / dropped) and generated_at — all
// straight from meta. The empty state names the telemetry that lights the map
// up (cloud flow pairs), because nothing here is ever inferred.

import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { ELK as ElkInstance } from "elkjs/lib/elk-api";
import { Chip } from "../../components/noc";
import { Skeleton } from "../../components/ui";
import { fmtDateTime } from "../../lib/time";
import { EmptyState, ago } from "./badges";
import { rangeWords, windowHoursFor } from "./range";
import type { CloudScopeControl } from "./useCloudScope";
import { loadServiceMap } from "./api";
import { buildServiceMapView } from "./serviceMap";
import type { SvcMapEdge, SvcMapNode, SvcMapView } from "./serviceMap";

// ── deterministic layout (ELK layered, left→right) ───────────────────────────
// Local, tiny adapter: the features/topology elkLayout is typed to the network
// TopologyView contract — reusing it here would couple two domains for a few
// lines of ELK options (topology-ui: clean adapter boundaries per renderer).

// elkjs is ~1.6 MB — dynamic-import it on first layout so it never rides in
// the page chunk. Memoized: one in-flight/loaded instance per session.
let elkPromise: Promise<ElkInstance> | null = null;
function loadElk(): Promise<ElkInstance> {
  if (!elkPromise) {
    elkPromise = import("elkjs/lib/elk.bundled.js").then((m) => new m.default());
  }
  return elkPromise;
}
type Positions = Record<string, { x: number; y: number }>;

async function layoutServiceMap(nodes: SvcMapNode[], edges: SvcMapEdge[]): Promise<Positions> {
  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.layered.spacing.nodeNodeBetweenLayers": "110",
      "elk.spacing.nodeNode": "42",
      "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
    },
    children: nodes.map((n) => ({ id: n.id, width: n.width, height: n.height })),
    edges: edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };
  try {
    const elk = await loadElk();
    const laid = await elk.layout(graph);
    const out: Positions = {};
    for (const c of laid.children ?? []) out[c.id] = { x: c.x ?? 0, y: c.y ?? 0 };
    if (Object.keys(out).length === nodes.length) return out;
  } catch { /* fall through to the calm grid — never blank the canvas */ }
  const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
  const out: Positions = {};
  nodes.forEach((n, i) => {
    out[n.id] = { x: (i % cols) * 260, y: Math.floor(i / cols) * 110 };
  });
  return out;
}

// ── node renderer ────────────────────────────────────────────────────────────
// Services carry a solid identity card; unattributed endpoints render dashed +
// muted with an explicit "unattributed" tag — honest, never service-shaped.

function SvcMapRFNode({ data }: NodeProps) {
  const d = data as unknown as SvcMapNode;
  const endpoint = d.kind === "endpoint";
  return (
    <div
      className={`ao-svcmap-node${endpoint ? " ao-svcmap-node--endpoint" : ""}`}
      style={{ width: d.width, height: d.height }}
      title={endpoint
        ? `${d.label} — observed endpoint no inventory or identity map claims`
        : `${d.label} — resolved service`}
    >
      <Handle type="target" position={Position.Left} className="ao-svcmap-handle" />
      <div className="ao-svcmap-node-l">{d.label}</div>
      <div className="ao-svcmap-node-s">
        {endpoint && <span className="ao-unknown">unattributed · </span>}
        {d.bytesText}
        {d.providers.length > 0 && ` · ${d.providers.map((p) => p.toUpperCase()).join(" + ")}`}
      </div>
      <Handle type="source" position={Position.Right} className="ao-svcmap-handle" />
    </div>
  );
}

const nodeTypes = { svcmap: SvcMapRFNode };

// stroke-weight px per volume bucket (accepted bytes only — serviceMap.ts).
const EDGE_WIDTH: Record<1 | 2 | 3 | 4, number> = { 1: 1.2, 2: 2, 3: 3, 4: 4.2 };

// ── explain strip (every edge/node explainable on click) ─────────────────────

type Inspect = { kind: "node"; node: SvcMapNode } | { kind: "edge"; edge: SvcMapEdge };

function ExplainStrip({ inspect, view, onClose }: {
  inspect: Inspect; view: SvcMapView; onClose: () => void;
}) {
  const cell = (k: string, v: string) => (
    <span className="ao-svcmap-cell">
      <span className="ao-svcmap-cell-k">{k}</span>
      <strong>{v}</strong>
    </span>
  );
  const providers = (p: string[]) => (p.length ? p.map((x) => x.toUpperCase()).join(" + ") : "—");
  if (inspect.kind === "node") {
    const n = inspect.node;
    return (
      <div className="ao-svcmap-strip" role="region" aria-label="Selection detail">
        <b>{n.label}</b>
        {n.kind === "service"
          ? cell("kind", "service (resolved)")
          : cell("kind", "unattributed endpoint — no inventory / identity-map claim")}
        {cell("observed bytes", n.bytesText)}
        {cell("clouds", providers(n.providers))}
        <button className="ao-svcmap-strip-x" onClick={onClose} aria-label="Close detail">×</button>
      </div>
    );
  }
  const e = inspect.edge;
  const label = (id: string) => view.nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <div className="ao-svcmap-strip" role="region" aria-label="Selection detail">
      <b>{label(e.source)} → {label(e.target)}</b>
      {cell("relationship", `${e.relationship} (observed traffic)`)}
      {cell("accepted bytes", e.bytesText)}
      {cell("address pairs", e.pairCount.toLocaleString())}
      {cell("clouds", providers(e.providers))}
      {e.blocked && (
        <span className="ao-svcmap-blocked-note">
          ⊘ security rules rejected traffic {e.blockedCount.toLocaleString()}× in the window
          (observed REJECTs — counts, never bytes)
        </span>
      )}
      <button className="ao-svcmap-strip-x" onClick={onClose} aria-label="Close detail">×</button>
    </div>
  );
}

// ── the view ─────────────────────────────────────────────────────────────────

export default function ServiceMap({ ctl }: { ctl: CloudScopeControl }) {
  const windowHours = windowHoursFor(ctl.scope.rangeMinutes);
  const [view, setView] = useState<SvcMapView | null>(null);
  const [status, setStatus] = useState<"loading" | "error" | "ready">("loading");
  const [positions, setPositions] = useState<Positions | null>(null);
  const [inspect, setInspect] = useState<Inspect | null>(null);

  useEffect(() => {
    let live = true;
    setStatus("loading");
    setPositions(null);
    setInspect(null);
    loadServiceMap(windowHours).then(
      (wire) => { if (live) { setView(buildServiceMapView(wire)); setStatus("ready"); } },
      () => { if (live) setStatus("error"); },
    );
    return () => { live = false; };
  }, [windowHours]);

  // Layout runs once per loaded graph (deterministic; cached by React state —
  // never recomputed per render, never a force simulation).
  useEffect(() => {
    if (!view || view.empty) return;
    let live = true;
    layoutServiceMap(view.nodes, view.edges).then((pos) => { if (live) setPositions(pos); });
    return () => { live = false; };
  }, [view]);

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!view || !positions) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] };
    const rfNodes: Node[] = view.nodes.map((n) => ({
      id: n.id, type: "svcmap",
      position: positions[n.id] ?? { x: 0, y: 0 },
      data: n as unknown as Record<string, unknown>,
      draggable: true,
    }));
    const rfEdges: Edge[] = view.edges.map((e) => {
      const color = e.blocked ? "var(--crit)" : "var(--accent)";
      return {
        id: e.id, source: e.source, target: e.target,
        // Blocked evidence is the ONE always-on canvas label (it is evidence,
        // not decoration); volume/pairs/providers explain themselves on click.
        label: e.blocked ? `⊘ ${e.blockedCount.toLocaleString()}` : undefined,
        labelStyle: { fill: "var(--crit)", fontWeight: 800, fontSize: 11 },
        labelBgStyle: { fill: "var(--panel)", fillOpacity: 0.9 },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        style: {
          stroke: color,
          strokeWidth: EDGE_WIDTH[e.weight],
          strokeDasharray: e.blocked ? "7 5" : undefined,
          opacity: 0.85,
        },
        interactionWidth: 18,
      };
    });
    return { rfNodes, rfEdges };
  }, [view, positions]);

  if (status === "loading") {
    return (
      <div className="ao-panel">
        <Skeleton w={220} h={14} />
        <div style={{ marginTop: 12 }}><Skeleton h={420} /></div>
      </div>
    );
  }
  if (status === "error" || !view) {
    return (
      <div className="ao-panel">
        <EmptyState title="Unable to load the service map"
          hint="the /api/cloud/service-map read failed — retry, or check the cloud data sources" />
      </div>
    );
  }

  const l = view.labels;
  if (view.empty) {
    return (
      <div className="ao-panel">
        <EmptyState
          title={`No observed service traffic in the ${rangeWords(windowHours * 60)}`}
          hint="this map draws ONLY observed cloud flow pairs (AWS VPC Flow Logs · Azure NSG flow logs · GCP VPC flows) — connect cloud flow telemetry in Data sources and dependencies appear here as they are observed; nothing is inferred from co-location or timing"
          action={
            <button className="ao-btn ao-btn--primary"
              onClick={() => { location.hash = "#/operations/services/datasources"; }}>
              Open Data sources
            </button>
          } />
      </div>
    );
  }

  return (
    <div className="ao-stack">
      {/* mandatory honesty caption — meta verbatim, never re-counted client-side */}
      <div className="ao-svcmap-cap" role="note" aria-label="Service map provenance">
        <Chip label="observed traffic" tone="var(--good)" />
        <span>{l.window}</span>
        <span>·</span>
        <span>{l.signals}</span>
        <span>·</span>
        <span>{l.endpoints}</span>
        {l.truncation && <><span>·</span><span>{l.truncation}</span></>}
        {l.generatedAt && (
          <>
            <span>·</span>
            <span title={fmtDateTime(l.generatedAt)}>generated {ago(l.generatedAt)}</span>
          </>
        )}
        {ctl.active && (
          <span className="ao-svcmap-tenantwide"
            title="Scope filters do not narrow this map yet — it is drawn for the whole tenant over the selected time window.">
            tenant-wide · scope filters not applied
          </span>
        )}
      </div>

      <div className="ao-svcmap-stage">
        <ReactFlow
          nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes}
          fitView fitViewOptions={{ padding: 0.25, maxZoom: 1.15 }}
          proOptions={{ hideAttribution: true }}
          nodesConnectable={false} elementsSelectable nodesDraggable panOnDrag
          minZoom={0.25} maxZoom={2} zoomOnScroll={false} preventScrolling={false}
          onNodeClick={(_, n) => {
            const node = view.nodes.find((x) => x.id === n.id);
            if (node) setInspect({ kind: "node", node });
          }}
          onEdgeClick={(_, ed) => {
            const edge = view.edges.find((x) => x.id === ed.id);
            if (edge) setInspect({ kind: "edge", edge });
          }}
          onPaneClick={() => setInspect(null)}
        >
          <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="var(--border)" />
          <Controls showInteractive={false} position="bottom-right" />
        </ReactFlow>
        {inspect && <ExplainStrip inspect={inspect} view={view} onClose={() => setInspect(null)} />}
      </div>

      {/* legend — what the marks mean, in the map's own honest words */}
      <div className="ao-svcmap-legend" aria-label="Service map legend">
        <span><i className="ao-svcmap-key ao-svcmap-key--svc" /> service (resolved)</span>
        <span><i className="ao-svcmap-key ao-svcmap-key--ep" /> unattributed endpoint</span>
        <span><i className="ao-svcmap-key ao-svcmap-key--talks" /> talks to · width = observed bytes</span>
        <span><i className="ao-svcmap-key ao-svcmap-key--blocked" /> ⊘ blocked · observed REJECT count</span>
      </div>
    </div>
  );
}
