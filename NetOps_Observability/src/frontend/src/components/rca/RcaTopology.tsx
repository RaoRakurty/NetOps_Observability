import { useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CorrTimeline, CorrSignal, Seam, ProbePath } from "../../services/api";
import { C, entityLabel, isInternalEntity, isRoutingKind, mentionsInternal } from "./labels";
import { ShapeSVG } from "../graph/shapes";
import FlowEdge from "../graph/FlowEdge";
import { buildTopoGraph, computeTopoModel, STATUS_META, statusForVerdict, methodTag, type EdgeState } from "./topoGraph";

// RcaTopology — the END-TO-END path with the fault marked, drawn with real
// network shapes (vantage / router / switch / firewall / gateway / cloud /
// target), health colour + glow, and animated traffic-flow links. OVERLAY MODEL:
// the path STRUCTURE comes from data — a live traceroute when one matches the
// destination (true hop order, both icmp+tcp), else the correlation object's own
// entities — and RCA ANNOTATES where it's broken / suspected / possible. We never
// invent a hop order we can't prove.
//
// The graph itself (nodes/edges/layout) is built by the SHARED, renderer-agnostic
// `buildTopoGraph` (topoGraph.ts) so the PDF export draws the SAME graph; this
// component only maps that output onto the React-Flow canvas + the live overlays
// (legend, STAMP toggle, empty/internal states).

const handleStyle = { width: 7, height: 7, background: "var(--border,#3a4252)", border: "none" } as const;

// ── one shape-based node for every role ────────────────────────────────────
// data: { kind, tone, label, sub, badge, chips[], via, pulse, mono, size,
//          hasIn, hasOut, hasBottom }
function TopoNode({ data }: NodeProps) {
  const d = data as any;
  const size = d.size ?? 56;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: d.width ?? 124, gap: 2 }}>
      {/* handles sit on the SHAPE's vertical center (not the whole node, whose
          label rows would otherwise pull the anchor down → crooked edges). */}
      <div style={{ position: "relative", width: size, height: size, display: "flex", alignItems: "center", justifyContent: "center" }}>
        {d.hasIn !== false && <Handle type="target" position={Position.Left} style={{ ...handleStyle, top: "50%" }} />}
        <ShapeSVG kind={d.kind} tone={d.tone} size={size} pulse={d.pulse} />
        {d.hasOut !== false && <Handle type="source" position={Position.Right} style={{ ...handleStyle, top: "50%" }} />}
        {d.hasBottom && <Handle type="source" position={Position.Bottom} id="b" style={{ ...handleStyle, left: "50%" }} />}
      </div>
      <div style={{ fontWeight: 700, fontSize: 12, color: "var(--fg,#e6edf3)", textAlign: "center", lineHeight: 1.2, fontFamily: d.mono ? "var(--font-mono, ui-monospace, monospace)" : "inherit", overflowWrap: "anywhere", maxWidth: 124 }}>
        {d.label}
      </div>
      {d.sub && <div style={{ fontSize: 10.5, color: C.muted, textAlign: "center", lineHeight: 1.15 }}>{d.sub}</div>}
      {d.badge && (
        <div style={{ fontSize: 10, fontWeight: 800, color: d.tone, textTransform: "uppercase", letterSpacing: 0.3 }}>{d.badge}</div>
      )}
      {d.chips?.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2, marginTop: 1 }}>
          {d.chips.map((c: string, i: number) => (
            <div key={i} style={{ fontSize: 10.5, fontWeight: 600, color: "var(--fg,#e6edf3)", background: d.tone + "1c", border: `1px solid ${d.tone}55`, borderRadius: 5, padding: "1px 6px", textAlign: "center", overflowWrap: "anywhere" }}>{c}</div>
          ))}
        </div>
      )}
      {d.via && <div style={{ fontSize: 10, fontWeight: 700, color: C.info }}>↳ via {String(d.via).toUpperCase()}</div>}
    </div>
  );
}

const nodeTypes = { topo: TopoNode };
const edgeTypes = { flow: FlowEdge };

function splitPath(id: string): { src: string; dst: string } | null {
  if (!id.includes("->")) return null;
  const [src, dst] = id.split("->");
  return { src: (src || "").trim(), dst: (dst || "").trim() };
}

// classifyRcaPath — decide WHAT the path/context view is for this object and
// whether it can be placed on a canvas at all. Drives the section title (so we
// never call a BGP-only object an "End-to-end path") and the compact empty-state
// when there is nothing structural to draw. Pure; mirrors the model the canvas
// builds. Precedence: full path → interface/link → routing peer → ownership
// boundary → device area → (unplaceable).
export type RcaPathCtx = {
  title: string; subtitle?: string; placeable: boolean; strongest?: string;
};
export function classifyRcaPath(timeline: CorrTimeline, _seams?: Record<string, Seam>): RcaPathCtx {
  const sigs = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  const isDebug = (s: CorrSignal) =>
    s.probe_authority === "debug_only" || s.probe_scope === "internal_self_probe" || s.probe_scope === "synthetic_lab_probe";

  // internal/self-monitoring only (every attached signal an internal probe)
  const probes = sigs.filter((s) => s.modality_class === "active_probe");
  const others = sigs.filter((s) => s.modality_class !== "active_probe");
  if (sigs.length > 0 && others.length === 0 && probes.length > 0 && probes.every(isDebug))
    return { title: "Internal monitoring path", placeable: true };

  const edges = timeline.edges ?? [];
  const seamEdge = edges.find((e) => e.grounding_kind === "seam");

  // measured path with both ends real (customer source → destination)
  const pathSig = sigs.find((s) => s.entity_type === "path" && s.is_trigger) ?? sigs.find((s) => s.entity_type === "path");
  const ends = pathSig ? splitPath(pathSig.entity_id) : null;
  const fullPath = !!(ends && !isInternalEntity(ends.src) && !isInternalEntity(ends.dst) && ends.src && ends.dst);

  // a local interface/link the issue sits on (link_state, if counters, …)
  const ifaceSig = sigs.find((s) => s.entity_type === "interface" && !isInternalEntity(s.entity_id));

  // a routing peer/session (BGP/OSPF/… with a named far end)
  const hasRouting = sigs.some((s) => isRoutingKind(s.kind));

  // device the grounded edges converge on (topo shared:X), non-internal
  const share = new Map<string, number>();
  for (const e of edges) if (e.grounding_kind === "topo" && e.grounding_ref.startsWith("shared:")) {
    const x = e.grounding_ref.slice(7);
    if (!isInternalEntity(x)) share.set(x, (share.get(x) ?? 0) + 1);
  }
  const locus = [...share.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

  const trig = sigs.find((s) => s.is_trigger) ?? sigs[0] ?? timeline.signals[0];
  const strongest = trig && !mentionsInternal(trig.entity_id) ? entityLabel(trig.entity_id) : undefined;

  if (fullPath) return { title: "End-to-end path", placeable: true };
  if (ifaceSig) return { title: "Affected link or interface", placeable: true };
  if (hasRouting) return { title: "Routing context", subtitle: "The routing peer/session involved in this issue.", placeable: true };
  if (seamEdge) return { title: "Ownership boundary involved", subtitle: "A provider/ownership handoff is part of this issue.", placeable: true };
  if (locus) return { title: "Affected device area", placeable: true };
  return { title: "Path location not known yet", placeable: false, strongest };
}

export default function RcaTopology({ timeline, seams, view = "operator", height = 320, probePaths, deviceByIp }: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view?: "operator" | "debug";
  height?: number;
  probePaths?: ProbePath[];
  deviceByIp?: Record<string, string>;
}) {
  // Evidence-derived model — drives the legend / STAMP toggle / empty-states. It
  // comes from the SAME builder the graph does (computeTopoModel), so the overlays
  // and the canvas can never disagree. (showStamp is a render-time label toggle
  // only — it doesn't change which nodes/edges exist, so the model is stamp-free.)
  const model = useMemo(() => computeTopoModel(timeline, seams, probePaths), [timeline, seams, probePaths]);

  const [showStamp, setShowStamp] = useState(false);

  // The graph (nodes/edges/layout) comes from the SHARED builder so the PDF draws
  // the same picture; here we just map it onto React Flow — nodes → topo nodes with
  // {position, draggable, data}, edges → the animated flow edge (marker/style/data).
  const { rfNodes, rfEdges } = useMemo(() => {
    const graph = buildTopoGraph(timeline, seams, view, showStamp, probePaths, deviceByIp);
    const meta = STATUS_META[statusForVerdict(timeline.verdict_tier)];
    const stateColor = (s: EdgeState) =>
      s === "confirmed_down" || s === "suspected_down" ? meta.color
      : s === "degraded" ? C.warn : s === "unknown" ? C.faint : "#5a93c2";

    const rfNodes: Node[] = graph.nodes.map((n) => ({
      id: n.id, type: "topo", position: { x: n.x, y: n.y }, draggable: true,
      data: n.data as unknown as Record<string, unknown>,
    }));
    const rfEdges: Edge[] = graph.edges.map((e) => {
      const color = stateColor(e.state);
      const down = e.state === "suspected_down" || e.state === "confirmed_down";
      // co-affected branch edges (the bottom-handle "unknown" links) are static
      // context, not traffic — they don't animate. Everything else flows.
      const flow = !(e.state === "unknown" && e.fromHandle === "b");
      return {
        id: `${e.from}~${e.to}`, source: e.from, target: e.to, sourceHandle: e.fromHandle, type: "flow",
        label: e.label, markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
        data: { flow, state: e.state, particles: e.state === "degraded" ? 4 : 2, speed: e.state === "degraded" ? 1.8 : 3.0 },
        style: { stroke: color, strokeWidth: down || e.state === "degraded" ? 2.8 : 1.8, opacity: 0.95 },
      };
    });
    return { rfNodes, rfEdges };
  }, [timeline, seams, view, showStamp, probePaths, deviceByIp]);

  // Platform self-monitoring object (no customer network entity) → don't dress it
  // up as a customer path (decision #76).
  if (model.internal) {
    return (
      <div style={{ fontSize: 12.5, padding: "12px 14px", borderRadius: 10, border: "1px solid var(--border,#2a2f3a)", background: "var(--panel,#151b2b)", color: C.muted, display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontSize: 18, opacity: 0.7 }}>◎</span>
        <span><b style={{ color: "var(--fg,#e6edf3)" }}>Internal monitoring path</b> — this is the platform observing itself (monitoring agents / platform services), not a customer network path. See Stack Health for self-monitoring.</span>
      </div>
    );
  }

  if (rfNodes.length === 0 || (!model.hasPath && !model.locusDev)) {
    return (
      <div className="empty" style={{ fontSize: 12, padding: "10px 0" }}>
        Not enough evidence to place this on an end-to-end path yet — no measured path and no device the signs converge on.
      </div>
    );
  }

  const m = STATUS_META[statusForVerdict(timeline.verdict_tier)];
  return (
    <div style={{ position: "relative", height, borderRadius: 10, overflow: "hidden", border: "1px solid var(--border,#2a2f3a)", background: "radial-gradient(120% 120% at 0% 0%, rgba(40,52,74,0.35), var(--bg,#0e1320) 60%)" }}>
      <ReactFlow
        nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
        fitView fitViewOptions={{ padding: 0.28, maxZoom: 1.05 }} proOptions={{ hideAttribution: true }}
        nodesConnectable={false} elementsSelectable nodesDraggable panOnDrag
        minZoom={0.3} maxZoom={1.8} zoomOnScroll={false} preventScrolling={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border,#2a2f3a)" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
      <div style={{
        position: "absolute", left: 10, top: 10, zIndex: 5, display: "flex", gap: 12, alignItems: "center",
        fontSize: 11, fontWeight: 600, padding: "3px 9px", borderRadius: 6,
        background: "var(--panel,#151b2b)", border: "1px solid var(--border,#2a2f3a)", color: C.muted,
      }}>
        <span style={{ color: m.color, fontWeight: 800 }}>{m.sym} {m.word}</span>
        {(() => {
          const methods = model.tracedRows.flatMap((row) => row.methods);
          const live = methods.length > 0;
          const fallbackLabel = model.peer ? "routing context" : "contextual path";
          return <span style={{ color: live ? C.ok : C.faint }}>{live ? `● live trace (${methodTag([...new Set(methods)])})` : fallbackLabel}</span>;
        })()}
      </div>
      {model.hasStamp && (
        <button
          onClick={() => setShowStamp((v) => !v)}
          title="Show per-path active-measurement (STAMP) metrics — loss · RTT · jitter"
          style={{
            position: "absolute", right: 10, top: 10, zIndex: 5, cursor: "pointer",
            fontSize: 11, fontWeight: 700, padding: "3px 9px", borderRadius: 6,
            background: showStamp ? C.info + "22" : "var(--panel,#151b2b)",
            border: `1px solid ${showStamp ? C.info : "var(--border,#2a2f3a)"}`,
            color: showStamp ? C.info : C.muted,
          }}>
          {showStamp ? "● STAMP metrics" : "○ STAMP metrics"}
        </button>
      )}
    </div>
  );
}
