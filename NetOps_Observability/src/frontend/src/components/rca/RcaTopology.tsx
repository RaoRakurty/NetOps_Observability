import { useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CorrTimeline, Seam } from "../../services/api";
import { C } from "./labels";
import { ShapeSVG } from "../graph/shapes";
import FlowEdge from "../graph/FlowEdge";
import { buildTopoGraph, computeTopoModel, STATUS_META, statusForVerdict, type EdgeState, type TopoGraphBand } from "./topoGraph";
import { methodLabel, confidenceLabel, type SpineEvidence } from "./servicePath";

// RcaTopology — the source→destination service path with the fault marked, drawn
// with real network shapes (client / router / gateway / firewall / cloud / app),
// health colour + glow, and animated traffic-flow links.
//
// THE BACKEND, NOT REACT, DETERMINES HOP ORDER (service-path contract §7). This
// component is a THIN React-Flow mapping of the shared, renderer-agnostic layout
// produced by `buildTopoGraph` (topoGraph.ts) — the same layout the PDF export
// draws — plus the live overlays: boundary bands, the evidence inspector, the
// legend and the honest empty states. It computes NO hop order, uses NO node
// degree, and never falls back to a star: a path-focused object with no backend
// spine says so.

const handleStyle = { width: 7, height: 7, background: "var(--border,#3a4252)", border: "none" } as const;

// ── one shape-based node for every role ────────────────────────────────────
function TopoNode({ data }: NodeProps) {
  const d = data as any;
  const size = d.size ?? 56;
  const blind = d.hopState && d.hopState !== "responding";
  return (
    <div title={d.title} style={{ display: "flex", flexDirection: "column", alignItems: "center", width: d.width ?? 124, gap: 2 }}>
      {/* handles sit on the SHAPE's vertical center (not the whole node, whose
          label rows would otherwise pull the anchor down → crooked edges). */}
      <div style={{ position: "relative", width: size, height: size, display: "flex", alignItems: "center", justifyContent: "center" }}>
        {d.hasIn !== false && <Handle type="target" position={Position.Left} style={{ ...handleStyle, top: "50%" }} />}
        <ShapeSVG kind={d.kind} tone={d.tone} size={size} pulse={d.pulse} provider={d.provider} />
        {d.hasOut !== false && <Handle type="source" position={Position.Right} style={{ ...handleStyle, top: "50%" }} />}
        {d.hasBottom && <Handle type="source" position={Position.Bottom} id="b" style={{ ...handleStyle, left: "50%" }} />}
      </div>
      <div style={{
        fontWeight: 700, fontSize: 12, color: "var(--fg,#e6edf3)", textAlign: "center", lineHeight: 1.2,
        fontFamily: d.mono ? "var(--font-mono, ui-monospace, monospace)" : "inherit",
        overflowWrap: "anywhere", maxWidth: 124, fontStyle: blind ? "italic" : undefined,
      }}>
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

// ── boundary band — LAN / SD-WAN / CARRIER / CLOUD, drawn BEHIND the spine ──
// A background layer (like React Flow's own Background) that GROUPS the hops it
// spans; tinted by the boundary's owner so "whose domain" reads at a glance.
function BandNode({ data }: NodeProps) {
  const d = data as any;
  return (
    <div style={{
      width: d.width, height: d.height, borderRadius: 14,
      border: `1px dashed ${d.color}66`, background: `${d.color}0f`,
      pointerEvents: "none", display: "flex", justifyContent: "center",
    }}>
      <div style={{
        alignSelf: "flex-start", transform: "translateY(-10px)",
        fontSize: 10, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase",
        color: d.color, background: "var(--panel,#151b2b)", border: `1px solid ${d.color}66`,
        borderRadius: 999, padding: "1px 9px", whiteSpace: "nowrap",
      }}>{d.name}</div>
    </div>
  );
}

const nodeTypes = { topo: TopoNode, band: BandNode };
const edgeTypes = { flow: FlowEdge };

type Inspect = { title: string; sub?: string; evidence?: SpineEvidence };

// The evidence a hop or a segment stands on (contract §5) — ref · method ·
// confidence · when · data class. Every displayed edge can state this; an edge
// that cannot is never drawn.
function EvidenceStrip({ inspect, onClose }: { inspect: Inspect; onClose: () => void }) {
  const e = inspect.evidence;
  const cell = (k: string, v: string, mono = false) => (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "baseline" }}>
      <span style={{ color: C.muted, fontSize: 10, textTransform: "uppercase", letterSpacing: ".04em" }}>{k}</span>
      <span style={{ fontWeight: 700, fontFamily: mono ? "var(--font-mono, ui-monospace, monospace)" : "inherit" }}>{v}</span>
    </span>
  );
  return (
    <div style={{
      position: "absolute", left: 10, right: 10, bottom: 10, zIndex: 6,
      display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap",
      fontSize: 11.5, padding: "6px 10px", borderRadius: 8,
      background: "var(--panel,#151b2b)", border: "1px solid var(--border,#2a2f3a)", color: "var(--fg,#e6edf3)",
    }}>
      <b style={{ fontSize: 12 }}>{inspect.title}</b>
      {inspect.sub && <span style={{ color: C.muted }}>{inspect.sub}</span>}
      {e ? (
        <>
          {cell("how", methodLabel(e.method))}
          {cell("confidence", confidenceLabel(e.confidence))}
          {e.observed_at && cell("observed", e.observed_at)}
          {cell("evidence", e.ref, true)}
          {e.data_class !== "live" && (
            <span style={{ fontWeight: 800, color: C.warn, textTransform: "uppercase", fontSize: 10 }}>{e.data_class} data — cannot confirm</span>
          )}
        </>
      ) : (
        <span style={{ color: C.muted }}>No evidence record attached to this element.</span>
      )}
      <button onClick={onClose} aria-label="Close evidence" style={{
        marginLeft: "auto", cursor: "pointer", background: "transparent", border: "none",
        color: C.muted, fontWeight: 800, fontSize: 13,
      }}>×</button>
    </div>
  );
}

export default function RcaTopology({ timeline, seams, view = "operator", height = 320 }: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view?: "operator" | "debug";
  height?: number;
}) {
  // Evidence-derived model — drives the legend / STAMP toggle / empty states. It
  // comes from the SAME builder the graph does, so overlays and canvas can never
  // disagree.
  const model = useMemo(() => computeTopoModel(timeline, seams), [timeline, seams]);
  const [showStamp, setShowStamp] = useState(false);
  const [inspect, setInspect] = useState<Inspect | null>(null);

  const graph = useMemo(() => buildTopoGraph(timeline, seams, view, showStamp), [timeline, seams, view, showStamp]);

  const { rfNodes, rfEdges } = useMemo(() => {
    const meta = STATUS_META[statusForVerdict(timeline.verdict_tier)];
    const stateColor = (s: EdgeState) =>
      s === "confirmed_down" || s === "suspected_down" ? meta.color
      : s === "degraded" ? C.warn : s === "unknown" ? C.faint : "#5a93c2";

    // Bands go in FIRST and sit behind everything (zIndex −1), like the dot grid.
    const bandNodes: Node[] = graph.bands.map((b: TopoGraphBand) => ({
      id: `band-${b.name}-${b.from}`, type: "band", position: { x: b.x, y: b.y },
      data: { name: b.name, color: b.color, width: b.width, height: b.height },
      draggable: false, selectable: false, focusable: false, zIndex: -1,
      style: { zIndex: -1, pointerEvents: "none" as const },
    }));

    const rfNodes: Node[] = bandNodes.concat(graph.nodes.map((n) => ({
      id: n.id, type: "topo", position: { x: n.x, y: n.y }, draggable: true, zIndex: 1,
      data: n.data as unknown as Record<string, unknown>,
    })));

    const rfEdges: Edge[] = graph.edges.map((e) => {
      const color = stateColor(e.state);
      const down = e.state === "suspected_down" || e.state === "confirmed_down";
      // branch/context edges (bottom-handle "unknown" links) are static context,
      // not traffic — they don't animate. A blind SEGMENT of the spine doesn't
      // animate either: we never show packets flowing through a hop we can't see.
      const flow = e.state !== "unknown";
      return {
        id: `${e.from}~${e.to}`, source: e.from, target: e.to, sourceHandle: e.fromHandle, type: "flow",
        label: e.label, markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
        data: { flow, state: e.state, particles: e.state === "degraded" ? 4 : 2, speed: e.state === "degraded" ? 1.8 : 3.0 },
        style: { stroke: color, strokeWidth: down || e.state === "degraded" ? 2.8 : 1.8, opacity: 0.95 },
      };
    });
    return { rfNodes, rfEdges };
  }, [graph, timeline.verdict_tier]);

  // Platform self-monitoring object (no customer network entity) → don't dress it
  // up as a customer path (decision #76).
  if (graph.mode === "internal") {
    return (
      <div style={{ fontSize: 12.5, padding: "12px 14px", borderRadius: 10, border: "1px solid var(--border,#2a2f3a)", background: "var(--panel,#151b2b)", color: C.muted, display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontSize: 18, opacity: 0.7 }}>◎</span>
        <span><b style={{ color: "var(--fg,#e6edf3)" }}>Internal monitoring path</b> — this is the platform observing itself (monitoring agents / platform services), not a customer network path. See Stack Health for self-monitoring.</span>
      </div>
    );
  }

  // NO SPINE ⇒ WE SAY SO. This issue is about a service path (client → app), but
  // no ordered, evidenced path has been measured for it — so there is nothing
  // honest to draw. We do NOT guess hops and we do NOT fall back to a star.
  if (graph.mode === "empty" && model.pathFocused) {
    return (
      <div style={{ fontSize: 12.5, padding: "12px 14px", borderRadius: 10, border: "1px dashed var(--border,#2a2f3a)", background: "var(--panel,#151b2b)", color: C.muted, display: "flex", gap: 10, alignItems: "flex-start" }}>
        <span style={{ fontSize: 16, opacity: 0.7, lineHeight: 1.3 }}>⌁</span>
        <span>
          <b style={{ color: "var(--fg,#e6edf3)" }}>No measured path for this issue yet.</b>{" "}
          This issue involves a service path, but no ordered hop-by-hop measurement (client → gateway → WAN edge → cloud → application)
          has been recorded for it. The path is shown only when it has been measured — hop order is never guessed.
          {model.hasStamp && <> Measured so far: <b style={{ color: "var(--fg,#e6edf3)" }}>{model.stampTxt}</b> end-to-end.</>}
        </span>
      </div>
    );
  }

  if (rfNodes.length === 0) {
    return (
      <div className="empty" style={{ fontSize: 12, padding: "10px 0" }}>
        Not enough evidence to place this on an end-to-end path yet — no measured path and no device the signs converge on.
      </div>
    );
  }

  const m = STATUS_META[statusForVerdict(timeline.verdict_tier)];
  const path = graph.path;
  // Legend: HOW the path was observed (the methods the backend's evidence names)
  // and whether any of it is non-live data (which can never confirm — contract §1).
  const methods = path ? [...new Set(path.edges.map((e) => e.evidence?.method).filter(Boolean) as string[])] : [];
  const nonLive = path ? [...new Set(path.edges.concat(path.spine as any).map((x: any) => x.evidence?.data_class).filter((c: string) => c && c !== "live"))] as string[] : [];

  return (
    <div style={{ position: "relative", height, borderRadius: 10, overflow: "hidden", border: "1px solid var(--border,#2a2f3a)", background: "radial-gradient(120% 120% at 0% 0%, rgba(40,52,74,0.35), var(--bg,#0e1320) 60%)" }}>
      <ReactFlow
        nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
        fitView fitViewOptions={{ padding: 0.28, maxZoom: 1.05 }} proOptions={{ hideAttribution: true }}
        nodesConnectable={false} elementsSelectable nodesDraggable panOnDrag
        minZoom={0.3} maxZoom={1.8} zoomOnScroll={false} preventScrolling={false}
        onNodeClick={(_, n) => {
          const d = graph.nodes.find((x) => x.id === n.id)?.data;
          if (!d) return;
          setInspect({
            title: d.label,
            sub: [d.hopIndex !== undefined ? `hop ${d.hopIndex}` : "", d.boundary, d.hopState && d.hopState !== "responding" ? d.hopState : "", d.transformation].filter(Boolean).join(" · ") || undefined,
            evidence: d.evidence,
          });
        }}
        onEdgeClick={(_, e) => {
          const ge = graph.edges.find((x) => `${x.from}~${x.to}` === e.id);
          if (!ge) return;
          const from = graph.nodes.find((n) => n.id === ge.from)?.data.label ?? ge.from;
          const to = graph.nodes.find((n) => n.id === ge.to)?.data.label ?? ge.to;
          setInspect({
            title: `${from} → ${to}`,
            sub: [ge.transformation, ge.state === "unknown" ? "unobserved segment" : ""].filter(Boolean).join(" · ") || undefined,
            evidence: ge.evidence,
          });
        }}
        onPaneClick={() => setInspect(null)}
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
        {graph.mode === "spine" ? (
          <span style={{ color: C.ok }}>
            ● measured path · {path?.spine.length ?? 0} hops{methods.length ? ` (${methods.map(methodLabel).join(" · ")})` : ""}
          </span>
        ) : (
          <span style={{ color: C.faint }}>{model.peer ? "routing context" : "affected device area"}</span>
        )}
        {nonLive.length > 0 && (
          <span title="Non-live evidence can support or illustrate, never confirm." style={{ color: C.warn, fontWeight: 800, textTransform: "uppercase" }}>
            {nonLive.join(" · ")} data
          </span>
        )}
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
          {showStamp ? `● ${model.stampTxt}` : "○ STAMP metrics"}
        </button>
      )}
      {inspect && <EvidenceStrip inspect={inspect} onClose={() => setInspect(null)} />}
    </div>
  );
}
