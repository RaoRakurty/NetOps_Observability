import { useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CorrTimeline, CorrSignal, Seam, ProbePath } from "../../services/api";
import { C, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, seamOwnerColor } from "./labels";

// RcaTopology — the END-TO-END contextual path with the fault marked. OVERLAY
// MODEL: the path STRUCTURE (observer → device area → target) is built from data
// — today from the correlation object's own entities, tomorrow fused with live
// traceroute (/api/probe/paths) for true hop order — and RCA ANNOTATES it with
// where it's broken / suspected / possible. Fully data-driven: no entity is
// hardcoded, so it scales as devices and seams are added to the network.
//
// Honesty: without a live trace we do NOT invent a hop sequence. We show what we
// can prove — "loss observed from <observer> to <target>; evidence converges on
// <device>; here is exactly what's broken there" — and place co-affected devices
// as a branch off the locus, not as a fake ordered chain.

type FaultStatus = "broken" | "suspected" | "possible";

const STATUS_META: Record<FaultStatus, { sym: string; word: string; color: string }> = {
  broken: { sym: "❌", word: "Broken", color: C.crit },
  suspected: { sym: "⚠", word: "Suspected", color: C.warn },
  possible: { sym: "?", word: "Possible", color: C.caution },
};

function statusForVerdict(tier: string): FaultStatus {
  return tier === "confirmed" ? "broken" : tier === "suspected" ? "suspected" : "possible";
}

// "vantage-e2e->e2e-edge1" → { src, dst }; tolerant of missing arrow.
function splitPath(id: string): { src: string; dst: string } | null {
  if (!id.includes("->")) return null;
  const [src, dst] = id.split("->");
  return { src: (src || "").trim(), dst: (dst || "").trim() };
}

// Base device an entity sits on: interface "dev:Gi0/1" → "dev"; device → itself.
function baseDevice(entityType: string, entityId: string): string {
  if (entityType === "interface") return entityId.split(":")[0];
  if (entityType === "path") return entityId; // handled separately
  return entityId.split(":")[0];
}

// Readable "what's broken" phrase for one signal (operator wording).
function brokenElement(s: CorrSignal): string {
  if (s.entity_type === "interface") {
    const iface = s.entity_id.split(":").slice(1).join(":");
    return `${iface || "interface"} · ${kindLabel(s.kind)}`;
  }
  return kindLabel(s.kind);
}

const SEV_RANK: Record<string, number> = { crit: 4, high: 3, warn: 2, info: 1 };

// --- custom nodes -----------------------------------------------------------
const handleStyle = { width: 6, height: 6, background: "var(--border,#3a4252)", border: "none" } as const;

function EndpointNode({ data }: NodeProps) {
  const d = data as any;
  return (
    <div style={{
      minWidth: 124, maxWidth: 168, background: "var(--panel,#151b2b)",
      border: "1px solid var(--border,#2a2f3a)", borderRadius: 10, padding: "9px 11px",
      boxShadow: "0 1px 2px rgba(0,0,0,.18), 0 6px 16px rgba(0,0,0,.14)", fontSize: 12, lineHeight: 1.25,
    }}>
      {d.hasIn && <Handle type="target" position={Position.Left} style={handleStyle} />}
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 13 }}>{d.icon}</span>
        <span style={{ fontWeight: 700, color: "var(--fg,#e6edf3)", overflowWrap: "anywhere" }}>{d.label}</span>
      </div>
      <div style={{ marginTop: 2, color: C.muted, fontSize: 11 }}>{d.role}</div>
      {d.hasOut && <Handle type="source" position={Position.Right} style={handleStyle} />}
    </div>
  );
}

function FaultNode({ data }: NodeProps) {
  const d = data as any;
  const m: { sym: string; word: string; color: string } = d.meta;
  return (
    <div style={{
      minWidth: 184, maxWidth: 248, background: "var(--panel,#151b2b)",
      border: `2px solid ${m.color}`, borderRadius: 11, padding: "10px 12px",
      boxShadow: `0 0 0 4px ${m.color}24, 0 8px 22px rgba(0,0,0,.22)`, fontSize: 12, lineHeight: 1.3,
    }}>
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
        <span style={{ fontSize: 15 }}>{m.sym}</span>
        <span style={{ fontWeight: 800, color: "var(--fg,#e6edf3)", fontSize: 13, overflowWrap: "anywhere" }}>{d.label}</span>
      </div>
      <div style={{ marginTop: 1, fontSize: 11, fontWeight: 700, color: m.color, textTransform: "uppercase", letterSpacing: 0.3 }}>
        {m.word} fault {d.isTarget ? "· destination" : ""}
      </div>
      {d.elements?.length > 0 && (
        <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 3 }}>
          {d.elements.map((e: string, i: number) => (
            <div key={i} style={{
              fontSize: 11, fontWeight: 600, color: "var(--fg,#e6edf3)",
              background: m.color + "1c", border: `1px solid ${m.color}55`,
              borderRadius: 5, padding: "2px 7px", overflowWrap: "anywhere",
            }}>{e}</div>
          ))}
        </div>
      )}
      <Handle type="source" position={Position.Right} style={handleStyle} />
      <Handle type="source" position={Position.Bottom} id="b" style={handleStyle} />
    </div>
  );
}

function AffectedNode({ data }: NodeProps) {
  const d = data as any;
  return (
    <div style={{
      minWidth: 120, maxWidth: 176, background: "var(--panel,#151b2b)",
      border: `1px solid ${C.warn}77`, borderLeft: `4px solid ${C.warn}`, borderRadius: 9,
      padding: "7px 10px", fontSize: 11.5, lineHeight: 1.25, boxShadow: "0 4px 12px rgba(0,0,0,.16)",
    }}>
      <Handle type="target" position={Position.Top} id="t" style={handleStyle} />
      <div style={{ fontWeight: 700, color: "var(--fg,#e6edf3)", overflowWrap: "anywhere" }}>{d.label}</div>
      <div style={{ marginTop: 1, color: C.warn, fontSize: 10.5, fontWeight: 600 }}>also affected</div>
      {d.detail && <div style={{ marginTop: 1, color: C.muted, fontSize: 10.5, overflowWrap: "anywhere" }}>{d.detail}</div>}
    </div>
  );
}

// One traced hop (live traceroute): IP/name + ttl, optional rtt/loss. `tone`
// (set on a trace-loss hop) tints the top border ThousandEyes-style.
function HopNode({ data }: NodeProps) {
  const d = data as any;
  return (
    <div style={{
      minWidth: 96, maxWidth: 154, background: "var(--panel,#151b2b)",
      border: `1px solid ${d.tone ?? "var(--border,#2a2f3a)"}`,
      borderTop: d.tone ? `3px solid ${d.tone}` : "1px solid var(--border,#2a2f3a)",
      borderRadius: 8, padding: "7px 9px", fontSize: 11.5, lineHeight: 1.2,
      boxShadow: "0 4px 12px rgba(0,0,0,.14)",
    }}>
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        {d.icon && <span style={{ fontSize: 12 }}>{d.icon}</span>}
        <span style={{ fontWeight: 700, color: "var(--fg,#e6edf3)", fontFamily: "var(--font-mono, ui-monospace, monospace)", fontSize: 11, overflowWrap: "anywhere" }}>{d.label}</span>
      </div>
      {d.sub && <div style={{ marginTop: 1, color: C.muted, fontSize: 10.5 }}>{d.sub}</div>}
      {d.metric && <div style={{ marginTop: 2, color: d.tone ?? C.info, fontSize: 10.5, fontWeight: 600 }}>{d.metric}</div>}
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
}

function SeamNode({ data }: NodeProps) {
  const d = data as any;
  return (
    <div style={{
      minWidth: 128, maxWidth: 168, background: "var(--panel,#151b2b)",
      border: `2px ${d.border} ${d.borderColor}`, borderRadius: 7, padding: "7px 10px",
      boxShadow: `0 0 0 3px ${d.color}1f, 0 6px 16px rgba(0,0,0,.16)`, fontSize: 11.5, lineHeight: 1.2,
    }}>
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ width: 10, height: 10, transform: "rotate(45deg)", flexShrink: 0, background: d.color, borderRadius: 2 }} />
        <span style={{ fontWeight: 700, color: "var(--fg,#e6edf3)", overflowWrap: "anywhere" }}>{d.head}</span>
      </div>
      <div style={{ marginTop: 3, color: C.muted, fontSize: 11 }}>
        <span style={{ color: d.color, fontWeight: 600 }}>{d.owner}</span>{d.vis ? ` · ${d.vis}` : ""}
      </div>
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
}

const nodeTypes = { endpoint: EndpointNode, fault: FaultNode, affected: AffectedNode, seamb: SeamNode, hop: HopNode };

const COL = 250;
const COL_HOP = 184;
const TRACE_LOSS_HI = 2; // % per-hop forwarding loss that flags a hop (ThousandEyes-style)

// Match the RCA path's destination to a live trace (exact, or either-contains —
// covers "10.70.245.120" == dst and named dsts like "aws-tgw").
function matchTrace(dst: string | undefined, paths?: ProbePath[]): ProbePath | undefined {
  if (!dst || !paths?.length) return undefined;
  const d = dst.trim();
  return paths.find((p) => p.dst === d)
    ?? paths.find((p) => p.dst && (p.dst.includes(d) || d.includes(p.dst)) && (p.hops?.length ?? 0) > 0);
}

export default function RcaTopology({ timeline, seams, view = "operator", height = 300, probePaths }: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view?: "operator" | "debug";
  height?: number;
  probePaths?: ProbePath[];
}) {
  const model = useMemo(() => {
    const sigs = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
    // primary probe path = the attached path signal (prefer trigger), gives ENDS.
    const pathSig = sigs.find((s) => s.entity_type === "path" && s.is_trigger)
      ?? sigs.find((s) => s.entity_type === "path");
    const ends = pathSig ? splitPath(pathSig.entity_id) : null;

    // Active-measurement (STAMP/probe) metrics on the measured path. The headline
    // `lossTxt` is always shown on the degraded segment (it's the fault signature);
    // the fuller `stampTxt` (loss · rtt · jitter) is opt-in (the toggle) so the
    // default stays uncluttered. Metrics are pulled from the path signals on THIS
    // path (probe_loss → loss; probe_rtt_ms[stamp|icmp|…] → rtt; probe_jitter →
    // jitter), preferring the STAMP method for rtt.
    const pathId = pathSig?.entity_id;
    const pathSigs = pathId ? sigs.filter((s) => s.entity_type === "path" && s.entity_id === pathId) : [];
    const lossPct = (() => {
      const s = pathSigs.find((x) => /loss/.test(x.kind));
      if (!s) return NaN;
      const v = Number(s.value);
      return isFinite(v) ? (v <= 1 ? v * 100 : v) : NaN;
    })();
    const rttMs = (() => {
      const cand = pathSigs.filter((x) => /rtt|latency/.test(x.kind) && isFinite(Number(x.value)));
      const s = cand.find((x) => /\[stamp\]/.test(x.metric_name)) ?? cand[0];
      return s ? Number(s.value) : NaN;
    })();
    const jitterMs = (() => {
      const s = pathSigs.find((x) => /jitter/.test(x.kind) || /jitter/.test(x.metric_name));
      return s ? Number(s.value) : NaN;
    })();
    const lossTxt = isFinite(lossPct) && lossPct > 0 ? `${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss`
      : pathSigs.some((x) => /rtt|latency/.test(x.kind)) ? "latency rise" : pathSig ? "degraded" : "";
    const stampParts: string[] = [];
    if (isFinite(lossPct) && lossPct > 0) stampParts.push(`${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss`);
    if (isFinite(rttMs)) stampParts.push(`${rttMs.toFixed(rttMs < 10 ? 2 : 1)} ms rtt`);
    if (isFinite(jitterMs)) stampParts.push(`${jitterMs.toFixed(2)} ms jitter`);
    const stampTxt = stampParts.join("  ·  ");
    const hasStamp = stampParts.length > 0;

    // aggregate device-level evidence (everything that isn't the path measure).
    type Dev = { dev: string; elements: string[]; worst: number };
    const devs = new Map<string, Dev>();
    for (const s of sigs) {
      if (s.entity_type === "path") continue;
      const dev = baseDevice(s.entity_type, s.entity_id);
      if (!dev) continue;
      const d = devs.get(dev) ?? { dev, elements: [], worst: 0 };
      const el = brokenElement(s);
      if (!d.elements.includes(el)) d.elements.push(el);
      d.worst = Math.max(d.worst, SEV_RANK[s.severity] ?? 1);
      devs.set(dev, d);
    }

    // locus = device the grounded topo edges converge on (shared:X), else the
    // worst-severity device, else the path destination.
    const shareCount = new Map<string, number>();
    for (const e of timeline.edges ?? []) {
      if (e.grounding_kind === "topo" && e.grounding_ref.startsWith("shared:")) {
        const x = e.grounding_ref.slice(7);
        shareCount.set(x, (shareCount.get(x) ?? 0) + 1);
      }
    }
    let locusDev = [...shareCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
    if (!locusDev) locusDev = [...devs.values()].sort((a, b) => b.worst - a.worst)[0]?.dev;
    if (!locusDev && ends) locusDev = ends.dst;

    // seam boundary on the path (first seam-grounded edge), if any.
    const seamEdge = (timeline.edges ?? []).find((e) => e.grounding_kind === "seam");
    const seam = seamEdge ? seams[seamEdge.grounding_ref] : undefined;

    // LIVE-TRACE FUSION: if the RCA path's destination has a real traceroute, use
    // its hops as the true ordered backbone (Phase 2). Else fall back to the
    // contextual placement (Phase 1).
    const traced = matchTrace(ends?.dst, probePaths);

    return { ends, lossTxt, stampTxt, hasStamp, devs, locusDev, seam, traced, hasPath: !!ends };
  }, [timeline, seams, probePaths]);

  const [showStamp, setShowStamp] = useState(false);

  const { rfNodes, rfEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const status = statusForVerdict(timeline.verdict_tier);
    const meta = STATUS_META[status];
    const { ends, lossTxt, stampTxt, devs, locusDev, seam, traced } = model;
    // measured-segment label: STAMP detail when the knob is on, else the loss
    // headline only (the fault signature) — keeps the default uncluttered.
    const measuredLabel = showStamp && stampTxt ? stampTxt : lossTxt;

    const locus = locusDev ? (devs.get(locusDev) ?? { dev: locusDev, elements: [], worst: 0 }) : undefined;
    const targetIsLocus = !!(ends && locus && ends.dst === locus.dev);

    const push = (n: Node) => { nodes.push(n); };
    const link = (from: string, to: string, opts: { degraded?: boolean; label?: string; fromHandle?: string } = {}) => {
      edges.push({
        id: `${from}~${to}`, source: from, target: to, sourceHandle: opts.fromHandle, type: "smoothstep",
        animated: !!opts.degraded, label: opts.label,
        labelStyle: { fill: "var(--fg,#e6edf3)", fontSize: 11, fontWeight: 700 },
        labelBgStyle: { fill: "var(--panel,#151b2b)" }, labelBgPadding: [4, 2] as [number, number], labelBgBorderRadius: 4,
        markerEnd: { type: MarkerType.ArrowClosed, color: opts.degraded ? meta.color : "#5a6472", width: 15, height: 15 },
        style: { stroke: opts.degraded ? meta.color : "#5a6472", strokeWidth: opts.degraded ? 2.6 : 1.6, opacity: 0.92 },
      });
    };

    // ===== TRACED MODE (Phase 2): real hop chain from live traceroute =========
    if (traced && ends) {
      const hops = [...(traced.hops ?? [])].sort((a, b) => a.ttl - b.ttl);
      // which hop carries the RCA fault: a hop whose IP/name matches the locus,
      // else the destination hop (the diagnosed target).
      let faultIdx = hops.findIndex((h) => h.ip && locusDev && h.ip === locusDev);
      if (faultIdx < 0) faultIdx = hops.length - 1;

      // observer / source
      push({ id: "src", type: "endpoint", position: { x: 0, y: 0 }, draggable: true,
        data: { icon: "◉", label: entityLabel(ends.src), role: "observed from here", hasIn: false, hasOut: true } });
      let prev = "src";

      hops.forEach((h, i) => {
        const id = `hop${i}`;
        const isLast = i === hops.length - 1;
        const lossHi = Number(h.loss_pct) > TRACE_LOSS_HI;
        const rtt = Number(h.rtt_ms);
        const hopLabel = h.ip && h.ip !== "" ? h.ip : "*";
        const metric =
          showStamp && isFinite(rtt) ? `${rtt.toFixed(rtt < 10 ? 2 : 1)} ms${lossHi ? ` · ${Math.round(Number(h.loss_pct))}% loss` : ""}`
          : lossHi ? `${Math.round(Number(h.loss_pct))}% loss` : undefined;
        if (i === faultIdx) {
          push({ id, type: "fault", position: { x: (i + 1) * COL_HOP, y: 0 }, draggable: true,
            data: { label: hopLabel, meta, elements: (locus?.elements ?? []).slice(0, 4), isTarget: isLast } });
        } else {
          push({ id, type: "hop", position: { x: (i + 1) * COL_HOP, y: 0 }, draggable: true,
            data: { label: hopLabel, icon: isLast ? "⊚" : undefined, sub: isLast ? "destination" : `hop ${h.ttl}`, metric, tone: lossHi ? meta.color : undefined } });
        }
        // edge into this hop: degraded if this hop lost packets (or it's the fault
        // hop on a degraded path). first segment carries the measured headline.
        const segDegraded = lossHi || (i === faultIdx && !!lossTxt);
        const segLabel = showStamp && isFinite(rtt) ? `${rtt.toFixed(rtt < 10 ? 2 : 1)} ms`
          : i === 0 ? measuredLabel : lossHi ? `${Math.round(Number(h.loss_pct))}% loss` : undefined;
        link(prev, id, { degraded: segDegraded, label: segLabel });
        prev = id;
      });

      return { rfNodes: nodes, rfEdges: edges };
    }

    // ===== CONTEXTUAL MODE (Phase 1): placement from RCA evidence ==============
    let col = 0;
    let prevId: string | null = null;
    let prevHandle: string | undefined;

    // 1) observer / source end
    if (ends) {
      const id = "src";
      push({ id, type: "endpoint", position: { x: col * COL, y: 0 }, draggable: true,
        data: { icon: "◉", label: entityLabel(ends.src), role: "observed from here", hasIn: false, hasOut: true } });
      prevId = id; col++;
    }

    // 2) optional seam boundary on the path
    if (seam) {
      const id = "seam";
      const vis = seam.visibility ?? "";
      const border = vis === "partial" ? "dashed" : vis === "blind" ? "dotted" : "solid";
      const ownerColor = seamOwnerColor(seam.control_plane_owner);
      push({ id, type: "seamb", position: { x: col * COL, y: 0 }, draggable: true,
        data: {
          head: view === "debug" ? (seam.seam_id || "boundary") : (seam.display_name || "Provider boundary"),
          owner: view === "debug" ? (seam.control_plane_owner ?? "?") : seamOwnerLabel(seam.control_plane_owner),
          vis: view === "debug" ? vis : visibilityLabel(seam.visibility),
          color: ownerColor, border, borderColor: vis === "blind" ? C.crit : vis === "partial" ? C.caution : ownerColor,
        } });
      if (prevId) link(prevId, id, { degraded: !!lossTxt, label: prevId === "src" ? measuredLabel : undefined });
      prevId = id; col++;
    }

    // 3) the fault locus (prominent)
    if (locus) {
      const id = "fault";
      push({ id, type: "fault", position: { x: col * COL, y: 0 }, draggable: true,
        data: { label: entityLabel(locus.dev), meta, elements: locus.elements.slice(0, 4), isTarget: targetIsLocus } });
      if (prevId) link(prevId, id, { degraded: !!lossTxt, label: prevId === "src" ? measuredLabel : undefined });
      prevId = id; prevHandle = undefined; col++;

      // 3b) co-affected devices branch BELOW the locus (no fake hop order)
      const others = [...devs.values()].filter((d) => d.dev !== locus.dev);
      others.slice(0, 4).forEach((d, i) => {
        const aid = `aff${i}`;
        push({ id: aid, type: "affected", position: { x: (col - 1) * COL + (i - (others.length - 1) / 2) * 150, y: 150 }, draggable: true,
          data: { label: entityLabel(d.dev), detail: d.elements[0] ?? "" } });
        link("fault", aid, { fromHandle: "b" });
      });
    }

    // 4) destination end (only if distinct from the fault device)
    if (ends && !targetIsLocus) {
      const id = "dst";
      push({ id, type: "endpoint", position: { x: col * COL, y: 0 }, draggable: true,
        data: { icon: "⊚", label: entityLabel(ends.dst), role: "destination", hasIn: true, hasOut: false } });
      if (prevId) link(prevId, id, { fromHandle: prevHandle });
    }

    return { rfNodes: nodes, rfEdges: edges };
  }, [model, timeline.verdict_tier, view, showStamp]);

  // Nothing groundable → honest fallback (don't invent a path).
  if (rfNodes.length === 0 || (!model.hasPath && !model.locusDev)) {
    return (
      <div className="empty" style={{ fontSize: 12, padding: "10px 0" }}>
        Not enough evidence to place this on an end-to-end path yet — no measured path and no device the signs converge on.
      </div>
    );
  }

  const m = STATUS_META[statusForVerdict(timeline.verdict_tier)];
  return (
    <div style={{ position: "relative", height, borderRadius: 8, overflow: "hidden", border: "1px solid var(--border,#2a2f3a)", background: "var(--bg,#0e1320)" }}>
      <ReactFlow
        nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes}
        fitView fitViewOptions={{ padding: 0.2 }} proOptions={{ hideAttribution: true }}
        nodesConnectable={false} elementsSelectable={false} nodesDraggable
        minZoom={0.3} maxZoom={1.6} zoomOnScroll={false} panOnScroll
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--border,#2a2f3a)" />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
      <div style={{
        position: "absolute", left: 10, top: 10, zIndex: 5, display: "flex", gap: 12, alignItems: "center",
        fontSize: 11, fontWeight: 600, padding: "3px 9px", borderRadius: 6,
        background: "var(--panel,#151b2b)", border: "1px solid var(--border,#2a2f3a)", color: C.muted,
      }}>
        <span style={{ color: m.color, fontWeight: 800 }}>{m.sym} {m.word}</span>
        <span>◉ observed</span><span>⊚ destination</span>
        <span style={{ color: model.traced ? C.ok : C.faint }}>
          {model.traced ? "● live trace" : "contextual path · live trace next"}
        </span>
      </div>
      {/* opt-in STAMP metrics knob — default OFF so the path stays uncluttered. */}
      {model.hasStamp && (
        <button
          onClick={() => setShowStamp((v) => !v)}
          title="Show per-path active-measurement (STAMP) metrics — loss · RTT · jitter — on the measured segment"
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
