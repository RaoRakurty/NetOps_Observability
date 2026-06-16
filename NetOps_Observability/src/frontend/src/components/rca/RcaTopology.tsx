import { useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CorrTimeline, CorrSignal, Seam, ProbePath } from "../../services/api";
import { C, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, seamOwnerColor, isInternalEntity } from "./labels";
import { ShapeSVG, kindForRole, type ShapeKind } from "../graph/shapes";
import FlowEdge from "../graph/FlowEdge";

// RcaTopology — the END-TO-END path with the fault marked, drawn with real
// network shapes (vantage / router / switch / firewall / gateway / cloud /
// target), health colour + glow, and animated traffic-flow links. OVERLAY MODEL:
// the path STRUCTURE comes from data — a live traceroute when one matches the
// destination (true hop order, both icmp+tcp), else the correlation object's own
// entities — and RCA ANNOTATES where it's broken / suspected / possible. We never
// invent a hop order we can't prove.

type FaultStatus = "broken" | "suspected" | "possible";

const STATUS_META: Record<FaultStatus, { sym: string; word: string; color: string }> = {
  broken: { sym: "❌", word: "Broken", color: C.crit },
  suspected: { sym: "⚠", word: "Suspected", color: C.warn },
  possible: { sym: "?", word: "Possible", color: C.caution },
};

function statusForVerdict(tier: string): FaultStatus {
  return tier === "confirmed" ? "broken" : tier === "suspected" ? "suspected" : "possible";
}

function splitPath(id: string): { src: string; dst: string } | null {
  if (!id.includes("->")) return null;
  const [src, dst] = id.split("->");
  return { src: (src || "").trim(), dst: (dst || "").trim() };
}

// Base device an entity sits on: interface "dev:Gi0/1" → "dev"; device → itself.
function baseDevice(entityType: string, entityId: string): string {
  if (entityType === "interface") return entityId.split(":")[0];
  if (entityType === "path") return entityId;
  return entityId.split(":")[0];
}

function brokenElement(s: CorrSignal): string {
  if (s.entity_type === "interface") {
    const iface = s.entity_id.split(":").slice(1).join(":");
    return `${iface || "interface"} · ${kindLabel(s.kind)}`;
  }
  return kindLabel(s.kind);
}

function parseAttrs(s?: string): Record<string, any> {
  try { return JSON.parse(s || "{}"); } catch { return {}; }
}

const SEV_RANK: Record<string, number> = { crit: 4, high: 3, warn: 2, info: 1 };
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

const COL = 200;
const COL_HOP = 168;
const TRACE_LOSS_HI = 2;

// destination kind: cloud/internet/transit → cloud; an IP/host → target bullseye.
function destKind(dst: string): ShapeKind {
  if (/cloud|internet|inet|aws|azure|gcp|tgw|transit|saas/i.test(dst)) return "cloud";
  return "target";
}

function matchTraces(dst: string | undefined, paths?: ProbePath[]): ProbePath[] {
  if (!dst || !paths?.length) return [];
  const d = dst.trim();
  const withHops = paths.filter((p) => (p.hops?.length ?? 0) > 0);
  let m = withHops.filter((p) => p.dst === d);
  if (m.length === 0) m = withHops.filter((p) => p.dst && (p.dst.includes(d) || d.includes(p.dst)));
  const byMethod = new Map<string, ProbePath>();
  for (const p of m) {
    const k = (p.method || "icmp").toLowerCase();
    if (!byMethod.has(k)) byMethod.set(k, p);
  }
  return [...byMethod.values()];
}

function groupBySignature(traces: ProbePath[]): { methods: string[]; trace: ProbePath }[] {
  const groups = new Map<string, { methods: string[]; trace: ProbePath }>();
  for (const t of traces) {
    const sig = (t.hops ?? []).map((h) => h.ip).join(">");
    const g = groups.get(sig);
    const method = (t.method || "icmp").toLowerCase();
    if (g) g.methods.push(method);
    else groups.set(sig, { methods: [method], trace: t });
  }
  return [...groups.values()];
}

const methodTag = (methods: string[]): string =>
  methods.map((m) => (m === "auto" ? "ICMP→TCP" : m.toUpperCase())).join(" · ");

export default function RcaTopology({ timeline, seams, view = "operator", height = 320, probePaths, deviceByIp }: {
  timeline: CorrTimeline;
  seams: Record<string, Seam>;
  view?: "operator" | "debug";
  height?: number;
  probePaths?: ProbePath[];
  deviceByIp?: Record<string, string>;
}) {
  const model = useMemo(() => {
    const sigs = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
    const pathSig = sigs.find((s) => s.entity_type === "path" && s.is_trigger)
      ?? sigs.find((s) => s.entity_type === "path");
    const ends = pathSig ? splitPath(pathSig.entity_id) : null;

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
    // label = a real metric only (loss %). No "latency rise"/"degraded" filler on
    // the arrow — the edge COLOUR already conveys degraded; text stays meaningful.
    const lossTxt = isFinite(lossPct) && lossPct > 0 ? `${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss` : "";
    const measuredDegraded = (isFinite(lossPct) && lossPct > 0) || pathSigs.some((x) => /rtt|latency/.test(x.kind));
    const stampParts: string[] = [];
    if (isFinite(lossPct) && lossPct > 0) stampParts.push(`${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss`);
    if (isFinite(rttMs)) stampParts.push(`${rttMs.toFixed(rttMs < 10 ? 2 : 1)} ms rtt`);
    if (isFinite(jitterMs)) stampParts.push(`${jitterMs.toFixed(2)} ms jitter`);
    const stampTxt = stampParts.join("  ·  ");
    const hasStamp = stampParts.length > 0;

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

    // CONTROL-PLANE PEER (the "total path" when there is no probe): a BGP/peer
    // signal names the far end (attrs.peer, or entity_id "device:peer"). That peer
    // IS the other end of the path segment — so a BGP flap draws device → peer,
    // not a lone node.
    const peer = (() => {
      for (const s of sigs) {
        if (!/bgp|peer|adjacency|neighbor|ldp|ospf|isis/i.test(s.kind)) continue;
        const a = parseAttrs(s.attrs);
        let p = (a.peer || a.neighbor || "") as string;
        if (!p && s.entity_id.includes(":")) p = s.entity_id.split(":").slice(1).join(":");
        if (p) return { peer: p, rel: /bgp/i.test(s.kind) ? "BGP session" : "Peering", state: (a.state || "") as string };
      }
      return undefined;
    })();

    const seamEdge = (timeline.edges ?? []).find((e) => e.grounding_kind === "seam");
    const seam = seamEdge ? seams[seamEdge.grounding_ref] : undefined;

    const tracedRows = groupBySignature(matchTraces(ends?.dst, probePaths));

    // DECISION #76 — platform services (api/clickhouse/netbox=Inventory service…)
    // and monitoring agents (prober/stamp/reflector) are how we OBSERVE, not the
    // customer network. Drop them from the path; keep only real network entities
    // (hosts/routers/switches/firewalls/WAN/ISP/cloud/IP endpoints). If NOTHING
    // customer-facing remains, it's a platform self-monitoring object → render an
    // "Internal monitoring path" note instead of a fake customer path.
    for (const k of [...devs.keys()]) if (isInternalEntity(k)) devs.delete(k);
    const cleanEnds = ends ? {
      src: isInternalEntity(ends.src) ? "" : ends.src,
      dst: isInternalEntity(ends.dst) ? "" : ends.dst,
    } : null;
    const cleanPeer = peer && !isInternalEntity(peer.peer) ? peer : undefined;
    if (locusDev && isInternalEntity(locusDev)) locusDev = "";
    const networkCount = devs.size + (cleanEnds?.src ? 1 : 0) + (cleanEnds?.dst ? 1 : 0) + (cleanPeer ? 1 : 0);
    const internal = networkCount === 0;

    return { ends: cleanEnds, lossTxt, measuredDegraded, stampTxt, hasStamp, devs, locusDev, seam, peer: cleanPeer, tracedRows, internal, hasPath: !!ends };
  }, [timeline, seams, probePaths]);

  const [showStamp, setShowStamp] = useState(false);

  const { rfNodes, rfEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const meta = STATUS_META[statusForVerdict(timeline.verdict_tier)];
    const { ends, lossTxt, measuredDegraded, stampTxt, devs, locusDev, seam, peer, tracedRows } = model;
    const measuredLabel = showStamp && stampTxt ? stampTxt : lossTxt;
    const hopName = (ip: string): string | undefined => (ip ? deviceByIp?.[ip] : undefined);

    const locus = locusDev ? (devs.get(locusDev) ?? { dev: locusDev, elements: [], worst: 0 }) : undefined;
    const targetIsLocus = !!(ends && locus && ends.dst === locus.dev);

    // verdict → the state of the segment that carries the fault.
    const faultEdgeState = statusForVerdict(timeline.verdict_tier) === "broken" ? "confirmed_down" : "suspected_down";
    const node = (n: Partial<Node> & { id: string; data: any; x: number; y: number }) =>
      nodes.push({ id: n.id, type: "topo", position: { x: n.x, y: n.y }, draggable: true, data: n.data });
    type ES = "healthy" | "degraded" | "suspected_down" | "confirmed_down" | "unknown";
    const stateColor = (s: ES) =>
      s === "confirmed_down" || s === "suspected_down" ? meta.color
      : s === "degraded" ? C.warn : s === "unknown" ? C.faint : "#5a93c2";
    const link = (from: string, to: string, o: { state?: ES; label?: string; flow?: boolean; fromHandle?: string } = {}) => {
      const state: ES = o.state ?? "healthy";
      const color = stateColor(state);
      const down = state === "suspected_down" || state === "confirmed_down";
      edges.push({
        id: `${from}~${to}`, source: from, target: to, sourceHandle: o.fromHandle, type: "flow",
        label: o.label, markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
        data: { flow: o.flow !== false, state, particles: state === "degraded" ? 4 : 2, speed: state === "degraded" ? 1.8 : 3.0 },
        style: { stroke: color, strokeWidth: down || state === "degraded" ? 2.8 : 1.8, opacity: 0.95 },
      });
    };

    // ===== TRACED MODE: real hop chain(s) from live traceroute ================
    if (tracedRows.length > 0 && ends) {
      const ROW_H = 168;
      const centerY = ((tracedRows.length - 1) * ROW_H) / 2;
      // observer shown only when it's a real customer vantage (a platform/agent
      // source was dropped by the #76 filter → start at the first hop).
      const hasObserver = !!ends.src;
      if (hasObserver) {
        node({ id: "src", x: 0, y: centerY, data: { kind: "vantage", tone: C.info, label: entityLabel(ends.src), sub: "observed from here", hasIn: false } });
      }

      tracedRows.forEach((row, r) => {
        const yBase = r * ROW_H;
        const hops = [...(row.trace.hops ?? [])].sort((a, b) => a.ttl - b.ttl);
        if (hops.length === 0) return;
        const tag = methodTag(row.methods);
        let faultIdx = hops.findIndex((h) => h.ip && locusDev && (h.ip === locusDev || hopName(h.ip) === locusDev));
        if (faultIdx < 0) faultIdx = hops.length - 1;
        let prev = hasObserver ? "src" : "";
        hops.forEach((h, i) => {
          const id = `r${r}h${i}`;
          const isLast = i === hops.length - 1;
          const lossHi = Number(h.loss_pct) > TRACE_LOSS_HI;
          const rtt = Number(h.rtt_ms);
          const ip = h.ip && h.ip !== "" ? h.ip : "*";
          const name = hopName(ip);
          const isFault = i === faultIdx;
          const metric = showStamp && isFinite(rtt) ? `${rtt.toFixed(rtt < 10 ? 2 : 1)} ms${lossHi ? ` · ${Math.round(Number(h.loss_pct))}% loss` : ""}`
            : lossHi ? `${Math.round(Number(h.loss_pct))}% loss` : undefined;
          const kind: ShapeKind = isLast ? destKind(ip) : isFault ? kindForRole(name ?? ip) : "router";
          node({
            id, x: (i + 1) * COL_HOP, y: yBase,
            data: {
              kind, tone: isFault ? meta.color : isLast ? C.info : C.flow, pulse: isFault,
              label: name ?? ip, mono: !name,
              sub: [isLast ? "destination" : `hop ${h.ttl}`, name ? ip : "", metric].filter(Boolean).join(" · ") || undefined,
              badge: isFault ? `${meta.sym} ${meta.word}` : undefined,
              chips: isFault ? (locus?.elements ?? []).slice(0, 3) : undefined,
              via: h.via,
            },
          });
          const firstLabel = [tag, measuredLabel].filter(Boolean).join(" · ");
          const segLabel = i === 0 ? firstLabel
            : showStamp && isFinite(rtt) ? `${rtt.toFixed(rtt < 10 ? 2 : 1)} ms`
            : lossHi ? `${Math.round(Number(h.loss_pct))}% loss` : undefined;
          if (prev) link(prev, id, { state: isFault ? faultEdgeState : lossHi ? "degraded" : "healthy", label: segLabel, flow: true });
          prev = id;
        });
      });
      return { rfNodes: nodes, rfEdges: edges };
    }

    // ===== CONTEXTUAL MODE: placement from RCA evidence =======================
    let col = 0;
    let prev: string | null = null;

    if (ends?.src) {
      node({ id: "src", x: col * COL, y: 0, data: { kind: "vantage", tone: C.info, label: entityLabel(ends.src), sub: "observed from here", hasIn: false } });
      prev = "src"; col++;
    }

    if (seam) {
      const vis = seam.visibility ?? "";
      const ownerColor = seamOwnerColor(seam.control_plane_owner);
      node({ id: "seam", x: col * COL, y: 0, data: {
        kind: "gateway", tone: ownerColor,
        label: view === "debug" ? (seam.seam_id || "boundary") : (seam.display_name || "Provider boundary"),
        sub: `${view === "debug" ? (seam.control_plane_owner ?? "?") : seamOwnerLabel(seam.control_plane_owner)}${vis ? " · " + (view === "debug" ? vis : visibilityLabel(seam.visibility)) : ""}`,
      } });
      if (prev) link(prev, "seam", { state: measuredDegraded ? "degraded" : "healthy", label: prev === "src" ? measuredLabel : undefined });
      prev = "seam"; col++;
    }

    if (locus) {
      node({ id: "fault", x: col * COL, y: 0, data: {
        kind: kindForRole(locus.dev), tone: meta.color, pulse: true, size: 62,
        label: entityLabel(locus.dev), badge: `${meta.sym} ${meta.word}${targetIsLocus ? " · dest" : ""}`,
        chips: locus.elements.slice(0, 4), hasBottom: true,
      } });
      if (prev) link(prev, "fault", { state: measuredDegraded ? "degraded" : "healthy", label: prev === "src" ? measuredLabel : undefined });
      prev = "fault"; col++;

      // co-affected devices branch below the locus
      const others = [...devs.values()].filter((d) => d.dev !== locus.dev);
      others.slice(0, 4).forEach((d, i) => {
        const aid = `aff${i}`;
        node({ id: aid, x: (col - 1) * COL + (i - (others.length - 1) / 2) * 140, y: 150, data: {
          kind: kindForRole(d.dev), tone: C.warn, label: entityLabel(d.dev), sub: "also affected", hasIn: true, hasOut: false,
        } });
        nodes[nodes.length - 1].data.hasIn = true;
        link("fault", aid, { fromHandle: "b", state: "unknown", flow: false });
      });
    }

    // CONTROL-PLANE PEER: the far end of a BGP/peering session = the rest of the
    // path (fixes "lone WAN-R2" — a flap is device → peer, the total segment).
    if (peer && !ends?.dst) {
      const down = /down|idle|active|flap/i.test(peer.state);
      node({ id: "peer", x: col * COL, y: 0, data: {
        kind: "router", tone: down ? meta.color : C.info, label: peer.peer, mono: true, sub: `${peer.rel.toLowerCase()} peer`, hasOut: false,
      } });
      if (prev) link(prev, "peer", { state: down ? faultEdgeState : "healthy", label: `${peer.rel}${peer.state ? " " + peer.state : ""}` });
      prev = "peer"; col++;
    } else if (ends?.dst && ends.dst !== locusDev) {
      node({ id: "dst", x: col * COL, y: 0, data: { kind: destKind(ends.dst), tone: C.info, label: entityLabel(ends.dst), sub: "destination", hasOut: false } });
      if (prev) link(prev, "dst", {});
    }

    return { rfNodes: nodes, rfEdges: edges };
  }, [model, timeline.verdict_tier, view, showStamp, deviceByIp]);

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
        nodesConnectable={false} elementsSelectable={false} nodesDraggable
        minZoom={0.3} maxZoom={1.6} zoomOnScroll={false} panOnScroll
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
          return <span style={{ color: live ? C.ok : C.faint }}>{live ? `● live trace (${methodTag([...new Set(methods)])})` : "contextual path"}</span>;
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
