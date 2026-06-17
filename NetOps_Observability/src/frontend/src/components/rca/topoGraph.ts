import { CorrTimeline, CorrSignal, Seam, ProbePath } from "../../services/api";
import { C, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, seamOwnerColor, isInternalEntity } from "./labels";
import { kindForRole, type ShapeKind } from "../graph/shapes";

// topoGraph.ts — the ONE shared model+layout builder for the RCA Network-Path
// topology. Both renderers consume it: the on-screen React Flow canvas
// (RcaTopology.tsx) and the print-ready PDF (rcaExport.ts). It emits
// renderer-agnostic nodes (with x/y positions + a data bag) and edges (from/to +
// state + label), so the two surfaces draw the SAME graph (same nodes, edges,
// layout) from a single code path — no more divergence from two builders.
//
// OVERLAY MODEL (unchanged): the path STRUCTURE comes from data — a live
// traceroute when one matches the destination (true hop order, both icmp+tcp),
// else the correlation object's own entities — and RCA ANNOTATES where it's
// broken / suspected / possible. We never invent a hop order we can't prove.

export type FaultStatus = "broken" | "suspected" | "possible";
export type EdgeState = "healthy" | "degraded" | "suspected_down" | "confirmed_down" | "unknown";

export const STATUS_META: Record<FaultStatus, { sym: string; word: string; color: string }> = {
  broken: { sym: "❌", word: "Broken", color: C.crit },
  suspected: { sym: "⚠", word: "Suspected", color: C.warn },
  possible: { sym: "?", word: "Possible", color: C.caution },
};

export function statusForVerdict(tier: string): FaultStatus {
  return tier === "confirmed" ? "broken" : tier === "suspected" ? "suspected" : "possible";
}

// renderer-agnostic node — data bag mirrors the on-screen TopoNode (RcaTopology):
// { kind, tone, label, sub, badge, chips[], via, pulse, mono, size, hasIn, hasOut,
//   hasBottom }. x/y are absolute canvas positions.
export interface TopoGraphNodeData {
  kind: ShapeKind;
  tone: string;
  pulse?: boolean;
  label: string;
  sub?: string;
  badge?: string;
  chips?: string[];
  mono?: boolean;
  via?: string;
  hasIn?: boolean;
  hasOut?: boolean;
  hasBottom?: boolean;
  size?: number;
}
export interface TopoGraphNode { id: string; x: number; y: number; data: TopoGraphNodeData; }
// fromHandle = the source-side handle id (e.g. "b" for the bottom branch handle);
// undefined → the default right-side source. state drives edge colour/dashing.
export interface TopoGraphEdge { from: string; to: string; state: EdgeState; label?: string; fromHandle?: string; }
export interface TopoGraph { nodes: TopoGraphNode[]; edges: TopoGraphEdge[]; internal: boolean; }

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

// What kind of evidence a signal is, for the fault's "what's broken" chips. The
// physical/control-plane cause (link down, BGP/routing) outranks device-resource
// (CPU/mem) — which is usually a SYMPTOM or co-occurrence, not the cause. The end-
// to-end path leads with the real cause and drops resource noise when a stronger
// signal is present, so a BGP flap reads as link/BGP, not "high CPU".
function elementRank(kind: string): number {
  if (/link_state|interface|carrier|los|fcs/i.test(kind)) return 5;
  if (/bgp|adjacency|peer|ospf|isis|ldp|route/i.test(kind)) return 4;
  if (/flow|traffic|discard|drop/i.test(kind)) return 2;
  if (/resource|cpu|mem|temperat|fan|power|disk/i.test(kind)) return 1;
  return 3;
}
type RankedEl = { label: string; rank: number };
function faultEls(d?: { els: RankedEl[] }): string[] {
  if (!d) return [];
  const strong = d.els.some((e) => e.rank >= 4);
  return d.els.filter((e) => !strong || e.rank >= 2).sort((a, b) => b.rank - a.rank).map((e) => e.label);
}

const SEV_RANK: Record<string, number> = { crit: 4, high: 3, warn: 2, info: 1 };

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

export const methodTag = (methods: string[]): string =>
  methods.map((m) => (m === "auto" ? "ICMP→TCP" : m.toUpperCase())).join(" · ");

// computeModel — the evidence-derived model (formerly RcaTopology's first
// useMemo). Returns the ends/loss/stamp/devices/locus/seam/peer/traces + the #76
// internal flag. Kept VERBATIM from the on-screen component. Exported so the
// on-screen component can drive its legend / STAMP toggle / empty-states from the
// same model the graph is built from (single source of truth).
export function computeTopoModel(timeline: CorrTimeline, seams: Record<string, Seam>, probePaths?: ProbePath[]) {
  return computeModel(timeline, seams, false, probePaths);
}
function computeModel(timeline: CorrTimeline, seams: Record<string, Seam>, showStamp: boolean, probePaths?: ProbePath[]) {
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

  type Dev = { dev: string; els: RankedEl[]; worst: number };
  const devs = new Map<string, Dev>();
  for (const s of sigs) {
    if (s.entity_type === "path") continue;
    const dev = baseDevice(s.entity_type, s.entity_id);
    if (!dev) continue;
    const d = devs.get(dev) ?? { dev, els: [], worst: 0 };
    const label = brokenElement(s);
    if (!d.els.some((x) => x.label === label)) d.els.push({ label, rank: elementRank(s.kind) });
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

  // showStamp affects the on-canvas metric labels (loss-only vs full STAMP line).
  void showStamp;
  return { ends: cleanEnds, lossTxt, measuredDegraded, stampTxt, hasStamp, devs, locusDev, seam, peer: cleanPeer, tracedRows, internal, hasPath: !!ends };
}

// buildTopoGraph — PURE: evidence → positioned nodes + edges. Both renderers
// consume this; the on-screen graph maps nodes→React-Flow and edges→its `link`
// builder, and the PDF lays out the same nodes/edges. The construction logic
// (traced + contextual modes, locus, seam, peer, traced hops, colours, positions)
// is moved VERBATIM from RcaTopology's second useMemo.
export function buildTopoGraph(
  timeline: CorrTimeline,
  seams: Record<string, Seam>,
  view: "operator" | "debug",
  showStamp: boolean,
  probePaths?: ProbePath[],
  deviceByIp?: Record<string, string>,
): TopoGraph {
  const model = computeModel(timeline, seams, showStamp, probePaths);
  const nodes: TopoGraphNode[] = [];
  const edges: TopoGraphEdge[] = [];

  if (model.internal) return { nodes, edges, internal: true };

  const meta = STATUS_META[statusForVerdict(timeline.verdict_tier)];
  const { ends, lossTxt, measuredDegraded, stampTxt, devs, locusDev, seam, peer, tracedRows } = model;
  const measuredLabel = showStamp && stampTxt ? stampTxt : lossTxt;
  const hopName = (ip: string): string | undefined => (ip ? deviceByIp?.[ip] : undefined);

  const locus = locusDev ? (devs.get(locusDev) ?? { dev: locusDev, els: [], worst: 0 }) : undefined;
  const targetIsLocus = !!(ends && locus && ends.dst === locus.dev);

  // verdict → the state of the segment that carries the fault.
  const faultEdgeState: EdgeState = statusForVerdict(timeline.verdict_tier) === "broken" ? "confirmed_down" : "suspected_down";
  const node = (n: { id: string; data: TopoGraphNodeData; x: number; y: number }) =>
    nodes.push({ id: n.id, x: n.x, y: n.y, data: n.data });
  const link = (from: string, to: string, o: { state?: EdgeState; label?: string; fromHandle?: string } = {}) => {
    const state: EdgeState = o.state ?? "healthy";
    edges.push({ from, to, state, label: o.label, fromHandle: o.fromHandle });
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
        // hostname preference: rDNS host (from the trace) → inventory name → IP.
        const name = h.host || hopName(ip);
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
            chips: isFault ? faultEls(locus).slice(0, 3) : undefined,
            via: h.via,
          },
        });
        const firstLabel = [tag, measuredLabel].filter(Boolean).join(" · ");
        const segLabel = i === 0 ? firstLabel
          : showStamp && isFinite(rtt) ? `${rtt.toFixed(rtt < 10 ? 2 : 1)} ms`
          : lossHi ? `${Math.round(Number(h.loss_pct))}% loss` : undefined;
        if (prev) link(prev, id, { state: isFault ? faultEdgeState : lossHi ? "degraded" : "healthy", label: segLabel });
        prev = id;
      });
    });
    return { nodes, edges, internal: false };
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
      chips: faultEls(locus).slice(0, 4), hasBottom: true,
    } });
    if (prev) link(prev, "fault", { state: measuredDegraded ? "degraded" : "healthy", label: prev === "src" ? measuredLabel : undefined });
    prev = "fault"; col++;

    // co-affected devices branch below the locus
    const others = [...devs.values()].filter((d) => d.dev !== locus.dev);
    others.slice(0, 4).forEach((d, i) => {
      const aid = `aff${i}`;
      node({ id: aid, x: (col - 1) * COL + (i - (others.length - 1) / 2) * 140, y: 150, data: {
        kind: kindForRole(d.dev), tone: C.warn, label: entityLabel(d.dev), sub: faultEls(d)[0] || "also affected", hasIn: true, hasOut: false,
      } });
      link("fault", aid, { fromHandle: "b", state: "unknown" });
    });
  }

  // CONTROL-PLANE PEER: the far end of a BGP/peering session = the rest of the
  // path (fixes "lone WAN-R2" — a flap is device → peer, the total segment).
  if (peer && !ends?.dst) {
    const down = /down|idle|active|flap/i.test(peer.state);
    node({ id: "peer", x: col * COL, y: 0, data: {
      kind: "router", tone: down ? meta.color : C.info, label: peer.peer, mono: true, sub: `${peer.rel.toLowerCase()} peer`, hasOut: false,
    } });
    // Label the edge by the EVENT, not the current session state: this object
    // exists because the adjacency CHANGED, so "BGP session up" would read as
    // misleadingly healthy. Edge carries the verdict tone (suspected = amber),
    // never a healthy green, but stays unbroken unless the overlay is down.
    if (prev) link(prev, "peer", { state: down ? faultEdgeState : (timeline.verdict_tier === "confirmed" ? "healthy" : "degraded"), label: /bgp/i.test(peer.rel) ? "BGP neighbor changed" : `${peer.rel} changed` });
    prev = "peer"; col++;
  } else if (ends?.dst && ends.dst !== locusDev) {
    node({ id: "dst", x: col * COL, y: 0, data: { kind: destKind(ends.dst), tone: C.info, label: entityLabel(ends.dst), sub: "destination", hasOut: false } });
    if (prev) link(prev, "dst", {});
  }

  return { nodes, edges, internal: false };
}
