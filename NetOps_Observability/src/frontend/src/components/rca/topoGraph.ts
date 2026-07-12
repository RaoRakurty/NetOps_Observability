import { CorrTimeline, CorrSignal, Seam } from "../../services/api";
import { C, entityLabel, kindLabel, seamOwnerLabel, visibilityLabel, seamOwnerColor, isInternalEntity } from "./labels";
import { kindForRole, type ShapeKind } from "../graph/shapes";
import {
  readServicePath, isPathFocused, transformationLabel, spineKindLabel, hopStateLabel,
  type ServicePath, type SpineNode, type SpineKind, type SpineEvidence,
} from "./servicePath";

// topoGraph.ts — the ONE shared model+layout builder for the RCA path topology.
// Both renderers consume it: the on-screen React Flow canvas (RcaTopology.tsx) and
// the print-ready PDF (rcaExport.ts). It emits renderer-agnostic nodes (with x/y +
// a data bag), edges and boundary bands, so the two surfaces draw the SAME graph.
//
// ═══ THE CONTRACT (docs/design/service-path-graph-contract.md §7) ═══════════════
// THE BACKEND, NOT REACT, DETERMINES HOP ORDER. When the RCA object carries a
// service path, this file is a DUMB LAYOUT of the backend's ordered spine:
//   · walk `index` left→right — no reordering, no degree math, no star fallback;
//   · group hops into LAN / SD-WAN / CARRIER / CLOUD boundary bands from
//     `boundaries[]` (computed server-side);
//   · preserve `missing`/`filtered` hops as explicit UNKNOWN segments;
//   · mark NAT / proxy / load-balancer / tunnel transformations;
//   · attach metrics/logs/flows/alerts/traces as evidence branches OFF the spine;
//   · render NO edge that cannot state its evidence (§5).
// A path-focused object with NO spine renders an honest empty state — we never
// invent a path (that empty state is decided by the caller from `mode: "empty"`).
//
// Network-only objects (device / interface / routing evidence, no path) keep the
// CONTEXT view: the affected device area and its ownership boundary. That view is
// placed from SEVERITY and the object's own declared relations — never from node
// degree, and it is never used for a path-focused object.

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

// renderer-agnostic node — data bag mirrors the on-screen TopoNode (RcaTopology).
// x/y are absolute canvas positions.
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
  // ── contract fields (surfaced on hover/inspect; §5/§7) ──
  hopIndex?: number;
  boundary?: string;
  entityRef?: string;
  address?: string;
  hopState?: string;          // responding | missing | filtered
  transformation?: string;    // operator label ("NAT", "Tunnel start", …)
  evidence?: SpineEvidence;   // ref · method · confidence · observed_at · data_class
  branchOf?: number;          // set on evidence-branch nodes: the hop they annotate
  title?: string;             // native tooltip line
}
export interface TopoGraphNode { id: string; x: number; y: number; data: TopoGraphNodeData; }
// fromHandle = the source-side handle id (e.g. "b" for the bottom branch handle);
// undefined → the default right-side source. state drives edge colour/dashing.
export interface TopoGraphEdge {
  from: string; to: string; state: EdgeState; label?: string; fromHandle?: string;
  // Contract §5 — EVERY displayed edge exposes its evidence. An edge that cannot
  // state its evidence never gets built (see layoutSpine / readServicePath).
  evidence?: SpineEvidence;
  type?: string;              // PATH_HAS_HOP | CROSSES_SEAM | EVIDENCE_SUPPORTS | …
  transformation?: string;
  seamId?: string;
  title?: string;
}
// A boundary band (LAN / SD-WAN / CARRIER / CLOUD) drawn BEHIND the flat spine.
// Geometry is computed here so the canvas and the PDF band identically.
export interface TopoGraphBand {
  name: string; color: string;
  from: number; to: number;        // spine indexes
  fromId: string; toId: string;    // the node ids at each end
  x: number; y: number; width: number; height: number;
}
export type TopoMode = "spine" | "context" | "internal" | "empty";
export interface TopoGraph {
  nodes: TopoGraphNode[];
  edges: TopoGraphEdge[];
  internal: boolean;
  mode: TopoMode;
  bands: TopoGraphBand[];
  path?: ServicePath;   // the backend spine this layout came from (mode === "spine")
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
// (CPU/mem) — which is usually a SYMPTOM or co-occurrence, not the cause.
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

const COL = 200;          // context-mode column pitch
const COL_SPINE = 200;    // spine hop pitch — x is a PURE FUNCTION of hop_index
const NODE_W = 124;       // TopoNode width (shape centred in it)
const BAND_PAD = 26;
const BAND_Y = -86;
const BAND_H = 246;
const BAND_INSET = 11;    // nesting step for overlapping boundary bands
const BRANCH_Y = 176;     // evidence branches hang BELOW the spine (never in it)
const BRANCH_ROW_H = 118;
const BRANCH_PITCH = 152;

// ═══ SPINE LAYOUT ══════════════════════════════════════════════════════════════

// hop kind → device shape. A hop that did not respond is ALWAYS the blind
// "unknown" shape regardless of its declared kind.
const SPINE_SHAPE: Record<SpineKind, ShapeKind> = {
  client: "server",
  lan_gateway: "router",
  wan_edge: "gateway",
  nva: "firewall",
  cloud_edge: "gateway",
  app_endpoint: "server",
  service_endpoint: "server",
  application: "cloud",
  transit: "router",
  unknown: "unknown",
};
function hopShape(n: SpineNode): ShapeKind {
  if (n.state !== "responding") return "unknown";
  return SPINE_SHAPE[n.kind] ?? "unknown";
}

// boundary name → owner tint. Reuses the ONE seam colour source (labels.ts) so a
// band, a seam node and the seam graph all say "whose domain" in the same hue.
export function boundaryOwner(name: string): string {
  const n = (name || "").toLowerCase();
  if (/lan|enterprise|campus|branch|internal/.test(n)) return "enterprise";
  if (/sd-?wan|overlay|fabric/.test(n)) return "sdwan_controller";
  if (/carrier|mpls|middle-?mile|transit/.test(n)) return "carrier";
  if (/isp|internet|dia/.test(n)) return "isp";
  if (/cloud|aws|azure|gcp|vpc|vnet/.test(n)) return "cloud";
  if (/colo|dc|data ?cent/.test(n)) return "colo";
  return "unknown";
}
export function boundaryColor(name: string): string {
  return seamOwnerColor(boundaryOwner(name));
}

const BRANCH_TONE: Record<string, string> = {
  metrics: C.info, logs: C.warn, flows: C.flow, alerts: C.crit, traces: C.discriminates,
};

const evidenceTitle = (e?: SpineEvidence): string | undefined =>
  e ? `evidence ${e.ref} · ${e.method} · ${e.confidence}${e.observed_at ? ` · ${e.observed_at}` : ""}${e.data_class !== "live" ? ` · ${e.data_class}` : ""}` : undefined;

// layoutSpine — the DUMB, deterministic layout of the backend-ordered spine.
// x = f(hop_index) only. It reorders nothing, infers nothing, and drops nothing:
// an unknown hop keeps its slot, and an edge without evidence is simply absent
// (readServicePath already refused it).
export function layoutSpine(path: ServicePath, verdictTier = ""): TopoGraph {
  const nodes: TopoGraphNode[] = [];
  const edges: TopoGraphEdge[] = [];
  const bands: TopoGraphBand[] = [];
  const meta = STATUS_META[statusForVerdict(verdictTier)];
  const byIndex = new Map<number, SpineNode>();
  const id = (index: number) => `h${index}`;

  const branchesByHop = new Map<number, number>();
  for (const b of path.evidence_branches) branchesByHop.set(b.attach_index, (branchesByHop.get(b.attach_index) ?? 0) + 1);

  // ── the spine itself: ONE node per hop, positioned by its index ──
  for (const n of path.spine) {
    byIndex.set(n.index, n);
    const blind = n.state !== "responding";
    const faulted = !!n.fault;
    const fmeta = n.fault ? STATUS_META[n.fault] : meta;
    const transform = transformationLabel(n.transformation);
    const tone = blind ? C.faint
      : faulted ? fmeta.color
      : n.kind === "client" || n.kind === "application" || n.kind === "app_endpoint" || n.kind === "service_endpoint" ? C.info
      : C.flow;
    const chips = [
      transform,
      (n.repeat_count ?? 0) > 1
        ? (blind ? `no response for ${n.repeat_count} hops` : `answered ${n.repeat_count} probes in a row`)
        : "",
    ].filter(Boolean) as string[];
    const sub = [
      spineKindLabel(n.kind),
      n.address && n.address !== n.label ? n.address : "",
      blind ? hopStateLabel(n.state) : "",
      typeof n.rtt_ms === "number" ? `${n.rtt_ms.toFixed(n.rtt_ms < 10 ? 2 : 1)} ms` : "",
    ].filter(Boolean).join(" · ");
    nodes.push({
      id: id(n.index), x: n.index * COL_SPINE, y: 0,
      data: {
        kind: hopShape(n), tone, pulse: faulted,
        // A silent hop with no identity renders as "Unknown hop" — but a KNOWN
        // endpoint that didn't answer keeps its name (the application the run
        // proved unreachable is the headline, not a mystery).
        label: blind && !n.address && n.kind === "unknown" ? "Unknown hop" : n.label,
        mono: !!n.address && n.address === n.label,
        sub: sub || undefined,
        badge: faulted ? `${fmeta.sym} ${fmeta.word}` : undefined,
        chips: chips.length ? chips : undefined,
        hasIn: n.index !== path.spine[0]?.index,
        hasOut: true,
        hasBottom: (branchesByHop.get(n.index) ?? 0) > 0,
        hopIndex: n.index,
        boundary: n.boundary,
        entityRef: n.entity_ref,
        address: n.address,
        hopState: n.state,
        transformation: transform || undefined,
        evidence: n.evidence,
        title: evidenceTitle(n.evidence),
      },
    });
  }

  // ── segments: ONLY the backend's declared, evidenced edges (§5) ──
  for (const e of path.edges) {
    const a = byIndex.get(e.from), b = byIndex.get(e.to);
    if (!a || !b) continue;
    const blind = a.state !== "responding" || b.state !== "responding";
    const state: EdgeState = e.state ?? (blind ? "unknown" : "healthy");
    const transform = transformationLabel(e.transformation);
    edges.push({
      from: id(e.from), to: id(e.to), state,
      label: transform || undefined,
      evidence: e.evidence,
      type: e.type,
      transformation: transform || undefined,
      seamId: e.seam_id,
      title: evidenceTitle(e.evidence),
    });
  }

  // ── boundary bands: LAN / SD-WAN / CARRIER / CLOUD, behind the flat spine ──
  // Boundaries legitimately OVERLAP (the contract's own §7 example has SD-WAN 2→2
  // inside CARRIER 2→3: a hop can sit on the overlay AND the carrier underneath).
  // Overlapping bands are nested into lanes so both stay readable — the grouping
  // itself is the backend's, we only draw it.
  const placed: { from: number; to: number; lane: number }[] = [];
  for (const b of path.boundaries) {
    const from = Math.min(b.from, b.to), to = Math.max(b.from, b.to);
    let lane = 0;
    while (placed.some((p) => p.lane === lane && p.from <= to && from <= p.to)) lane++;
    placed.push({ from, to, lane });
    bands.push({
      name: b.name, color: boundaryColor(b.name),
      from, to, fromId: id(from), toId: id(to),
      x: from * COL_SPINE - BAND_PAD + lane * BAND_INSET,
      y: BAND_Y + lane * BAND_INSET,
      width: (to - from) * COL_SPINE + NODE_W + BAND_PAD * 2 - lane * BAND_INSET * 2,
      height: BAND_H - lane * BAND_INSET * 2,
    });
  }

  // ── evidence branches: metrics / logs / flows / alerts / traces hang BELOW the
  // hop they annotate. They never change a spine node's x/y (contract §7).
  const branchSeen = new Map<number, number>();
  for (const br of path.evidence_branches) {
    const hop = byIndex.get(br.attach_index);
    if (!hop) continue;
    const total = branchesByHop.get(br.attach_index) ?? 1;
    const seq = branchSeen.get(br.attach_index) ?? 0;
    branchSeen.set(br.attach_index, seq + 1);
    const col = seq % 2, row = Math.floor(seq / 2);
    const bid = `ev${br.attach_index}_${seq}`;
    const tone = BRANCH_TONE[br.class] ?? C.muted;
    nodes.push({
      id: bid,
      x: hop.index * COL_SPINE + (total > 1 ? (col - 0.5) * BRANCH_PITCH : 0),
      y: BRANCH_Y + row * BRANCH_ROW_H,
      data: {
        kind: "evidence", tone, label: br.label,
        sub: [br.summary, typeof br.count === "number" ? `${br.count}` : ""].filter(Boolean).join(" · ") || undefined,
        hasIn: true, hasOut: false,
        branchOf: br.attach_index,
        evidence: br.evidence,
        title: evidenceTitle(br.evidence),
      },
    });
    edges.push({
      from: id(br.attach_index), to: bid, fromHandle: "b", state: "unknown",
      evidence: br.evidence, type: "EVIDENCE_SUPPORTS", title: evidenceTitle(br.evidence),
    });
  }

  return { nodes, edges, bands, internal: false, mode: "spine", path };
}

// ═══ CONTEXT MODEL (network-only objects — no service path) ═════════════════════

// computeTopoModel — the evidence-derived model behind the on-screen overlays
// (legend, STAMP toggle, empty states). Exported so the component and the canvas
// are driven by ONE source of truth.
export function computeTopoModel(timeline: CorrTimeline, seams: Record<string, Seam>) {
  return computeModel(timeline, seams);
}
function computeModel(timeline: CorrTimeline, seams: Record<string, Seam>) {
  const sigs = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  const path = readServicePath(timeline);
  const pathFocused = isPathFocused(timeline);

  // Path METRICS (loss / RTT / jitter) are evidence, not structure — they label
  // the measurement, they never place a hop.
  const pathSigs = sigs.filter((s) => s.entity_type === "path");
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
  const lossTxt = isFinite(lossPct) && lossPct > 0 ? `${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss` : "";
  const measuredDegraded = (isFinite(lossPct) && lossPct > 0) || pathSigs.some((x) => /rtt|latency/.test(x.kind));
  const stampParts: string[] = [];
  if (isFinite(lossPct) && lossPct > 0) stampParts.push(`${lossPct < 10 ? lossPct.toFixed(1) : Math.round(lossPct)}% loss`);
  if (isFinite(rttMs)) stampParts.push(`${rttMs.toFixed(rttMs < 10 ? 2 : 1)} ms rtt`);
  if (isFinite(jitterMs)) stampParts.push(`${jitterMs.toFixed(2)} ms jitter`);
  const stampTxt = stampParts.join("  ·  ");
  const hasStamp = stampParts.length > 0;

  // Affected DEVICE AREA — devices and interfaces only. An app / cloud resource is
  // NOT bucketed onto a pseudo-device (that collapse is what produced the old
  // single-node star); those entities belong on the backend's spine.
  type Dev = { dev: string; els: RankedEl[]; worst: number };
  const devs = new Map<string, Dev>();
  for (const s of sigs) {
    if (s.entity_type !== "device" && s.entity_type !== "interface") continue;
    const dev = s.entity_type === "interface" ? s.entity_id.split(":")[0] : s.entity_id;
    if (!dev) continue;
    const d = devs.get(dev) ?? { dev, els: [], worst: 0 };
    const label = brokenElement(s);
    if (!d.els.some((x) => x.label === label)) d.els.push({ label, rank: elementRank(s.kind) });
    d.worst = Math.max(d.worst, SEV_RANK[s.severity] ?? 1);
    devs.set(dev, d);
  }
  // DECISION #76 — platform services / monitoring agents are how we OBSERVE, not
  // the customer network. Drop them from the view.
  for (const k of [...devs.keys()]) if (isInternalEntity(k)) devs.delete(k);

  // Fault locus = the WORST-SEVERITY affected device. Deliberately NOT the
  // highest-degree node: node-degree layout is forbidden (contract §7).
  const locusDev = [...devs.values()].sort((a, b) => b.worst - a.worst || a.dev.localeCompare(b.dev))[0]?.dev;

  // Routing far end — used ONLY when the device itself DECLARED its neighbour
  // (attrs.peer / attrs.neighbor). We no longer guess a peer out of an entity id.
  const peer = (() => {
    for (const s of sigs) {
      if (!/bgp|peer|adjacency|neighbor|ldp|ospf|isis/i.test(s.kind)) continue;
      const a = parseAttrs(s.attrs);
      const p = String(a.peer || a.neighbor || "").trim();
      if (p && !isInternalEntity(p)) {
        return { peer: p, rel: /bgp/i.test(s.kind) ? "BGP session" : "Peering", state: String(a.state || "") };
      }
    }
    return undefined;
  })();

  const seamEdge = (timeline.edges ?? []).find((e) => e.grounding_kind === "seam");
  const seam = seamEdge ? seams[seamEdge.grounding_ref] : undefined;

  // Platform self-monitoring object (every attached entity is our own infra) →
  // never dressed up as a customer path.
  const entities = sigs.map((s) => s.entity_id).filter(Boolean);
  const internal = !path && entities.length > 0 && entities.every(isInternalEntity);

  return { path, pathFocused, lossTxt, measuredDegraded, stampTxt, hasStamp, devs, locusDev, seam, peer, internal };
}

// buildTopoGraph — PURE: RCA object → positioned nodes + edges + bands. Both
// renderers consume this, so screen and PDF cannot diverge.
//   spine  → the backend's ordered service path (the ONLY path layout)
//   context→ network-only object: the affected device area + its boundary
//   empty  → path-focused but NO spine: the caller says so. We invent nothing.
export function buildTopoGraph(
  timeline: CorrTimeline,
  seams: Record<string, Seam>,
  view: "operator" | "debug",
  showStamp: boolean,
): TopoGraph {
  const model = computeModel(timeline, seams);
  const nodes: TopoGraphNode[] = [];
  const edges: TopoGraphEdge[] = [];

  // 1) THE BACKEND'S SPINE WINS. Screen and PDF both get it for free.
  if (model.path) return layoutSpine(model.path, timeline.verdict_tier);

  if (model.internal) return { nodes, edges, bands: [], internal: true, mode: "internal" };

  // 2) A path-focused object with no spine is an HONEST BLANK — not a star.
  if (model.pathFocused) return { nodes, edges, bands: [], internal: false, mode: "empty" };

  const meta = STATUS_META[statusForVerdict(timeline.verdict_tier)];
  const { measuredDegraded, devs, locusDev, seam, peer } = model;
  void showStamp;

  const locus = locusDev ? devs.get(locusDev) : undefined;
  if (!locus && !seam && !peer) return { nodes, edges, bands: [], internal: false, mode: "empty" };

  const faultEdgeState: EdgeState = statusForVerdict(timeline.verdict_tier) === "broken" ? "confirmed_down" : "suspected_down";
  const node = (n: TopoGraphNode) => nodes.push(n);
  const link = (from: string, to: string, o: { state?: EdgeState; label?: string; fromHandle?: string } = {}) => {
    edges.push({ from, to, state: o.state ?? "healthy", label: o.label, fromHandle: o.fromHandle });
  };

  // ===== CONTEXT MODE: the affected device area (network-only object) ==========
  let col = 0;
  let prev: string | null = null;

  if (seam) {
    const vis = seam.visibility ?? "";
    const ownerColor = seamOwnerColor(seam.control_plane_owner);
    node({ id: "seam", x: col * COL, y: 0, data: {
      kind: "gateway", tone: ownerColor,
      label: view === "debug" ? (seam.seam_id || "boundary") : (seam.display_name || "Provider boundary"),
      sub: `${view === "debug" ? (seam.control_plane_owner ?? "?") : seamOwnerLabel(seam.control_plane_owner)}${vis ? " · " + (view === "debug" ? vis : visibilityLabel(seam.visibility)) : ""}`,
      hasIn: false,
    } });
    prev = "seam"; col++;
  }

  if (locus) {
    node({ id: "fault", x: col * COL, y: 0, data: {
      kind: kindForRole(locus.dev), tone: meta.color, pulse: true, size: 62,
      label: entityLabel(locus.dev), badge: `${meta.sym} ${meta.word}`,
      chips: faultEls(locus).slice(0, 4), hasBottom: true, hasIn: !!prev,
    } });
    if (prev) link(prev, "fault", { state: measuredDegraded ? "degraded" : "healthy" });
    prev = "fault"; col++;

    // Also-affected devices sit BELOW the locus as context (never on the primary
    // axis, and never used to imply a path).
    const others = [...devs.values()].filter((d) => d.dev !== locus.dev);
    others.slice(0, 4).forEach((d, i) => {
      const aid = `aff${i}`;
      node({ id: aid, x: (col - 1) * COL + (i - (others.length - 1) / 2) * 140, y: 150, data: {
        kind: kindForRole(d.dev), tone: C.warn, label: entityLabel(d.dev),
        sub: faultEls(d)[0] || "also affected", hasIn: true, hasOut: false,
      } });
      link("fault", aid, { fromHandle: "b", state: "unknown" });
    });
  }

  // The far end of a routing session the device itself declared — the segment the
  // adjacency change is about (a flap is device → peer, not a lone node).
  if (peer) {
    const down = /down|idle|active|flap/i.test(peer.state);
    node({ id: "peer", x: col * COL, y: 0, data: {
      kind: "router", tone: down ? meta.color : C.info, label: peer.peer, mono: true,
      sub: `${peer.rel.toLowerCase()} peer`, hasOut: false, hasIn: !!prev,
    } });
    if (prev) link(prev, "peer", {
      state: down ? faultEdgeState : (timeline.verdict_tier === "confirmed" ? "healthy" : "degraded"),
      label: /bgp/i.test(peer.rel) ? "BGP neighbor changed" : `${peer.rel} changed`,
    });
  }

  return { nodes, edges, bands: [], internal: false, mode: nodes.length ? "context" : "empty" };
}
