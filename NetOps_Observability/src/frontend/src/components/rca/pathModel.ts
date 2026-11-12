// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type {
  CorrTimeline, RcaPathAttribution, RcaTypedSegment, RcaPathKeyDevice,
  RcaAttributedFault, RcaDiscountedFault, RcaPathHead,
} from "../../services/api";
import { readServicePath, type SpineKind } from "./servicePath";
import { isRoutingKind, mentionsInternal, kindLabel, entityLabel } from "./labels";
import {
  type TopologyContext, type TopoCtxNode, type TopoCtxEdge, type FaultMark, type CausalRelation,
  devicePeak, deviceFaultKinds, interfaceFaults, severityTone,
} from "./topologyContext";

// pathModel.ts — the SINGLE data-derivation for the RCA case path view (owner
// P1 2026-07-19: "Path causality duplicates Network path and causal topology —
// merge this and make it single logic"). Every RCA path render goes through
// derivePathModel(); RcaPathCausality is the only component that draws it.
//
// Sources, in order of authority (never mixed, never invented):
//  1. TYPED — the engine's path_attribution render contract (rca_path_attribution.go):
//     the discovered typed SRC→DST path + the named on-path cause. Authoritative.
//  2. DERIVED — the backend's measured service-path spine (contract §7, via
//     readServicePath): hop-by-hop measurement grouped into boundary segments,
//     with the backend's own fault/health marks. The hop ORDER is backend data;
//     this module only GROUPS consecutive hops by their declared boundary.
//  3. ADJACENCY — a routing signal that names a device + peer: the adjacency is
//     known even without a path; we say exactly that, nothing more.
//  4. INTERNAL — the platform observing itself; never dressed as a customer path.
//  5. NONE — an honest "path not fully discovered". No hop, break or segment is
//     ever fabricated.
//
// TOPOLOGY CONTEXT (RCA document v2 §2, 2026-11-12). When the server sends
// `topology_context` it is THE topology authority: the four states
// (topology_with_path · topology_only · device_only · no_asset_mapping) and the
// three layers (known topology, measured fault overlay, causal overlay) come
// from it and nothing else. deriveContextModel lays it out with the SAME
// geometry as the server partial (rca_report_html_topology.go topoEgoSVG /
// topoDeviceSVG), so the screen, the print fallback and the server PDF draw the
// same picture. Sources 3–5 above apply only to a server that sends no context
// (a pre-v2 build): with a context present, the adjacency guess is never used.
//
// CANONICAL SEGMENTATION (owner directive 2026-07-19): every rendered segment
// canonicalizes onto the enterprise connectivity taxonomy —
//   site_lan → edge_security → wan_edge → carrier → dc_wan_edge → dc_fabric
//   (cloud attachment: … → cloud_edge → cloud)
// with two invariants:
//   · TOPOLOGICAL COMPLETENESS — a path that spans site LAN → cloud (or → DC)
//     ALWAYS renders the intermediate WAN construct (wan_edge, carrier) even
//     with zero responding hops: measurement absence ≠ topological absence.
//     Such segments are marked `inferred` and drawn dotted, never omitted and
//     never dressed as measured. A purely intra-site path gets nothing added.
//   · BOUNDARIES — every adjacent segment pair carries a boundary; the seam is
//     labeled where OWNERSHIP changes (enterprise ↔ carrier ↔ provider). The
//     red break hero sits ON a boundary when the seam between parties is
//     suspected, WITHIN a segment when a device inside it is suspected.

// "context" — no path chain to draw, but the server's topology context is
// present: the view renders its state (device card, known topology, or the
// data-availability error) instead of the legacy fallbacks.
export type PathMode = "typed" | "derived" | "context" | "adjacency" | "internal" | "none";
export type SegmentHealth = "degraded" | "down";

// ── canonical segment taxonomy ────────────────────────────────────────────────

export type CanonicalSegment =
  | "site_lan" | "edge_security" | "wan_edge" | "carrier"
  | "dc_wan_edge" | "dc_fabric" | "cloud_edge" | "cloud" | "unknown";

export type OwnerClass = "enterprise" | "carrier" | "provider" | "unknown";

// Who owns each canonical segment — drives the seam labels at boundaries.
export const SEGMENT_OWNER: Record<CanonicalSegment, OwnerClass> = {
  site_lan: "enterprise", edge_security: "enterprise", wan_edge: "enterprise",
  carrier: "carrier",
  dc_wan_edge: "enterprise", dc_fabric: "enterprise",
  cloud_edge: "provider", cloud: "provider",
  unknown: "unknown",
};

// Legacy engine segment vocabulary → canonical taxonomy. The engine/spine still
// emits lan|wan|internet|cloud|dc|wan_seam; the render is canonical-only.
const LEGACY_CANON: Record<string, CanonicalSegment> = {
  lan: "site_lan", dc: "dc_fabric", wan: "wan_edge", wan_seam: "wan_edge",
  internet: "carrier", cloud: "cloud", unknown: "unknown",
  site_lan: "site_lan", edge_security: "edge_security", wan_edge: "wan_edge",
  carrier: "carrier", dc_wan_edge: "dc_wan_edge", dc_fabric: "dc_fabric",
  cloud_edge: "cloud_edge",
};

// Backend cloud-attachment vocabulary → NOC display flavor. ONLY these values
// render; anything else is omitted (never guessed).
const ATTACHMENT_LABEL: Record<string, string> = {
  // "ISP breakout", not "DIA breakout" — DIA displays as ISP (owner 2026-07-26,
  // labels.ts SEAM_TYPE_LABEL).
  dia: "ISP breakout", dia_breakout: "ISP breakout", sdwan_dia: "ISP breakout",
  direct_connect: "Direct Connect", dx: "Direct Connect",
  expressroute: "ExpressRoute", express_route: "ExpressRoute",
  ipsec_vpn: "IPsec VPN", ipsec: "IPsec VPN", vpn: "IPsec VPN",
};
export function attachmentLabel(a?: string): string {
  return ATTACHMENT_LABEL[(a || "").toLowerCase()] ?? "";
}

// A segment as the view renders it: the engine segment plus its canonical
// placement, ownership, and (when topology demands it) the inferred marker.
export interface PathSegmentView extends RcaTypedSegment {
  canonical: CanonicalSegment;
  ownerClass: OwnerClass;
  // Topological inference: the segment is REQUIRED by the path class (a site LAN
  // never reaches cloud/DC without a WAN construct) but carries zero responding
  // hops. Drawn dotted with its reason — measurement absence ≠ topological absence.
  inferred?: boolean;
  // NOC attachment flavor for the cloud_edge segment ("DIA breakout",
  // "Direct Connect", "ExpressRoute", "IPsec VPN") — backend-derived only.
  attachmentText?: string;
}

// A boundary between viewSegments[afterIndex] and viewSegments[afterIndex+1].
// Every adjacent pair gets one; the seam is labeled where ownership changes.
export interface PathBoundary {
  afterIndex: number;
  seamLabel?: string;   // "enterprise ↔ carrier" — only when ownership changes
  suspected?: boolean;  // the red break hero sits ON this boundary
}

export interface PathModel {
  mode: PathMode;
  head: RcaPathHead | null;
  dstName: string;
  segments: PathSegmentView[];
  boundaries: PathBoundary[];
  // Per-segment health overlay (segment `index` → state). Only segments whose
  // health the backend actually measured appear — absence stays quiet.
  segmentHealth: Record<number, SegmentHealth>;
  cause: RcaAttributedFault | null;
  // When set, the break hero renders ON the boundary at this afterIndex (the
  // seam between the parties is the suspect) and the cause device inside a
  // segment is NOT marked — one hero, never two.
  causeBoundary: number | null;
  explainedAway: RcaAttributedFault[];
  discounted: RcaDiscountedFault[];
  verdict: string;
  baseline: string;
  lifted: boolean;
  capped: boolean;
  capReason?: string;
  ambiguous: boolean;
  notes: string[];
  adjacency?: { device: string; peer: string; kindText: string };
  // The server's topology context and its layout, when the report carried one.
  // Rendered beside (typed/derived) or instead of (context mode) the chain.
  context?: TopologyContext;
  contextModel?: ContextModel;
}

// ── topology-context layout (mirrors rca_report_html_topology.go) ────────────

export type OverlayTone = "none" | "amber" | "red";

export interface EgoNodeView {
  node: TopoCtxNode;
  x: number; y: number; r: number;
  tone: OverlayTone;
  roleText: string;          // role in words, or "not in inventory" for an unmanaged neighbour
  anomalousPorts: string[];  // interface names carrying evidence (layer 2)
}
export interface EgoEdgeView {
  edge: TopoCtxEdge;
  x1: number; y1: number; x2: number; y2: number;
  // A known link the engine joined no evidence across: "?" drawn on its middle.
  unknownMark?: { x1: number; y1: number; x2: number; y2: number };
}
export interface CausalLineView {
  x1: number; y1: number; x2: number; y2: number;
  relation: CausalRelation;
  directed: boolean;
}
export interface EgoView {
  w: number; h: number;
  nodes: EgoNodeView[];
  edges: EgoEdgeView[];
  causal: CausalLineView[];   // cross-device engine edges, offset off the grey link
}
export interface PanelPortView {
  fault: FaultMark;
  x: number; y: number; w: number; h: number;
  tone: OverlayTone;
}
export interface PanelConnectorView {
  x1: number; y1: number; x2: number; y2: number;
  // Absent → a plain thin connector (the port carries evidence but no engine
  // edge joins it to the device).
  relation?: CausalRelation;
  directed: boolean;
}
export interface PanelArcView {
  x: number; y1: number; y2: number; bulge: number;
  relation: CausalRelation;
}
export interface DevicePanelView {
  node: TopoCtxNode;
  w: number; h: number;
  dev: { x: number; y: number; w: number; h: number };
  devTone: OverlayTone;
  roleText: string;
  devKinds: string[];
  ports: PanelPortView[];
  connectors: PanelConnectorView[];
  arcs: PanelArcView[];
  morePorts: number;
  undirectedPortPairs: number;
}
export interface ContextModel {
  ego: EgoView | null;          // only when known links exist
  panels: DevicePanelView[];    // affected devices carrying evidence (≤ 3)
  panelsCapped: boolean;
}

const EGO_W = 760;
const PANEL_W = 760;
const PANEL_MAX_PORTS = 12;
const PANEL_MAX = 3;

function relRank(r: string): number {
  return r === "verified" ? 0 : r === "suspected" ? 1 : 2;
}
function pairKey(a: string, b: string): string {
  return a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`;
}
function markDevice(type: string, id: string): string {
  if (type === "node") return id;
  if (type === "interface") { const i = id.indexOf(":"); return i > 0 ? id.slice(0, i) : ""; }
  return "";
}
function roleWords(n: TopoCtxNode): string {
  const sub = (n.role ?? "").replace(/_/g, " ");
  return !n.managed && !sub ? "not in inventory" : sub;
}

// layoutEgo — anchors on the centre line; with one anchor its neighbours sit on
// an ellipse around it, with several they alternate on a row above and below
// (so no link is drawn through another anchor). Identical to topoEgoSVG.
function layoutEgo(tc: TopologyContext): EgoView {
  const anchors = tc.nodes.filter((n) => n.anchor);
  const neigh = tc.nodes.filter((n) => !n.anchor);
  const h = neigh.length > 8 ? 330 : 250;
  const cx = EGO_W / 2, cy = h / 2;
  const pos = new Map<string, [number, number]>();
  const spacing = Math.min(140, 560 / Math.max(1, anchors.length));
  anchors.forEach((a, i) => pos.set(a.id, [cx + (i - (anchors.length - 1) / 2) * spacing, cy]));
  if (anchors.length <= 1) {
    const rx = EGO_W / 2 - 70, ry = h / 2 - 38;
    neigh.forEach((n, i) => {
      const ang = neigh.length === 1 ? 0 : -Math.PI / 2 + (2 * Math.PI * i) / neigh.length;
      pos.set(n.id, [cx + rx * Math.cos(ang), cy + ry * Math.sin(ang)]);
    });
  } else {
    const top = neigh.filter((_, i) => i % 2 === 0);
    const bottom = neigh.filter((_, i) => i % 2 === 1);
    for (const [row, y] of [[top, 40], [bottom, h - 52]] as [TopoCtxNode[], number][]) {
      row.forEach((n, j) => pos.set(n.id, [50 + (EGO_W - 100) * (j + 0.5) / row.length, y]));
    }
  }

  const unknownOnLink = new Set<string>();
  for (const m of tc.causal) {
    if (m.from_type === "node" && m.to_type === "node" && !m.from_kind && !m.to_kind) unknownOnLink.add(pairKey(m.from, m.to));
  }
  const edges: EgoEdgeView[] = [];
  for (const e of tc.edges) {
    const pa = pos.get(e.a), pb = pos.get(e.b);
    if (!pa || !pb) continue;
    const v: EgoEdgeView = { edge: e, x1: pa[0], y1: pa[1], x2: pb[0], y2: pb[1] };
    if (unknownOnLink.has(pairKey(e.a, e.b))) {
      v.unknownMark = {
        x1: pa[0] + (pb[0] - pa[0]) * 0.35, y1: pa[1] + (pb[1] - pa[1]) * 0.35,
        x2: pa[0] + (pb[0] - pa[0]) * 0.65, y2: pa[1] + (pb[1] - pa[1]) * 0.65,
      };
    }
    edges.push(v);
  }

  // Cross-device engine edges between two DRAWN devices, strongest relation per pair.
  const best = new Map<string, { from: string; to: string; rel: CausalRelation; directed: boolean }>();
  for (const m of tc.causal) {
    if (!m.from_kind && !m.to_kind) continue; // a topology-link mark, drawn on the link
    const da = markDevice(m.from_type, m.from), db = markDevice(m.to_type, m.to);
    if (!da || !db || da === db || !pos.has(da) || !pos.has(db)) continue;
    const k = pairKey(da, db);
    const cur = best.get(k);
    if (!cur || relRank(m.relation) < relRank(cur.rel)) best.set(k, { from: da, to: db, rel: m.relation, directed: m.directed });
  }
  const causal: CausalLineView[] = [];
  for (const k of [...best.keys()].sort()) {
    const pm = best.get(k)!;
    const pa = pos.get(pm.from)!, pb = pos.get(pm.to)!;
    const dx = pb[0] - pa[0], dy = pb[1] - pa[1];
    const l = Math.hypot(dx, dy);
    if (l === 0) continue;
    const ox = (-dy / l) * 6, oy = (dx / l) * 6;
    causal.push({
      x1: pa[0] + (dx / l) * 20 + ox, y1: pa[1] + (dy / l) * 20 + oy,
      x2: pb[0] - (dx / l) * 20 + ox, y2: pb[1] - (dy / l) * 20 + oy,
      relation: pm.rel, directed: pm.directed,
    });
  }

  const nodes: EgoNodeView[] = [...anchors, ...neigh].map((n) => {
    const [x, y] = pos.get(n.id)!;
    return {
      node: n, x, y, r: n.anchor ? 18 : 14,
      tone: severityTone(devicePeak(tc, n.id)),
      roleText: roleWords(n),
      anomalousPorts: interfaceFaults(tc, n.id).map((f) => f.port || f.target_id),
    };
  });
  return { w: EGO_W, h, nodes, edges, causal };
}

// layoutPanel — one affected device with its evidence interfaces and the
// engine's device ↔ interface marks (strongest per interface). Interface ↔
// interface marks draw only when directed; undirected ones are counted.
// Identical to topoDeviceSVG.
function layoutPanel(tc: TopologyContext, n: TopoCtxNode): DevicePanelView {
  let ports = interfaceFaults(tc, n.id);
  let morePorts = 0;
  if (ports.length > PANEL_MAX_PORTS) { morePorts = ports.length - PANEL_MAX_PORTS; ports = ports.slice(0, PANEL_MAX_PORTS); }
  const h = Math.max(110, 40 + 30 * ports.length);
  const devX = 40, devW = 220, portX = 470, portW = 190;
  const devY = h / 2;
  const portY = (i: number) => (ports.length === 1 ? devY : 30 + (i * (h - 60)) / (ports.length - 1));
  const idx = new Map<string, number>();
  ports.forEach((p, i) => idx.set(p.target_id, i));

  const per = new Map<number, { rel: CausalRelation; directed: boolean; devToPort: boolean }>();
  let undirectedPortPairs = 0;
  const arcs: PanelArcView[] = [];
  for (const m of tc.causal) {
    const fi = idx.get(m.from), ti = idx.get(m.to);
    const fIsDev = m.from_type === "node" && m.from === n.id && !!m.from_kind;
    const tIsDev = m.to_type === "node" && m.to === n.id && !!m.to_kind;
    if ((fIsDev && ti !== undefined) || (fi !== undefined && tIsDev)) {
      const i = fi !== undefined && tIsDev ? fi : ti!;
      const d2p = !(fi !== undefined && tIsDev);
      const cur = per.get(i);
      if (!cur || relRank(m.relation) < relRank(cur.rel)) per.set(i, { rel: m.relation, directed: m.directed, devToPort: d2p });
    } else if (fi !== undefined && ti !== undefined && fi !== ti) {
      if (m.directed && m.relation !== "unknown") {
        const x = portX + portW;
        arcs.push({ x, y1: portY(fi), y2: portY(ti), bulge: x + 30 + 6 * Math.abs(ti - fi), relation: m.relation });
      } else {
        undirectedPortPairs++;
      }
    }
  }
  const connectors: PanelConnectorView[] = ports.map((_, i) => {
    const y = portY(i);
    const m = per.get(i);
    if (!m) return { x1: devX + devW, y1: devY, x2: portX, y2: y, directed: false };
    return m.devToPort
      ? { x1: devX + devW, y1: devY, x2: portX, y2: y, relation: m.rel, directed: m.directed }
      : { x1: portX, y1: y, x2: devX + devW, y2: devY, relation: m.rel, directed: m.directed };
  });
  return {
    node: n, w: PANEL_W, h,
    dev: { x: devX, y: devY - 27, w: devW, h: 54 },
    devTone: severityTone(devicePeak(tc, n.id)),
    roleText: (n.role ?? "").replace(/_/g, " ") || "device",
    devKinds: deviceFaultKinds(tc, n.id),
    ports: ports.map((f, i) => ({ fault: f, x: portX, y: portY(i) - 11, w: portW, h: 22, tone: severityTone(f.peak_severity) })),
    connectors, arcs, morePorts, undirectedPortPairs,
  };
}

/** deriveContextModel — the layout of a topology context (pure, deterministic). */
export function deriveContextModel(tc: TopologyContext): ContextModel {
  if (tc.state === "no_asset_mapping") return { ego: null, panels: [], panelsCapped: false };
  const ego = tc.edges.length > 0 ? layoutEgo(tc) : null;
  const panels: DevicePanelView[] = [];
  let panelsCapped = false;
  for (const n of tc.nodes) {
    if (!n.anchor) continue;
    const faulted = tc.faults.some((f) => f.device === n.id);
    if (!faulted && tc.state !== "device_only") continue;
    if (panels.length === PANEL_MAX) { panelsCapped = true; break; }
    panels.push(layoutPanel(tc, n));
  }
  return { ego, panels, panelsCapped };
}

// Spine boundary name → typed segment_type (labels.ts SEGMENT_META vocabulary).
const BOUNDARY_SEG: Record<string, string> = {
  LAN: "lan", "SD-WAN": "wan", SDWAN: "wan", WAN: "wan",
  CARRIER: "internet", INTERNET: "internet", CLOUD: "cloud", DC: "dc",
};
// Spine hop kind → device role token (labels.ts ROLE_LABEL vocabulary).
const SPINE_ROLE: Record<SpineKind, string> = {
  client: "client", lan_gateway: "gateway", wan_edge: "edge", nva: "nva",
  cloud_edge: "gateway", app_endpoint: "app", service_endpoint: "app",
  application: "app", transit: "router", unknown: "unknown",
};

function emptyModel(mode: PathMode, verdict: string): PathModel {
  return {
    mode, head: null, dstName: "application", segments: [], boundaries: [],
    segmentHealth: {}, cause: null, causeBoundary: null,
    explainedAway: [], discounted: [], verdict, baseline: verdict,
    lifted: false, capped: false, ambiguous: false, notes: [],
  };
}

// ── canonicalization ──────────────────────────────────────────────────────────

// Discovery device_role values that mean "this is the WAN edge construct".
const WAN_EDGE_ROLES = new Set(["wan_edge", "edge", "tunnel", "tunnel_gw", "nva"]);
const DC_FABRIC_ROLES = new Set(["dc_leaf", "dc_spine", "leaf", "spine"]);
const EDGE_SECURITY_ROLES = new Set(["firewall", "fw", "waf"]);
const CLOUD_EDGE_ROLES = new Set(["cloud_edge", "gateway", "tunnel", "tunnel_gw", "nva"]);

function deviceRoles(seg: RcaTypedSegment): string[] {
  return (seg.key_devices ?? []).map((d) => (d.device_role || d.role || "").toLowerCase());
}

// canonicalSegment — place one engine segment on the canonical taxonomy. The
// legacy type anchors it; discovery device roles REFINE it (never contradict it
// across ownership lines): a lan segment of firewalls is edge_security, a lan/dc
// segment with leaf/spine roles is dc_fabric, a cloud segment whose devices are
// all edge constructs is cloud_edge, a wan segment of DC-side edges is
// dc_wan_edge. Unknown stays unknown — roles are used, never invented.
export function canonicalSegment(seg: RcaTypedSegment): CanonicalSegment {
  const base = LEGACY_CANON[(seg.segment_type || "").toLowerCase()] ?? "unknown";
  const roles = deviceRoles(seg).filter((r) => r && r !== "unknown");
  if (roles.length === 0) return base;
  switch (base) {
    case "site_lan":
      if (roles.every((r) => EDGE_SECURITY_ROLES.has(r))) return "edge_security";
      if (roles.some((r) => DC_FABRIC_ROLES.has(r))) return "dc_fabric";
      return base;
    case "wan_edge":
      if (roles.some((r) => r === "dc_wan_edge")) return "dc_wan_edge";
      if (roles.every((r) => r === "carrier_hop")) return "carrier";
      return base;
    case "carrier":
      // A carrier-classified span whose devices are actually the enterprise WAN
      // edge (SD-WAN CPE answering from carrier-assigned space) is the WAN edge.
      if (roles.length > 0 && roles.every((r) => WAN_EDGE_ROLES.has(r))) return "wan_edge";
      return base;
    case "dc_fabric":
      if (roles.some((r) => r === "dc_wan_edge")) return "dc_wan_edge";
      return base;
    case "cloud":
      if (roles.every((r) => CLOUD_EDGE_ROLES.has(r))) return "cloud_edge";
      return base;
    default:
      return base;
  }
}

function toView(seg: RcaTypedSegment): PathSegmentView {
  const canonical = canonicalSegment(seg);
  return {
    ...seg,
    // The render vocabulary IS the canonical taxonomy (labels.ts SEGMENT_META).
    segment_type: canonical === "unknown" ? seg.segment_type : canonical,
    canonical,
    ownerClass: SEGMENT_OWNER[canonical],
    attachmentText: attachmentLabel(seg.attachment) || undefined,
  };
}

// ── topological completeness (owner directive: measurement absence ≠
//    topological absence) ─────────────────────────────────────────────────────

const SITE_SIDE = new Set<CanonicalSegment>(["site_lan", "edge_security"]);
const CLOUD_SIDE = new Set<CanonicalSegment>(["cloud_edge", "cloud"]);

const INFERRED_REASON: Partial<Record<CanonicalSegment, string>> = {
  wan_edge: "No responding hops — WAN edge inferred: a site LAN always attaches upstream through a WAN edge (SD-WAN CPE / CE router), even when it answers no probes.",
  carrier: "No responding hops — carrier path inferred: between a site and its cloud/DC attachment there is always a carrier / middle-mile leg; its hops are often silent.",
  dc_wan_edge: "No responding hops — DC WAN edge inferred: the data-center side terminates the WAN on its own edge (SD-WAN / CE), even when it answers no probes.",
};

function inferredSegment(canonical: CanonicalSegment, index: number): PathSegmentView {
  return {
    index, segment_type: canonical, canonical, ownerClass: SEGMENT_OWNER[canonical],
    inferred: true, key_devices: [], unknown_hops: [], ambiguous: false,
    reason: INFERRED_REASON[canonical],
  };
}

// ensureCompleteness — when the path spans site LAN → cloud (or → DC), the WAN
// constructs between them are ALWAYS rendered:
//  · a measured-but-unclassified (unknown) span sitting between the site side and
//    the far side IS the WAN/carrier leg topologically — it is reclassified to
//    carrier and marked inferred (its measured unknown-hop count is kept);
//  · any still-missing required construct (wan_edge, carrier, dc_wan_edge for a
//    DC-bound path) is inserted as a zero-hop inferred segment.
// A path that does not span (purely intra-site, cloud-only, …) is left alone.
// Inserted segments use negative indexes so they can never collide with engine
// segment indexes (health/device identity stays keyed to real segments).
export function ensureCompleteness(segments: PathSegmentView[]): PathSegmentView[] {
  if (segments.length === 0) return segments;
  const canon = (s: PathSegmentView) => s.canonical;

  const lastSite = findLast(segments, (s) => SITE_SIDE.has(canon(s)));
  const firstCloud = segments.findIndex((s) => CLOUD_SIDE.has(canon(s)));
  const firstDc = segments.findIndex((s) => canon(s) === "dc_fabric" || canon(s) === "dc_wan_edge");
  const far = firstCloud >= 0 ? firstCloud : firstDc;
  const toDc = firstCloud < 0 && firstDc >= 0;
  // No site→far span ⇒ nothing to infer (an intra-site or cloud-only case).
  if (lastSite < 0 || far < 0 || far <= lastSite) return segments;

  const out = segments.slice();

  // 1) A positional unknown span between the site side and the far side is the
  //    WAN/carrier leg topologically: reclassify (keep its measured hop count).
  for (let i = lastSite + 1; i < far; i++) {
    if (out[i].canonical === "unknown") {
      out[i] = {
        ...out[i], canonical: "carrier", segment_type: "carrier",
        ownerClass: SEGMENT_OWNER.carrier, inferred: true,
        reason: out[i].reason || INFERRED_REASON.carrier,
      };
    }
  }

  // 2) Which required constructs are still absent between the ends?
  const present = new Set(out.map(canon));
  const required: CanonicalSegment[] = toDc
    ? ["wan_edge", "carrier", "dc_wan_edge"]
    : ["wan_edge", "carrier"];
  // A named WAN-edge DEVICE inside a site-side segment also satisfies wan_edge
  // (the construct is drawn where it was measured, not duplicated).
  const hasWanEdgeDevice = out.some((s) =>
    SITE_SIDE.has(s.canonical) && deviceRoles(s).some((r) => WAN_EDGE_ROLES.has(r)));
  const missing = required.filter((c) =>
    !present.has(c) && !(c === "wan_edge" && hasWanEdgeDevice) &&
    !(c === "dc_wan_edge" && out.some((s) => s.canonical === "dc_fabric" && deviceRoles(s).some((r) => r === "dc_wan_edge"))));
  if (missing.length === 0) return out;

  // 3) Insert each missing construct, in canonical order, before the first
  //    later-ranked segment after the site side (so wan_edge lands before an
  //    existing carrier leg, carrier before the DC/cloud side, and so on).
  const CANON_ORDER: CanonicalSegment[] = [
    "site_lan", "edge_security", "wan_edge", "carrier", "dc_wan_edge",
    "dc_fabric", "cloud_edge", "cloud",
  ];
  const rank = (c: CanonicalSegment): number => CANON_ORDER.indexOf(c);
  missing.sort((a, b) => rank(a) - rank(b));
  let syntheticIdx = -1;
  for (const c of missing) {
    let at = out.length;
    for (let i = lastSite + 1; i < out.length; i++) {
      const r = rank(out[i].canonical);
      if (r >= 0 && r > rank(c)) { at = i; break; }
    }
    out.splice(at, 0, inferredSegment(c, syntheticIdx--));
  }
  return out;
}

function findLast<T>(arr: T[], pred: (t: T) => boolean): number {
  for (let i = arr.length - 1; i >= 0; i--) if (pred(arr[i])) return i;
  return -1;
}

// ── boundaries & seam-break placement ────────────────────────────────────────

const OWNER_WORD: Record<OwnerClass, string> = {
  enterprise: "enterprise", carrier: "carrier", provider: "provider", unknown: "",
};

// deriveBoundaries — one boundary per adjacent pair; the seam is labeled where
// ownership changes ("enterprise ↔ carrier"). The suspected flag is set by
// placeSeamBreak, not here.
export function deriveBoundaries(segments: PathSegmentView[]): PathBoundary[] {
  const out: PathBoundary[] = [];
  for (let i = 0; i < segments.length - 1; i++) {
    const a = segments[i].ownerClass, b = segments[i + 1].ownerClass;
    const label = a !== b && OWNER_WORD[a] && OWNER_WORD[b]
      ? `${OWNER_WORD[a]} ↔ ${OWNER_WORD[b]}` : undefined;
    out.push({ afterIndex: i, seamLabel: label });
  }
  return out;
}

function segHasRespondingDevices(s: PathSegmentView): boolean {
  return (s.key_devices?.length ?? 0) > 0;
}

// placeSeamBreak — decides whether the break hero sits ON a boundary (the seam
// between parties is the suspect) or WITHIN a segment (a device is). Rules,
// derived only from what the backend stated:
//  (a) the attributed cause names a segment that has NO responding devices
//      (inferred / opaque carrier span) → the handoff INTO that segment is the
//      suspect: hero on the preceding boundary.
//  (b) derived (spine) mode: the fault mark sits on the LAST responding device
//      of its segment, the NEXT segment is dark (no responding hops), and
//      ownership changes across that boundary → the seam is the suspect (the
//      measurement died exactly at the parties' handoff).
// Anything else keeps the device hero. Returns the boundary afterIndex or null.
export function placeSeamBreak(
  mode: PathMode,
  segments: PathSegmentView[],
  cause: RcaAttributedFault | null,
): number | null {
  if (!cause || segments.length < 2) return null;
  const si = segments.findIndex((s) => s.index === cause.device.segment_index);
  if (si < 0) return null;
  const seg = segments[si];

  // (a) blamed segment has no named devices → the seam into it is the suspect.
  if (!segHasRespondingDevices(seg) && si > 0) {
    return si - 1;
  }

  // (b) spine-derived: died at the last device before a dark handoff.
  if (mode === "derived" && si < segments.length - 1) {
    const devs = seg.key_devices ?? [];
    const isLastDevice = devs.length > 0 &&
      matchesDevice(devs[devs.length - 1], cause.device);
    const next = segments[si + 1];
    const ownerChanges = seg.ownerClass !== next.ownerClass;
    if (isLastDevice && !segHasRespondingDevices(next) && ownerChanges) {
      return si;
    }
  }
  return null;
}

function matchesDevice(a: RcaPathKeyDevice, b: { address?: string; label?: string; role?: string }): boolean {
  return (a.address || "").toLowerCase() === (b.address || "").toLowerCase() &&
    (a.label || "").toLowerCase() === (b.label || "").toLowerCase();
}

// finalizeSegments — canonicalize, complete, and derive boundaries + seam break
// for one set of engine segments. Shared by the typed and derived sources.
function finalizeSegments(
  mode: PathMode,
  raw: RcaTypedSegment[],
  cause: RcaAttributedFault | null,
): { segments: PathSegmentView[]; boundaries: PathBoundary[]; causeBoundary: number | null } {
  const segments = ensureCompleteness(raw.map(toView));
  const boundaries = deriveBoundaries(segments);
  const causeBoundary = placeSeamBreak(mode, segments, cause);
  if (causeBoundary !== null && boundaries[causeBoundary]) {
    boundaries[causeBoundary] = { ...boundaries[causeBoundary], suspected: true };
  }
  return { segments, boundaries, causeBoundary };
}

// ── fallback readers (unchanged logic) ───────────────────────────────────────

// The routing-context read (device + peer off a routing signal) — the honest
// adjacency fallback when no path exists. Internal entities are never surfaced.
function routingContext(timeline: CorrTimeline): { device: string; peer: string; kindText: string } | null {
  for (const s of timeline.signals) {
    if (!s.attached || s.kind.endsWith("_clear") || !isRoutingKind(s.kind)) continue;
    let device = s.entity_id, peer = "";
    try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); peer = a.peer || a.neighbor || ""; } catch { /* no attrs */ }
    const ci = s.entity_id.indexOf(":");
    if (ci > 0) { device = s.entity_id.slice(0, ci); if (!peer) peer = s.entity_id.slice(ci + 1); }
    if (mentionsInternal(device)) return null;
    return { device: entityLabel(device), peer, kindText: kindLabel(s.kind) };
  }
  return null;
}

// Internal/self-probe-only object → never dressed as a customer path.
function internalOnly(timeline: CorrTimeline): boolean {
  const attached = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  if (attached.length === 0) return false;
  const probes = attached.filter((s) => s.modality_class === "active_probe");
  const others = attached.filter((s) => s.modality_class !== "active_probe");
  return others.length === 0 && probes.length > 0 &&
    probes.every((s) => s.probe_authority === "debug_only" || s.probe_scope === "internal_self_probe" || s.probe_scope === "synthetic_lab_probe");
}

// Derive segments from the backend's measured spine: consecutive hops grouped by
// their declared boundary; responding hops become key devices, silent hops fold
// into the segment's unknown-hop count; the backend's fault mark (if any)
// becomes the cause. Health comes only from the backend's edge states.
function fromSpine(timeline: CorrTimeline): PathModel | null {
  const sp = readServicePath(timeline);
  if (!sp) return null;
  const spine = [...sp.spine].sort((a, b) => a.index - b.index);

  const segments: RcaTypedSegment[] = [];
  const hopSeg = new Map<number, number>();   // spine index → segment index
  let curKey: string | null = null;
  for (const n of spine) {
    const key = (n.boundary || "").toUpperCase();
    if (curKey === null || key !== curKey) {
      curKey = key;
      segments.push({
        index: segments.length,
        segment_type: BOUNDARY_SEG[key] ?? (key ? "unknown" : "unknown"),
        boundary: n.boundary,
        provider: n.provider,
        key_devices: [], unknown_hops: [], ambiguous: false,
      });
    }
    const seg = segments[segments.length - 1];
    if (!seg.provider && n.provider) seg.provider = n.provider;
    hopSeg.set(n.index, seg.index);
    if (n.state === "responding") {
      (seg.key_devices as RcaPathKeyDevice[]).push({
        address: n.address, role: SPINE_ROLE[n.kind] ?? "unknown", label: n.label,
        device_role: n.device_role, role_confidence: n.role_confidence,
      });
    } else {
      (seg.unknown_hops as number[]).push(n.index);
      if (!seg.reason) seg.reason = n.state === "filtered"
        ? "This hop filters path probes — not visible from here."
        : "This hop did not respond to path measurement — not visible from here.";
    }
  }

  // The backend's fault mark → the cause; "last_response" is a measurement
  // fact (where the run stopped answering), never blame.
  let cause: RcaAttributedFault | null = null;
  const notes: string[] = [];
  for (const n of spine) {
    if (n.fault === "broken" || n.fault === "suspected" || n.fault === "possible") {
      const si = hopSeg.get(n.index) ?? 0;
      cause = {
        device: {
          address: n.address, role: SPINE_ROLE[n.kind] ?? "unknown", label: n.label,
          segment_index: si, segment_type: segments[si]?.segment_type, upstream_rank: 0, ambiguous: false,
        },
        kind: "",
      };
      break;
    }
    if (n.fault === "last_response") {
      notes.push(`Path measurement stopped answering after ${n.label} — a measurement fact, not an attribution.`);
    }
  }

  // Segment health overlay from the backend's edge states only.
  const segmentHealth: Record<number, SegmentHealth> = {};
  for (const e of sp.edges) {
    const si = hopSeg.get(e.to) ?? hopSeg.get(e.from);
    if (si === undefined || !e.state) continue;
    if (e.state === "confirmed_down" || e.state === "suspected_down") segmentHealth[si] = "down";
    else if (e.state === "degraded" && segmentHealth[si] !== "down") segmentHealth[si] = "degraded";
  }
  if (cause) {
    const si = cause.device.segment_index;
    if (!segmentHealth[si]) segmentHealth[si] = "down";
  }

  const last = spine[spine.length - 1];
  const verdict = timeline.verdict_tier || "suspected";
  const fin = finalizeSegments("derived", segments, cause);
  return {
    mode: "derived", head: null,
    dstName: last?.kind === "application" || last?.kind === "app_endpoint" || last?.kind === "service_endpoint"
      ? last.label : (last?.label || "destination"),
    segments: fin.segments, boundaries: fin.boundaries, segmentHealth, cause,
    causeBoundary: fin.causeBoundary,
    explainedAway: [], discounted: [],
    verdict, baseline: verdict, lifted: false, capped: false,
    ambiguous: false, notes,
  };
}

// derivePathModel — the ONE derivation every RCA case path render consumes.
// `context` is the server's topology context (readTopologyContext); when it is
// present it decides the topology state and the legacy adjacency/none fallbacks
// are not used.
export function derivePathModel(
  data: RcaPathAttribution | null | undefined,
  timeline?: CorrTimeline | null,
  context?: TopologyContext | null,
): PathModel {
  const base = derivePathChain(data, timeline, !!context);
  if (!context) return base;
  const withCtx: PathModel = { ...base, context, contextModel: deriveContextModel(context) };
  // A chain the context does not back is not drawn as a measured path: the
  // derived spine renders only in topology_with_path (the server attached a
  // measured path). Typed attribution is the engine's own discovered path and
  // always renders.
  if (base.mode === "derived" && context.state !== "topology_with_path") {
    return { ...emptyModel("context", base.verdict), context, contextModel: withCtx.contextModel };
  }
  if (base.mode === "none" || base.mode === "adjacency") {
    return { ...emptyModel("context", base.verdict), context, contextModel: withCtx.contextModel };
  }
  return withCtx;
}

function derivePathChain(
  data: RcaPathAttribution | null | undefined,
  timeline: CorrTimeline | null | undefined,
  hasContext: boolean,
): PathModel {
  // 1) TYPED: the engine's decoded path-causality attribution.
  const typedSegments = data?.path?.segments ?? [];
  if (data && (data.attributed || typedSegments.length > 0)) {
    const verdict = data.verdict_tier;
    const cause = data.attributed ?? null;
    const segmentHealth: Record<number, SegmentHealth> = {};
    if (cause) segmentHealth[cause.device.segment_index] = "down";
    const fin = finalizeSegments("typed", typedSegments, cause);
    return {
      mode: "typed",
      head: data.path?.head ?? null,
      dstName: data.path?.head?.query_name || "application",
      segments: fin.segments,
      boundaries: fin.boundaries,
      segmentHealth,
      cause,
      causeBoundary: fin.causeBoundary,
      explainedAway: data.explained_away ?? [],
      discounted: data.discounted ?? [],
      verdict,
      baseline: data.baseline_verdict_tier,
      lifted: !!data.confidence_lifted && !!data.baseline_verdict_tier && data.baseline_verdict_tier !== verdict,
      capped: !!data.capped, capReason: data.cap_reason,
      ambiguous: !!data.path?.ambiguous,
      notes: data.path?.notes ?? [],
    };
  }

  if (!timeline) return emptyModel("none", data?.verdict_tier || "suspected");
  if (internalOnly(timeline)) return emptyModel("internal", timeline.verdict_tier || "suspected");

  // 2) DERIVED: the backend's measured spine, grouped into boundary segments.
  const spineModel = fromSpine(timeline);
  if (spineModel) return spineModel;

  // 3) ADJACENCY: routing evidence names a device + peer — say exactly that.
  //    Only for a server that sent no topology context (pre-v2): the context
  //    is the authority, and a client-side guess would contradict the PDF.
  if (hasContext) return emptyModel("none", timeline.verdict_tier || "suspected");
  const adj = routingContext(timeline);
  if (adj) return { ...emptyModel("adjacency", timeline.verdict_tier || "suspected"), adjacency: adj };

  // 4) NONE — honest absence.
  return emptyModel("none", timeline.verdict_tier || "suspected");
}
