// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { CorrTimeline } from "../../services/api";
import { C, seamOwnerColor, isInternalEntity } from "./labels";
import type { ShapeKind } from "../graph/shapes";
import {
  readServicePath, transformationLabel, spineKindLabel, hopStateLabel,
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
// An object with NO spine yields an empty graph — we never invent a path. Its
// known topology comes from the server's topology context (topologyContext.ts).

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
  provider?: string;          // aws | azure | gcp — declared-inventory claim (backend-stamped)
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
    // A measurement boundary is NOT a fault: it says where the run stopped
    // answering, without blaming the path (the case's fault lies elsewhere).
    const boundaryOnly = n.fault === "last_response";
    const faulted = !!n.fault && !boundaryOnly;
    const fmeta = faulted && n.fault ? STATUS_META[n.fault as "broken" | "suspected" | "possible"] : meta;
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
        kind: hopShape(n), tone: boundaryOnly ? C.muted : tone, pulse: faulted,
        // A silent hop with no identity renders as "Unknown hop" — but a KNOWN
        // endpoint that didn't answer keeps its name (the application the run
        // proved unreachable is the headline, not a mystery).
        label: blind && !n.address && n.kind === "unknown" ? "Unknown hop" : n.label,
        mono: !!n.address && n.address === n.label,
        sub: sub || undefined,
        badge: faulted ? `${fmeta.sym} ${fmeta.word}` : boundaryOnly ? "◍ Last response" : undefined,
        chips: chips.length ? chips : undefined,
        hasIn: n.index !== path.spine[0]?.index,
        hasOut: true,
        hasBottom: (branchesByHop.get(n.index) ?? 0) > 0,
        hopIndex: n.index,
        boundary: n.boundary,
        entityRef: n.entity_ref,
        address: n.address,
        provider: n.provider,
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
    // The segment LEAVING the backend-stamped drop point is where the path
    // died — render it as the fault (red ✕), matching the hop's own mark.
    const faultEdge = a.fault && a.fault !== "last_response" && b.state !== "responding"
      ? (a.fault === "broken" ? "confirmed_down" : "suspected_down") as EdgeState
      : undefined;
    const state: EdgeState = e.state ?? faultEdge ?? (blind ? "unknown" : "healthy");
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

// buildTopoGraph — PURE: RCA object → the backend spine's positioned graph, for
// the client print fallback (rcaExport.ts) that draws the measured path.
//   spine    → the backend's ordered service path (the ONLY path layout)
//   internal → the platform observing itself — never dressed as a customer path
//   empty    → no spine. The known topology around the affected devices is the
//              server's topology context (RCA document v2 §2), drawn by
//              RcaTopologyContext and rcaExport from that one struct — this file
//              no longer derives a device area of its own (the "context mode"
//              that drew a node the server PDF denied is gone).
export function buildTopoGraph(timeline: CorrTimeline): TopoGraph {
  const path = readServicePath(timeline);
  if (path) return layoutSpine(path, timeline.verdict_tier);
  const entities = timeline.signals
    .filter((s) => s.attached && !s.kind.endsWith("_clear"))
    .map((s) => s.entity_id).filter(Boolean);
  const internal = entities.length > 0 && entities.every(isInternalEntity);
  return { nodes: [], edges: [], bands: [], internal, mode: internal ? "internal" : "empty" };
}
