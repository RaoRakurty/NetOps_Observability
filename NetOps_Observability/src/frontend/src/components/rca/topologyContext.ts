// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyContext.ts — the ONE topology model of an RCA case, as the server
// sends it (RCA document v2 §2; Go: internal/rca/topology_context.go). The
// report JSON carries it under `topology_context`; the screen (RcaPathCausality
// via pathModel.ts), the client print fallback (rcaExport.ts) and the server PDF
// all draw from this one struct, so they cannot disagree.
//
// Zero trust (CLAUDE.md §3): the payload is untrusted input. readTopologyContext
// validates the shape, bounds every list and string, and drops a malformed entry
// rather than guessing at it. Nothing here ever ADDS a node, an edge or a mark —
// a value the server did not send is never drawn (plan §2 "never invent").
//
// The state words mirror the server partial (rca_report_html_topology.go
// topoStateLabel / topoCtxSourceLabel) so the UI and the PDF say the same thing.

// ── interfaces first ─────────────────────────────────────────────────────────

export type TopologyState = "topology_with_path" | "topology_only" | "device_only" | "no_asset_mapping";
export type CausalRelation = "verified" | "suspected" | "unknown";

/** One consulted topology source and what it returned. */
export interface TopologySource {
  kind: string;          // lldp | cdp | bgp_ls | topology_graph | sdwan_overlay | controller | inventory
  status: string;        // read | unavailable | not_configured
  rows: number;
  observed_at?: string;  // RFC 3339 UTC
  stale: boolean;
  freshness: string;     // current | stale | empty | unavailable | not_configured
  detail?: string;
}

/** A device (or an unresolved neighbour) in the 1-hop ego-graph. */
export interface TopoCtxNode {
  id: string;
  label: string;
  role?: string;
  source: string;
  anchor: boolean;
  managed: boolean;
  first_seen?: string;
  last_seen?: string;
  stale: boolean;
}

/** One known adjacency between two drawn nodes. */
export interface TopoCtxEdge {
  id: string;
  a: string;
  a_port?: string;
  b: string;
  b_port?: string;
  relationship: string;
  protocol?: string;
  sources: string[];
  confidence?: number;
  bidirectional: boolean;
  first_seen?: string;
  last_seen?: string;
  stale: boolean;
  freshness: string;     // current | stale | after_incident
}

/** Layer 2 — where anomalous evidence was observed. Never a causal claim. */
export interface FaultMark {
  target_type: "node" | "interface";
  target_id: string;
  device: string;
  port?: string;
  kinds: string[];
  peak_severity: string;
  evidence_refs: string[];
}

/** Layer 3 — one engine edge (or a known link with no engine edge) read causally. */
export interface CausalMark {
  from: string;
  from_type: string;
  from_kind?: string;
  to: string;
  to_type: string;
  to_kind?: string;
  relation: CausalRelation;
  directed: boolean;
  basis: string;
  direction_conf: number;
  evidence_refs: string[];
}

export interface TopologyContext {
  state: TopologyState;
  sources: TopologySource[];
  anchors: string[];
  unmapped: string[];
  nodes: TopoCtxNode[];
  edges: TopoCtxEdge[];
  more_nodes: number;
  faults: FaultMark[];
  causal: CausalMark[];
  /** The measured path, when one is attached. Its hops are drawn from the
   *  case timeline's service-path spine (the same backend spine). */
  has_spine: boolean;
  reason: string;
  remediation: string[];
}

// ── bounds (a hostile or broken payload cannot blow up the render) ───────────

const MAX_NODES = 64;          // server caps at 24 (+ "N more"); headroom only
const MAX_EDGES = 256;
const MAX_FAULTS = 128;
const MAX_CAUSAL = 512;
const MAX_SOURCES = 16;
const MAX_REFS = 20;
const MAX_STR = 512;
const MAX_TEXT = 2000;

const STATES: ReadonlySet<string> = new Set(["topology_with_path", "topology_only", "device_only", "no_asset_mapping"]);
const RELATIONS: ReadonlySet<string> = new Set(["verified", "suspected", "unknown"]);

function obj(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function str(v: unknown, max = MAX_STR): string {
  return typeof v === "string" ? v.slice(0, max) : "";
}
function optStr(v: unknown, max = MAX_STR): string | undefined {
  const s = str(v, max);
  return s ? s : undefined;
}
function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}
function bool(v: unknown): boolean {
  return v === true;
}
function strList(v: unknown, max: number, each = MAX_STR): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    if (out.length >= max) break;
    const s = str(x, each);
    if (s) out.push(s);
  }
  return out;
}
function list<T>(v: unknown, max: number, read: (o: Record<string, unknown>) => T | null): T[] {
  if (!Array.isArray(v)) return [];
  const out: T[] = [];
  for (const x of v) {
    if (out.length >= max) break;
    const o = obj(x);
    if (!o) continue;
    const t = read(o);
    if (t) out.push(t);
  }
  return out;
}

/**
 * readTopologyContext — the validated topology context from an RCA report JSON
 * (the whole report, or the `topology_context` value itself). Absent, malformed
 * or an unknown state → null: the caller then says the context was not built,
 * never guesses one.
 */
export function readTopologyContext(report: unknown): TopologyContext | null {
  const root = obj(report);
  if (!root) return null;
  const tc = obj(root.topology_context) ?? (typeof root.state === "string" ? root : null);
  if (!tc) return null;
  const state = str(tc.state);
  if (!STATES.has(state)) return null;

  const nodes = list(tc.nodes, MAX_NODES, (o): TopoCtxNode | null => {
    const id = str(o.id);
    if (!id) return null;
    return {
      id, label: str(o.label) || id, role: optStr(o.role), source: str(o.source),
      anchor: bool(o.anchor), managed: bool(o.managed),
      first_seen: optStr(o.first_seen), last_seen: optStr(o.last_seen), stale: bool(o.stale),
    };
  });
  // De-duplicate by id: a repeated id is the same node, never a second one.
  const seen = new Set<string>();
  const uniqNodes = nodes.filter((n) => (seen.has(n.id) ? false : (seen.add(n.id), true)));

  const edges = list(tc.edges, MAX_EDGES, (o): TopoCtxEdge | null => {
    const id = str(o.id), a = str(o.a), b = str(o.b);
    // An edge must join two nodes the server drew; otherwise it is dropped —
    // the UI never adds an endpoint to make an edge fit.
    if (!id || !a || !b || a === b || !seen.has(a) || !seen.has(b)) return null;
    return {
      id, a, b, a_port: optStr(o.a_port), b_port: optStr(o.b_port),
      relationship: str(o.relationship), protocol: optStr(o.protocol),
      sources: strList(o.sources, 8), confidence: num(o.confidence) || undefined,
      bidirectional: bool(o.bidirectional), first_seen: optStr(o.first_seen), last_seen: optStr(o.last_seen),
      stale: bool(o.stale), freshness: str(o.freshness),
    };
  });

  const faults = list(tc.faults, MAX_FAULTS, (o): FaultMark | null => {
    const tt = str(o.target_type);
    const target = str(o.target_id), device = str(o.device);
    if ((tt !== "node" && tt !== "interface") || !target || !device) return null;
    return {
      target_type: tt, target_id: target, device, port: optStr(o.port),
      kinds: strList(o.kinds, 12), peak_severity: str(o.peak_severity, 16).toLowerCase(),
      evidence_refs: strList(o.evidence_refs, MAX_REFS),
    };
  });

  const causal = list(tc.causal, MAX_CAUSAL, (o): CausalMark | null => {
    const from = str(o.from), to = str(o.to), rel = str(o.relation);
    if (!from || !to || !RELATIONS.has(rel)) return null;
    return {
      from, to, from_type: str(o.from_type), to_type: str(o.to_type),
      from_kind: optStr(o.from_kind), to_kind: optStr(o.to_kind),
      relation: rel as CausalRelation, directed: bool(o.directed),
      basis: str(o.basis, MAX_TEXT), direction_conf: num(o.direction_conf),
      evidence_refs: strList(o.evidence_refs, MAX_REFS),
    };
  });

  const sources = list(tc.sources, MAX_SOURCES, (o): TopologySource | null => {
    const kind = str(o.kind);
    if (!kind) return null;
    return {
      kind, status: str(o.status), rows: Math.max(0, Math.trunc(num(o.rows))),
      observed_at: optStr(o.observed_at), stale: bool(o.stale), freshness: str(o.freshness),
      detail: optStr(o.detail, MAX_TEXT),
    };
  });

  return {
    state: state as TopologyState,
    sources,
    anchors: strList(tc.anchors, MAX_NODES),
    unmapped: strList(tc.unmapped, MAX_NODES),
    nodes: uniqNodes,
    edges,
    more_nodes: Math.max(0, Math.trunc(num(tc.more_nodes))),
    faults,
    causal,
    has_spine: !!obj(tc.spine),
    reason: str(tc.reason, MAX_TEXT),
    remediation: strList(tc.remediation, 12, MAX_TEXT),
  };
}

// ── wording — mirrors the server partial word for word ───────────────────────

/** The state, in the words the server document uses (topoStateLabel). */
export function topoStateLabel(s: string): string {
  switch (s) {
    case "topology_with_path": return "topology with measured path";
    case "topology_only": return "known topology, no measured path";
    case "device_only": return "device only — no neighbour or path data";
    case "no_asset_mapping": return "no asset mapping";
  }
  return "unknown";
}

/** A source kind in plain words (topoCtxSourceLabel). */
export function topoSourceLabel(kind: string): string {
  switch (kind) {
    case "lldp": return "LLDP";
    case "cdp": return "CDP";
    case "bgp_ls": return "BGP-LS";
    case "topology_graph": return "the persisted topology graph";
    case "sdwan_overlay": return "the SD-WAN overlay";
    case "controller": return "the SD-WAN controller";
    case "inventory": return "the inventory";
  }
  return kind;
}

/** The sources that contributed rows, in words (topoSourcesLine). */
export function topoSourcesLine(tc: TopologyContext): string {
  const withRows: string[] = [];
  let inv = false;
  for (const s of tc.sources) {
    if (s.status !== "read" || s.rows === 0) continue;
    if (s.kind === "inventory") { inv = true; continue; }
    let label = topoSourceLabel(s.kind).replace(/^the /, "");
    if (s.freshness === "stale") label += " (stale)";
    withRows.push(label);
  }
  if (tc.has_spine) withRows.unshift("measured path");
  if (withRows.length > 0 && inv) return `${withRows.join(", ")}, inventory`;
  if (withRows.length > 0) return withRows.join(", ");
  if (inv) return "inventory only";
  return "none readable";
}

/** Sources that were read and returned nothing (the device card's "Read and empty"). */
export function readAndEmptySources(tc: TopologyContext): TopologySource[] {
  return tc.sources.filter((s) => s.kind !== "inventory" && s.status === "read" && s.rows === 0);
}

/** Sources that could not be read when the report was generated. */
export function unreadSources(tc: TopologyContext): TopologySource[] {
  return tc.sources.filter((s) => s.kind !== "inventory" && s.status === "unavailable");
}

/** The causal relation as the document words it ("? unknown" keeps the mark). */
export function causalRelationLabel(r: CausalRelation): string {
  return r === "unknown" ? "? unknown" : r;
}

/** An RFC 3339 instant as the document prints it ("2026-11-12 04:57 UTC"). */
export function topoTS(rfc: string | undefined): string {
  if (!rfc) return "";
  const t = Date.parse(rfc);
  if (!Number.isFinite(t)) return rfc;
  return new Date(t).toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

/** An engine word with underscores, as plain words ("wan_edge" → "wan edge"). */
export function humanWord(s: string | undefined): string {
  return (s ?? "").replace(/_/g, " ");
}

/** Interface faults on one device, in server order. */
export function interfaceFaults(tc: TopologyContext, device: string): FaultMark[] {
  return tc.faults.filter((f) => f.target_type === "interface" && f.device === device);
}

/** The device's own (non-interface) fault kinds. */
export function deviceFaultKinds(tc: TopologyContext, device: string): string[] {
  return tc.faults.filter((f) => f.target_type === "node" && f.device === device).flatMap((f) => f.kinds);
}

// The server's severity ladder (topoCtxSevRank): anything else ranks -1.
const SEV_RANK: Record<string, number> = { info: 0, warn: 1, warning: 1, high: 2, crit: 3, critical: 3 };

/** The device's peak severity across its own and its interfaces' marks ("" = none). */
export function devicePeak(tc: TopologyContext, device: string): string {
  let best = "", rank = -1;
  for (const f of tc.faults) {
    if (f.device !== device) continue;
    const r = Object.prototype.hasOwnProperty.call(SEV_RANK, f.peak_severity) ? SEV_RANK[f.peak_severity] : -1;
    if (r > rank) { rank = r; best = f.peak_severity; }
  }
  return best;
}

/** Severity → the overlay tone (crit is red; anything else observed is amber). */
export function severityTone(sev: string): "none" | "amber" | "red" {
  if (!sev) return "none";
  return sev === "crit" || sev === "critical" ? "red" : "amber";
}
