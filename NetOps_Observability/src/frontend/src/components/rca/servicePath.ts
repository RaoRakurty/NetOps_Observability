import type { CorrTimeline } from "../../services/api";

// servicePath.ts — the FRONTEND-SIDE READ MODEL for the frozen Service Path Graph
// contract (docs/design/service-path-graph-contract.md, v1).
//
// THE RULE (contract §7): "the UI is a dumb layout of this spine. It MUST NOT
// compute hop order, MUST NOT lay out from node degree, and MUST NOT fall back to
// a star for a path-focused RCA. If the backend supplies no spine, the UI says so
// — it does not invent one."
//
// So this file does exactly two things:
//   1. defines the contract's §7 wire shape as TypeScript types, and
//   2. VALIDATES an untrusted payload into it (zero trust, CLAUDE.md §3 — the API
//      response is an input like any other; a malformed spine yields `null`, never
//      a half-invented path).
// It contains NO hop inference, NO ordering, NO degree math. The backend owns all
// of that. `topoGraph.ts` lays the result out; nothing else reads the raw payload.

// ── §7 wire types ──────────────────────────────────────────────────────────────

// Endpoint/hop kinds — contract §2.1 `Endpoint.kind` plus `application` (the
// service itself, the last node of the §10 acceptance spine).
export type SpineKind =
  | "client" | "lan_gateway" | "wan_edge" | "nva" | "cloud_edge"
  | "app_endpoint" | "service_endpoint" | "application" | "transit" | "unknown";

export type HopState = "responding" | "missing" | "filtered";           // §2.4
export type Transformation =                                            // §2.4
  | "none" | "nat" | "proxy" | "load_balancer" | "tunnel_ingress" | "tunnel_egress";
export type Confidence = "authoritative" | "strong" | "candidate" | "unknown"; // §3
export type DataClass = "live" | "synthetic" | "replay" | "lab";        // §1

// Every rendered edge must be able to state THIS (contract §5). No evidence ⇒ the
// edge is not rendered.
export interface SpineEvidence {
  ref: string;                 // provenance_id — the evidence handle (§1)
  method: string;              // traceroute_icmp | traceroute_tcp | stamp | transaction | flow_stitch
  confidence: Confidence;
  observed_at: string;
  data_class: DataClass;
}

export interface SpineNode {
  index: number;               // ORDERED by the backend. The spine order is DATA.
  kind: SpineKind;
  label: string;
  address?: string;            // null/absent when state != responding (§2.4)
  boundary?: string;           // LAN | SD-WAN | CARRIER | CLOUD | …
  entity_ref?: string;         // device_id | cloud_resource_id | interface_id
  state: HopState;
  transformation?: Transformation;
  seam_id?: string;
  // Cloud provider whose DECLARED inventory claims this hop's address
  // (aws | azure | gcp) — stamped by the backend, never guessed client-side.
  provider?: string;
  rtt_ms?: number;
  // repeat_count > 1: this node stands for that many CONSECUTIVE measured TTLs
  // with the identical answer (a dying path answers every remaining TTL from the
  // drop point). The backend folds the ladder; the count keeps it honest.
  repeat_count?: number;
  // OPTIONAL backend extension: which hop the RCA verdict lands on. Absent ⇒ the
  // renderer marks NO fault (it must never pick one itself).
  // "last_response" = a measurement FACT (where the run stopped answering),
  // carrying no blame; broken/suspected additionally attribute the case to it.
  fault?: "broken" | "suspected" | "possible" | "last_response";
  evidence?: SpineEvidence;
}

export interface SpineEdge {
  from: number;                // spine index (not a node id)
  to: number;
  type: string;                // PATH_HAS_HOP | CROSSES_SEAM | HOP_RESOLVES_TO | …
  seam_id?: string;
  transformation?: Transformation;
  // OPTIONAL backend extension: segment health. Absent ⇒ derived from hop state
  // only (unknown across an unknown hop, healthy otherwise) — never invented.
  state?: "healthy" | "degraded" | "suspected_down" | "confirmed_down" | "unknown";
  evidence?: SpineEvidence;
}

export interface SpineBoundary { name: string; from: number; to: number; }

// Evidence branches attach OFF the spine (contract §7) — metrics, logs, flows,
// alerts, traces. They annotate a hop; they must never reorder or displace it.
export interface SpineBranch {
  attach_index: number;
  class: string;               // metrics | logs | flows | alerts | traces
  label: string;
  summary?: string;
  count?: number;
  evidence?: SpineEvidence;
}

export interface ServicePath {
  spine: SpineNode[];
  edges: SpineEdge[];
  boundaries: SpineBoundary[];
  evidence_branches: SpineBranch[];
  contract_version?: number;
}

// ── validation (zero trust) ────────────────────────────────────────────────────

const KINDS: SpineKind[] = [
  "client", "lan_gateway", "wan_edge", "nva", "cloud_edge",
  "app_endpoint", "service_endpoint", "application", "transit", "unknown",
];
const STATES: HopState[] = ["responding", "missing", "filtered"];
const TRANSFORMS: Transformation[] = ["none", "nat", "proxy", "load_balancer", "tunnel_ingress", "tunnel_egress"];
const CONFIDENCES: Confidence[] = ["authoritative", "strong", "candidate", "unknown"];
const DATA_CLASSES: DataClass[] = ["live", "synthetic", "replay", "lab"];
const EDGE_STATES = ["healthy", "degraded", "suspected_down", "confirmed_down", "unknown"] as const;

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
const num = (v: unknown): number | undefined => (typeof v === "number" && isFinite(v) ? v : undefined);
const oneOf = <T extends string>(v: unknown, allowed: readonly T[]): T | undefined => {
  const s = str(v).toLowerCase();
  return (allowed as readonly string[]).includes(s) ? (s as T) : undefined;
};

// An edge/branch may be rendered ONLY if it can state its evidence (contract §5).
// A record with no ref or no observation method cannot — so it is dropped here and
// never reaches the canvas.
export function readEvidence(v: unknown): SpineEvidence | undefined {
  if (!v || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  const ref = str(o.ref) || str(o.evidence_ref) || str(o.provenance_id);
  const method = str(o.method) || str(o.observation_method);
  if (!ref || !method) return undefined;
  return {
    ref, method,
    confidence: oneOf(o.confidence, CONFIDENCES) ?? "unknown",
    observed_at: str(o.observed_at),
    data_class: oneOf(o.data_class, DATA_CLASSES) ?? "live",
  };
}
export function hasEvidence(e: { evidence?: SpineEvidence }): boolean {
  return !!e.evidence?.ref && !!e.evidence.method;
}

function readNode(v: unknown): SpineNode | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const index = num(o.index) ?? num(o.hop_index);
  if (index === undefined || index < 0 || !Number.isInteger(index)) return null;   // no index ⇒ no order ⇒ not a hop
  const state = oneOf(o.state, STATES) ?? "responding";
  const address = str(o.address) || str(o.observed_address);
  const label = str(o.label) || address || (state === "responding" ? "" : "Unknown hop");
  if (!label) return null;
  return {
    index,
    kind: oneOf(o.kind, KINDS) ?? "unknown",
    label,
    address: address || undefined,
    boundary: str(o.boundary) || undefined,
    entity_ref: str(o.entity_ref) || str(o.resolved_entity_ref) || undefined,
    state,
    transformation: oneOf(o.transformation, TRANSFORMS),
    seam_id: str(o.seam_id) || undefined,
    provider: str(o.provider) || undefined,
    rtt_ms: num(o.rtt_ms),
    repeat_count: num(o.repeat_count),
    fault: oneOf(o.fault, ["broken", "suspected", "possible", "last_response"] as const),
    evidence: readEvidence(o.evidence),
  };
}

// readServicePath — parse the path block off the RCA payload. Accepts either the
// §7 object (`timeline.path`) or a bare `timeline.spine` array, both of which the
// backend may embed. Returns null when there is NO usable spine — the caller then
// says so honestly rather than inventing one.
export function readServicePath(timeline: CorrTimeline | null | undefined): ServicePath | null {
  if (!timeline) return null;
  const t = timeline as unknown as Record<string, unknown>;
  const blockRaw = (t.path ?? t.service_path ?? t.path_graph) as unknown;
  const block = (blockRaw && typeof blockRaw === "object" ? blockRaw : t) as Record<string, unknown>;
  const rawSpine = block.spine;
  if (!Array.isArray(rawSpine) || rawSpine.length === 0) return null;

  const spine: SpineNode[] = [];
  const seen = new Set<number>();
  for (const r of rawSpine) {
    const n = readNode(r);
    if (!n || seen.has(n.index)) continue;   // duplicate index = ambiguous order ⇒ drop
    seen.add(n.index);
    spine.push(n);
  }
  if (spine.length === 0) return null;

  const edges: SpineEdge[] = [];
  for (const r of Array.isArray(block.edges) ? block.edges : []) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const from = num(o.from), to = num(o.to);
    if (from === undefined || to === undefined || from === to) continue;
    if (!seen.has(from) || !seen.has(to)) continue;      // an edge to a hop we don't have is not renderable
    const evidence = readEvidence(o.evidence);
    if (!evidence) continue;                             // §5: no evidence ⇒ NOT RENDERED
    edges.push({
      from, to,
      type: str(o.type) || "PATH_HAS_HOP",
      seam_id: str(o.seam_id) || undefined,
      transformation: oneOf(o.transformation, TRANSFORMS),
      state: oneOf(o.state, EDGE_STATES),
      evidence,
    });
  }

  const boundaries: SpineBoundary[] = [];
  for (const r of Array.isArray(block.boundaries) ? block.boundaries : []) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const name = str(o.name);
    const from = num(o.from), to = num(o.to);
    if (!name || from === undefined || to === undefined || to < from) continue;
    if (!seen.has(from) || !seen.has(to)) continue;
    boundaries.push({ name, from, to });
  }

  const evidence_branches: SpineBranch[] = [];
  for (const r of Array.isArray(block.evidence_branches) ? block.evidence_branches : []) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const attach = num(o.attach_index) ?? num(o.index) ?? num(o.hop_index);
    if (attach === undefined || !seen.has(attach)) continue;
    const cls = (str(o.class) || str(o.kind) || str(o.type)).toLowerCase();
    if (!cls) continue;
    const evidence = readEvidence(o.evidence);
    if (!evidence) continue;                             // §5 again — an unevidenced branch is not shown
    evidence_branches.push({
      attach_index: attach,
      class: cls,
      label: str(o.label) || branchClassLabel(cls),
      summary: str(o.summary) || str(o.note) || undefined,
      count: num(o.count),
      evidence,
    });
  }

  return { spine, edges, boundaries, evidence_branches, contract_version: num(block.contract_version) };
}

// isPathFocused — is this RCA object about a SERVICE PATH (client → … → app)?
// Path-focused objects MUST come from the backend spine; when one is missing the
// renderer says so (contract §7) instead of falling back to a star. Network-only
// objects (device / interface / routing evidence) keep their contextual view.
const PATH_ENTITY = /^(path|app|application|service|cloud_resource|endpoint)$/i;
export function isPathFocused(timeline: CorrTimeline | null | undefined): boolean {
  if (!timeline) return false;
  if (readServicePath(timeline)) return true;
  return (timeline.signals ?? []).some(
    (s) => s.attached && !s.kind.endsWith("_clear") && PATH_ENTITY.test(s.entity_type),
  );
}

// ── operator language (no engine tokens on screen) ─────────────────────────────

const METHOD_LABEL: Record<string, string> = {
  traceroute_icmp: "ICMP path trace",
  traceroute_tcp: "TCP path trace",
  stamp: "Active path measurement",
  transaction: "Application transaction",
  flow_stitch: "Traffic-flow session",
};
export function methodLabel(m: string): string {
  return METHOD_LABEL[m] ?? m.replace(/_/g, " ");
}

const TRANSFORM_LABEL: Record<Transformation, string> = {
  none: "",
  nat: "NAT",
  proxy: "Proxy",
  load_balancer: "Load balancer",
  tunnel_ingress: "Tunnel start",
  tunnel_egress: "Tunnel end",
};
export function transformationLabel(t?: Transformation): string {
  return t ? TRANSFORM_LABEL[t] ?? "" : "";
}

const KIND_LABEL: Record<SpineKind, string> = {
  client: "Client",
  lan_gateway: "LAN gateway",
  wan_edge: "WAN edge",
  nva: "Network appliance",
  cloud_edge: "Cloud edge",
  app_endpoint: "Application endpoint",
  service_endpoint: "Service endpoint",
  application: "Application",
  transit: "Transit hop",
  unknown: "Unidentified hop",
};
export function spineKindLabel(k: SpineKind): string {
  return KIND_LABEL[k] ?? k.replace(/_/g, " ");
}

export function hopStateLabel(s: HopState): string {
  return s === "responding" ? "responded" : s === "missing" ? "no response" : "filtered";
}

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  authoritative: "Authoritative",
  strong: "Strong",
  candidate: "Candidate",
  unknown: "Unresolved",
};
export function confidenceLabel(c: Confidence): string {
  return CONFIDENCE_LABEL[c] ?? c;
}

const BRANCH_LABEL: Record<string, string> = {
  metrics: "Metrics", logs: "Logs", flows: "Traffic flows",
  alerts: "Alerts", traces: "Traces",
};
export function branchClassLabel(c: string): string {
  return BRANCH_LABEL[c] ?? c.replace(/_/g, " ");
}
