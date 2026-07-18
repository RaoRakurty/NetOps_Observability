// serviceMap.ts — the observed cloud service dependency map (Wave 3 #9 carried,
// tracker #110): the pure transform from the GET /api/cloud/service-map wire
// shape to the view model the Service Map canvas renders.
//
// Honesty contract (mirrors the backend's — cloud_service_map.go):
//   * every node/edge is OBSERVED traffic; nothing here infers, promotes or
//     disguises. A node the backend did not resolve renders as an unattributed
//     endpoint — even if a malformed row claims kind "service".
//   * blocked evidence is an observation COUNT (provider REJECT semantics
//     differ), never bytes — it must never feed the volume weight.
//   * the meta block becomes the caption labels verbatim-derived (window, pair
//     signals, resolved/unresolved endpoints, truncation) so the canvas can
//     never claim more than the window actually held.
//
// Pure + deterministic → unit-tested (serviceMap.test.ts). React Flow types
// never appear here (topology-ui rule: no API-domain/renderer type mixing).

import { fmtBytes } from "./badges";
import { rangeWords } from "./range";

// ── wire shapes (GET /api/cloud/service-map) ─────────────────────────────────

export interface ServiceMapWireNode {
  id: string;
  label: string;
  kind: string; // "service" | "endpoint"
  resolved: boolean;
  bytes: number;
  providers: string[];
}

export interface ServiceMapWireEdge {
  source_service: string;
  dest_service: string;
  relationship: string; // always "talks_to" — observed traffic
  bytes: number; // ACCEPTED volume only, never REJECT-derived
  pair_count: number;
  blocked: boolean;
  blocked_count: number;
  providers: string[];
}

export interface ServiceMapWireMeta {
  window_hours: number;
  pair_signals: number;
  resolved_endpoints: number;
  unresolved_endpoints: number;
  unattributed_shown: number;
  unattributed_dropped: number;
  generated_at: string;
}

export interface ServiceMapWire {
  nodes: ServiceMapWireNode[];
  edges: ServiceMapWireEdge[];
  meta: ServiceMapWireMeta;
}

// ── view model ───────────────────────────────────────────────────────────────

export type SvcMapNodeKind = "service" | "endpoint";

/** Node footprint per size bucket — the SAME numbers feed ELK and the DOM, so
 *  the layout can never disagree with what renders. */
export const SVCMAP_NODE_SIZE: Record<1 | 2 | 3, { width: number; height: number }> = {
  1: { width: 148, height: 52 },
  2: { width: 172, height: 58 },
  3: { width: 198, height: 64 },
};

export interface SvcMapNode {
  id: string;
  label: string;
  kind: SvcMapNodeKind;
  resolved: boolean;
  bytes: number;
  /** "—" when no accepted volume was observed (blocked-only participation). */
  bytesText: string;
  providers: string[];
  sizeBucket: 1 | 2 | 3; // relative observed volume → node weight
  width: number;
  height: number;
}

export interface SvcMapEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  bytes: number;
  bytesText: string;
  pairCount: number;
  blocked: boolean;
  blockedCount: number;
  providers: string[];
  /** stroke-weight bucket from ACCEPTED bytes only (blocked-only edges stay 1). */
  weight: 1 | 2 | 3 | 4;
}

/** The mandatory honesty labels, derived ONLY from meta — never re-counted
 *  client-side, so the caption states what the server actually aggregated. */
export interface SvcMapLabels {
  window: string; // "last 24 hours" — the server-honored window
  signals: string; // "132 pair signals aggregated"
  endpoints: string; // "5 resolved · 3 unresolved endpoints"
  truncation: string; // "" unless the unattributed budget dropped endpoints
  generatedAt: string; // raw ISO — the component formats it
}

export interface SvcMapView {
  nodes: SvcMapNode[];
  edges: SvcMapEdge[];
  labels: SvcMapLabels;
  /** nothing observed in the window — render the honest empty state. */
  empty: boolean;
}

// ── pure helpers (exported for tests) ────────────────────────────────────────

/** Relative log-scale bucket 1..max — log because observed bytes span orders of
 *  magnitude (a linear scale would flatten everything under the loudest edge). */
function logBucket(bytes: number, maxBytes: number, buckets: number): number {
  if (!(bytes > 0) || !(maxBytes > 0)) return 1;
  const r = Math.log1p(bytes) / Math.log1p(maxBytes);
  return Math.max(1, Math.min(buckets, 1 + Math.round(r * (buckets - 1))));
}

/** Edge stroke-weight bucket from ACCEPTED bytes (1..4). */
export function edgeWeight(bytes: number, maxBytes: number): 1 | 2 | 3 | 4 {
  return logBucket(bytes, maxBytes, 4) as 1 | 2 | 3 | 4;
}

/** Node size bucket from observed bytes (1..3). */
export function nodeSizeBucket(bytes: number, maxBytes: number): 1 | 2 | 3 {
  return logBucket(bytes, maxBytes, 3) as 1 | 2 | 3;
}

/** Honesty rule: only a backend-RESOLVED node may render as a service. */
export function nodeKind(n: Pick<ServiceMapWireNode, "kind" | "resolved">): SvcMapNodeKind {
  return n.resolved && n.kind === "service" ? "service" : "endpoint";
}

const plural = (n: number, word: string): string =>
  `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

/** The mandatory caption labels, straight from meta. */
export function mapLabels(meta: ServiceMapWireMeta): SvcMapLabels {
  return {
    window: rangeWords(Math.max(1, meta.window_hours) * 60),
    signals: `${plural(meta.pair_signals, "pair signal")} aggregated`,
    endpoints: `${meta.resolved_endpoints.toLocaleString()} resolved · ` +
      `${plural(meta.unresolved_endpoints, "unresolved endpoint")}`,
    truncation: meta.unattributed_dropped > 0
      ? `top ${meta.unattributed_shown} of ${meta.unresolved_endpoints} unattributed shown · ` +
        `${meta.unattributed_dropped} dropped`
      : "",
    generatedAt: meta.generated_at,
  };
}

// ── the transform ────────────────────────────────────────────────────────────

export function buildServiceMapView(wire: ServiceMapWire): SvcMapView {
  const wireNodes = wire.nodes ?? [];
  const wireEdges = wire.edges ?? [];

  const maxNodeBytes = wireNodes.reduce((m, n) => Math.max(m, n.bytes || 0), 0);
  const nodes: SvcMapNode[] = wireNodes
    .filter((n) => n.id)
    .map((n) => {
      const bytes = n.bytes > 0 ? n.bytes : 0;
      const sizeBucket = nodeSizeBucket(bytes, maxNodeBytes);
      return {
        id: n.id,
        label: n.label || n.id,
        kind: nodeKind(n),
        resolved: !!n.resolved,
        bytes,
        bytesText: bytes > 0 ? fmtBytes(bytes) : "—",
        providers: n.providers ?? [],
        sizeBucket,
        ...SVCMAP_NODE_SIZE[sizeBucket],
      };
    });

  // Zero-trust on the upstream shape: an edge may only reference nodes that are
  // actually on the map (drawing a link without both endpoints is forbidden).
  const known = new Set(nodes.map((n) => n.id));
  const maxEdgeBytes = wireEdges.reduce((m, e) => Math.max(m, e.bytes || 0), 0);
  const edges: SvcMapEdge[] = wireEdges
    .filter((e) => known.has(e.source_service) && known.has(e.dest_service) &&
      e.source_service !== e.dest_service)
    .map((e) => {
      const bytes = e.bytes > 0 ? e.bytes : 0; // blocked counts NEVER inflate volume
      return {
        id: `${e.source_service}→${e.dest_service}`,
        source: e.source_service,
        target: e.dest_service,
        relationship: e.relationship || "talks_to",
        bytes,
        bytesText: bytes > 0 ? fmtBytes(bytes) : "—",
        pairCount: e.pair_count > 0 ? e.pair_count : 0,
        blocked: !!e.blocked,
        blockedCount: e.blocked_count > 0 ? e.blocked_count : 0,
        providers: e.providers ?? [],
        weight: edgeWeight(bytes, maxEdgeBytes),
      };
    });

  return {
    nodes,
    edges,
    labels: mapLabels(wire.meta ?? {
      window_hours: 24, pair_signals: 0, resolved_endpoints: 0,
      unresolved_endpoints: 0, unattributed_shown: 0, unattributed_dropped: 0,
      generated_at: "",
    }),
    empty: nodes.length === 0,
  };
}
