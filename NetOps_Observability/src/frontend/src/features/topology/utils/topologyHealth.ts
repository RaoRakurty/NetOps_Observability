// topologyHealth.ts — the single source of truth for how health, confidence and
// source map to visual treatment. Nodes, edges, legend, drawer and overlays all
// import from here so the design system stays consistent (PDF §11).
//
// Rule: color is never the only signal, and we use rings/badges — never a full
// red/orange node fill.

import type { Health, TopologySource, EvidenceRef, TopologyEdge, EdgeVariant } from "../api/topologyTypes";

/** Calm, premium NOC palette. Slate for unknown so it reads as "no signal", not alarm. */
export const HEALTH_COLOR: Record<Health, string> = {
  ok: "#16a34a",
  warning: "#d97706",
  critical: "#dc2626",
  unknown: "#64748b",
};

/** Soft tint behind a health ring (used for the ring track, not a node fill). */
export const HEALTH_TINT: Record<Health, string> = {
  ok: "rgba(22,163,74,0.14)",
  warning: "rgba(217,119,6,0.16)",
  critical: "rgba(220,38,38,0.18)",
  unknown: "rgba(100,116,139,0.12)",
};

export const HEALTH_LABEL: Record<Health, string> = {
  ok: "Healthy",
  warning: "Warning",
  critical: "Critical",
  unknown: "Unknown",
};

/** Short uppercase glyph for the accessibility "color is not the only signal" rule. */
export const HEALTH_GLYPH: Record<Health, string> = {
  ok: "OK",
  warning: "!",
  critical: "✕",
  unknown: "?",
};

/** Worst-wins rollup for groups. */
export function rollupHealth(items: { health?: Health; status?: Health }[]): Health {
  const order: Health[] = ["critical", "warning", "unknown", "ok"];
  for (const h of order) {
    if (items.some((i) => (i.health ?? i.status) === h)) return h;
  }
  return "ok";
}

/** Per-source baseline confidence guidance (PDF §8). Used to sanity-check facts. */
export const SOURCE_BASE_CONFIDENCE: Record<TopologySource, number> = {
  lldp: 0.95,
  cdp: 0.93,
  bgp_ls: 0.9,
  isis_lsdb: 0.9,
  ospf_lsdb: 0.88,
  snmp: 0.8,
  netbox: 0.85,
  cloud_api: 0.92,
  k8s_api: 0.9,
  metric: 0.7,
  trace: 0.75,
  flow: 0.5, // flow-only dependencies are dashed + lower confidence
  syslog: 0.55,
  manual: 0.8,
};

export const SOURCE_LABEL: Record<TopologySource, string> = {
  lldp: "LLDP",
  cdp: "CDP",
  snmp: "SNMP",
  bgp_ls: "BGP-LS",
  isis_lsdb: "IS-IS LSDB",
  ospf_lsdb: "OSPF LSDB",
  netbox: "NetBox",
  cloud_api: "Cloud API",
  k8s_api: "Kubernetes",
  flow: "Flow",
  trace: "Trace",
  syslog: "Syslog",
  metric: "Metric",
  manual: "Manual",
};

/** A 0..1 confidence → percent string for badges/drawer. */
export function confidencePct(c: number): string {
  return `${Math.round(Math.max(0, Math.min(1, c)) * 100)}%`;
}

/** Confidence band → label/tone for the ConfidencePanel. */
export function confidenceBand(c: number): { label: string; tone: Health } {
  if (c >= 0.85) return { label: "High", tone: "ok" };
  if (c >= 0.6) return { label: "Probable", tone: "warning" };
  return { label: "Low", tone: "critical" };
}

/**
 * Choose the edge VARIANT (visual treatment) from the domain edge. This is where
 * "never draw a link without evidence" + confidence + relationship become a style.
 * Bundled wins (collapsed parallel links); then degraded (unhealthy); then inferred
 * / flow (dashed, low confidence); else the plain topology edge.
 */
export function edgeVariant(edge: TopologyEdge): EdgeVariant {
  if (edge.bundle_id && (edge.bundle_count ?? 1) > 1) return "bundled";
  if (edge.status === "critical" || edge.status === "warning") return "degraded";
  if (edge.relationship === "inferred" || edge.relationship === "dependency" || edge.confidence < 0.6) return "inferred";
  return "topology";
}

/** True when an edge has real evidence. The adapter must drop edges that fail this. */
export function hasEvidence(evidence: EvidenceRef[] | undefined): boolean {
  return Array.isArray(evidence) && evidence.length > 0;
}

/** One-line edge summary for hover, e.g. "LLDP confirmed · confidence 98%". */
export function edgeEvidenceSummary(edge: TopologyEdge): string {
  const src = SOURCE_LABEL[edge.protocol_source] ?? edge.protocol_source;
  const bi = edge.direction === "bi" ? "bidirectional " : "";
  return `${bi}${src} · confidence ${confidencePct(edge.confidence)}`;
}
