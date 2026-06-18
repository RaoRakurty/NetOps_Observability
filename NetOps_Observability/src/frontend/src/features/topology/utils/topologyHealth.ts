// topologyHealth.ts — the single source of truth for how health, confidence,
// status and source map to visual treatment. Nodes, edges, legend, drawer and
// overlays import from here so the design system stays consistent.
//
// Rule: color is never the only signal (pair with glyph/label); use rings/badges,
// never a full red/orange node fill.

import type { Health, EdgeStatus, TopologySource, EvidenceRef, TopologyEdge, EdgeVariant } from "../api/topologyTypes";

/** Calm, premium NOC palette. `maintenance` reads as intentional (sky), not alarm. */
export const HEALTH_COLOR: Record<Health, string> = {
  ok: "#16a34a",
  warning: "#d97706",
  critical: "#dc2626",
  unknown: "#64748b",
  maintenance: "#0284c7",
};

export const HEALTH_TINT: Record<Health, string> = {
  ok: "rgba(22,163,74,0.14)",
  warning: "rgba(217,119,6,0.16)",
  critical: "rgba(220,38,38,0.18)",
  unknown: "rgba(100,116,139,0.12)",
  maintenance: "rgba(2,132,199,0.14)",
};

export const HEALTH_LABEL: Record<Health, string> = {
  ok: "Healthy",
  warning: "Warning",
  critical: "Critical",
  unknown: "Unknown",
  maintenance: "Maintenance",
};

/** Short glyph so color isn't the only signal (accessibility rule). */
export const HEALTH_GLYPH: Record<Health, string> = {
  ok: "OK",
  warning: "!",
  critical: "✕",
  unknown: "?",
  maintenance: "⚙",
};

/** Map an edge's link status to a Health band for colouring. */
export function statusToHealth(status?: EdgeStatus): Health {
  switch (status) {
    case "up":
      return "ok";
    case "down":
      return "critical";
    case "degraded":
    case "warning":
      return "warning";
    case "maintenance":
      return "maintenance";
    default:
      return "unknown";
  }
}

/** Worst-wins rollup for groups (maintenance is calm, ranked below warning). */
export function rollupHealth(items: { health?: Health }[]): Health {
  const order: Health[] = ["critical", "warning", "maintenance", "unknown", "ok"];
  for (const h of order) if (items.some((i) => i.health === h)) return h;
  return "ok";
}

/** Per-source baseline confidence (skill topology-fact-model.md). */
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
  flow: 0.65, // flow-only dependency
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

/** Confidence thresholds: below LOW = inferred/dashed; below DOTTED = dotted line. */
export const LOW_CONFIDENCE = 0.6;
export const DOTTED_CONFIDENCE = 0.5;

export function confidencePct(c: number): string {
  return `${Math.round(Math.max(0, Math.min(1, c)) * 100)}%`;
}

export function confidenceBand(c: number): { label: string; tone: Health } {
  if (c >= 0.85) return { label: "High", tone: "ok" };
  if (c >= LOW_CONFIDENCE) return { label: "Probable", tone: "warning" };
  return { label: "Low", tone: "critical" };
}

/**
 * Choose the edge VARIANT (visual treatment) from the flat edge. Bundled wins
 * (collapsed parallel links); then degraded (unhealthy status); then inferred
 * (inferred/dependency/flow OR low confidence → InferredEdge picks dashed vs
 * dotted); else the plain topology edge.
 */
export function edgeVariant(edge: TopologyEdge): EdgeVariant {
  if (edge.bundle_id && (edge.bundle_count ?? 1) > 1) return "bundled";
  const h = statusToHealth(edge.status);
  if (h === "critical" || h === "warning") return "degraded";
  if (
    edge.relationship === "inferred" ||
    edge.relationship === "dependency" ||
    edge.protocol === "flow" ||
    edge.confidence < LOW_CONFIDENCE
  )
    return "inferred";
  return "topology";
}

/** True when an edge has real evidence. The adapter drops edges that fail this. */
export function hasEvidence(evidence: EvidenceRef[] | undefined): boolean {
  return Array.isArray(evidence) && evidence.length > 0;
}

/** One-line edge summary for hover, e.g. "bidirectional LLDP · confidence 98%". */
export function edgeEvidenceSummary(edge: TopologyEdge): string {
  const src = edge.protocol ? SOURCE_LABEL[edge.protocol] : "topology";
  const bi = edge.direction === "bi" ? "bidirectional " : "";
  return `${bi}${src} · confidence ${confidencePct(edge.confidence)}`;
}
