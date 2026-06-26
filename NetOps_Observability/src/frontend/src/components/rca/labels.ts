// Human-readable labels for the operator-facing RCA story. The engine speaks in
// signature ids and signal kinds; operators need plain language. These maps turn
// `sig.ent.middle-mile.dia-egress-latency` → "ISP / DIA egress latency" and
// `probe_latency_departure` → "Probe latency departure — active probe", while the
// raw id stays available (rendered small/gray) for debugging.
import type { Tone } from "./rcaCase";

// NOC color system — tuned for engineers on wall + desk monitors, 24/7 day/night.
// Principle: the surface stays CALM (desaturated slate, off-white text, never pure
// black/white) so a quiet room reads as quiet; severity colors are the ONLY loud
// hues and are always paired with a glyph/label (colorblind-safe, color-not-only).
// All values clear WCAG 4.5:1 on the dark slate surfaces below.
// IMPORTANT: the app ships BOTH a light (default) and a dark theme. Text colors
// MUST defer to the theme tokens (var(--fg)/var(--muted)/var(--fg-subtle)) or
// they go invisible on the light canvas. Severity hues are mid-tone (≈600-level)
// so they read on a WHITE card and on dark slate alike — no neon (which only
// works on dark) and no pale (which only works on dark).
export const C = {
  // severity — mid-tone, theme-neutral (legible on white AND dark)
  crit: "#E11D48",        // critical / contradicts / malformed
  warn: "#D97706",        // warning / caution / needed-to-confirm / control-plane / seam
  caution: "#B45309",     // softer burnt-amber for inline warnings (calm caution, not alarm; AA on white)
  ok: "#16A34A",          // healthy / linked / supports
  info: "#2563EB",        // info / device-telemetry / present-not-linked
  flow: "#0D9488",        // flows (teal)
  discriminates: "#7C3AED", // discriminating evidence (violet)
  // text/surfaces — defer to theme tokens so they adapt light↔dark
  fg: "var(--fg)",        // primary text (theme-aware)
  muted: "#6B7280",       // secondary text — mid gray, readable on white + dark
  faint: "#8A93A6",       // tertiary / absent — lighter mid gray
  line: "var(--border)",  // borders/dividers (theme-aware)
  bg: "#0E1320",          // deepest surface, never #000
  panel: "#151B2B",       // card surface
} as const;

// Evidence planes — distinct, calm hues; always positioned + labeled so they read
// without relying on color alone. `label` is the NOC/operator name; `help` is the
// plain-English "what this is" line. Debug View shows the raw key instead (see
// modalityLabel(key, "debug")).
export const MODALITY_META: Record<string, { label: string; color: string; help: string }> = {
  device_telemetry: { label: "Device health", color: C.info, help: "interface errors, link counters, CPU, memory" },
  control_plane: { label: "Routing & link events", color: C.warn, help: "BGP, link up/down, syslog, traps" },
  passive_flow: { label: "Traffic flow evidence", color: C.flow, help: "traffic loss, volume drop, traffic shift" },
  active_probe: { label: "Active checks", color: C.ok, help: "ping, HTTP, STAMP, path checks" },
};

export const MODALITY_ORDER = ["device_telemetry", "control_plane", "passive_flow", "active_probe"];

// Operator View → NOC label ("Device health"); Debug View → raw engine key
// ("device_telemetry"). Most callers are operator paths and omit `view`.
export function modalityLabel(key: string, view: "operator" | "debug" = "operator"): string {
  if (view === "debug") return key;
  return MODALITY_META[key]?.label ?? key.replace(/_/g, " ");
}
export function modalityHelp(key: string): string {
  return MODALITY_META[key]?.help ?? "";
}

// Signature id → friendly "Domain / fault" title.
const SIG_NAME: Record<string, string> = {
  "sig.ent.middle-mile.dia-egress-latency": "ISP / DIA egress latency",
  "sig.ent.wan-edge.bgp-peer-flap": "BGP peer flap",
  "sig.ent.access.local-link-fault": "Local link fault",
  "sig.ent.wan-edge.congestion": "WAN edge congestion",
  "sig.ent.wan-edge.routing-instability": "Routing instability",
  "sig.ent.middle-mile.physical-degradation": "Circuit / optics degradation",
  "sig.ent.internet.dns-impairment": "Internet / DNS impairment",
  "sig.ent.cloud.region-degradation": "Cloud / region degradation",
  "sig.ent.wan-edge.tunnel-mtu-blackhole": "Tunnel MTU blackhole",
};

export function signatureName(id: string): string {
  if (SIG_NAME[id]) return SIG_NAME[id];
  // fallback: last two dotted segments, humanized — "sig.sp.foo.bar-baz" → "Foo / bar baz"
  const parts = id.replace(/^sig\./, "").split(".");
  const tail = parts.slice(-2);
  return tail.map((p, i) => {
    const t = p.replace(/-/g, " ");
    return i === 0 ? t.charAt(0).toUpperCase() + t.slice(1) : t;
  }).join(" / ");
}

// Operator View headline — NOC "Possible …" phrasing from a small, fixed
// vocabulary (NOT the technical signature name, and never the raw id). Debug View
// uses signatureName()/the raw id instead.
// Scenario-signature → factual NOC title (the #14 decision: titles state WHAT was
// observed, never the verdict — confirmed/suspected is carried by the RCA-state
// pill + the engine wording). Covers every signature the correlation engine emits
// today, plus the enterprise/SP/DC scenarios the Phase-2/3 catalog will add (SD-WAN,
// cloud, LAN access, app, MPLS, DC fabric, security) so wording is ready the moment
// a signature lands. Titles stay neutral and non-overclaiming per rca-copy-precision.
const SIG_NOC_TITLE: Record<string, string> = {
  // ── WAN edge / middle-mile / internet / cloud (emitted today) ──
  "sig.ent.middle-mile.dia-egress-latency": "Middle-mile latency increase",
  "sig.ent.middle-mile.physical-degradation": "Middle-mile path degradation",
  "sig.ent.wan-edge.bgp-peer-flap": "Routing adjacency change",
  "sig.ent.wan-edge.routing-instability": "Routing instability",
  "sig.ent.wan-edge.congestion": "WAN edge congestion",
  "sig.ent.wan-edge.tunnel-mtu-blackhole": "Path MTU blackhole",
  "sig.ent.access.local-link-fault": "Link state change",
  "sig.ent.internet.dns-impairment": "DNS resolution impairment",
  "sig.ent.cloud.region-degradation": "Cloud region degradation",
  "sig.ent.cloud.region-impairment": "Cloud region impairment",
  // ── SD-WAN overlay (Phase 2) ──
  "sig.ent.sdwan.tunnel-sla-breach": "SD-WAN tunnel SLA breach",
  "sig.ent.sdwan.tunnel-flap": "SD-WAN tunnel flap",
  "sig.ent.wan-edge.ipsec-down": "IPsec tunnel down",
  // ── Cloud reachability (Phase 3) ──
  "sig.ent.cloud.path-blocked": "Cloud path unreachable",
  "sig.ent.cloud.gateway-degradation": "Cloud gateway degradation",
  // ── LAN / access (Phase 2) ──
  "sig.ent.access.uplink-down": "Access uplink down",
  "sig.ent.access.qos-drops": "QoS drops on access",
  // ── Application (network attribution) ──
  "sig.ent.app.degradation-network-clear": "Application degradation (network clear)",
  // ── Service-provider core · DC fabric · security ──
  "sig.sp.core.mpls-lsp-down": "MPLS LSP down",
  "sig.dc.fabric.uplink-fault": "Fabric uplink fault",
  "sig.ent.security.fw-policy-drop": "Firewall policy drop",
};
// Dominant evidence plane → NOC headline when no signature has matched.
// Titles describe the OBSERVED condition factually — the NOT CONFIRMED / Confidence
// badges carry the verdict, not the title (no speculative "Possible …" hedging).
export const PLANE_NOC_TITLE: Record<string, string> = {
  active_probe: "Path performance change",
  device_telemetry: "Device health change",
  control_plane: "Routing adjacency change",
  passive_flow: "Traffic flow change",
};
// Domain-correct fallback for an unmapped signature — order matters: cloud and
// SD-WAN/tunnel are tested BEFORE the generic WAN/provider catch, so a cloud or
// overlay fault is never mislabelled "WAN / provider path change" (the bug the
// old single `cloud`-in-WAN branch caused).
export function signatureNocTitle(id: string): string {
  if (SIG_NOC_TITLE[id]) return SIG_NOC_TITLE[id];
  if (/cloud/.test(id)) return "Cloud service-path change";
  if (/sdwan|overlay|tunnel|ipsec/.test(id)) return "SD-WAN / tunnel change";
  if (/dns/.test(id)) return "DNS resolution impairment";
  if (/mpls|lsp|l3vpn|vrf/.test(id)) return "MPLS / VPN path change";
  if (/dia|middle-mile|internet|provider|congestion|wan/.test(id)) return "WAN / provider path change";
  if (/bgp|ospf|isis|routing/.test(id)) return "Routing adjacency change";
  if (/link|access|uplink/.test(id)) return "Link state change";
  if (/fw|firewall|policy|security/.test(id)) return "Security policy change";
  if (/device|resource|cpu|mem|hardware|fabric/.test(id)) return "Device health change";
  return "Network change observed";
}

// signal kind → (humanized label, modality, expected source).
const KIND_META: Record<string, { modality: string; source: string }> = {
  probe_rtt_anomaly: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_latency_departure: { modality: "active_probe", source: "STAMP / synthetic probes" },
  probe_loss: { modality: "active_probe", source: "STAMP / synthetic probes" },
  dns_latency_high: { modality: "active_probe", source: "DNS probes" },
  dns_failure_rate: { modality: "active_probe", source: "DNS probes" },
  bgp_state_anomaly: { modality: "device_telemetry", source: "gNMI / SNMP BGP-MIB" },
  bgp_adjacency_change: { modality: "control_plane", source: "syslog (%BGP ADJCHANGE)" },
  bgp_path_change: { modality: "control_plane", source: "BGP / routing telemetry" },
  ospf_adjacency_change: { modality: "control_plane", source: "syslog (%OSPF ADJCHANGE)" },
  link_state_change: { modality: "control_plane", source: "syslog (%LINK/%LINEPROTO)" },
  lldp_neighbor_change: { modality: "control_plane", source: "syslog / LLDP" },
  device_resource_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI host metrics" },
  if_metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  if_util_high: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  if_errors: { modality: "device_telemetry", source: "SNMP / gNMI interface counters" },
  metric_anomaly: { modality: "device_telemetry", source: "SNMP / gNMI metrics" },
  qos_drops: { modality: "device_telemetry", source: "SNMP / gNMI QoS counters" },
  lb_5xx: { modality: "passive_flow", source: "LB / app telemetry" },
  cloud_gw_anomaly: { modality: "passive_flow", source: "cloud gateway telemetry" },
  cloud_health_event: { modality: "passive_flow", source: "cloud health feed" },
  flow_volume_anomaly: { modality: "passive_flow", source: "NetFlow / IPFIX / sFlow" },
  tunnel_degraded: { modality: "active_probe", source: "tunnel probes" },
  tunnel_flap: { modality: "control_plane", source: "SD-WAN controller" },
};

// Routing-protocol signals that a NOC reads as "routing", regardless of HOW they
// were observed. The engine keeps these on their true modality_class for the
// independence math (a polled BGP metric and a BGP syslog event are independent
// observers); this is a DISPLAY-only test, used to place them on the operator
// timeline's "Routing & link events" lane where operators expect to find them.
export function isRoutingKind(kind: string): boolean {
  return /bgp|ospf|isis|^ldp|rsvp|adjacency|route_|_route|^bfd|peer/.test(kind);
}

export function kindMeta(kind: string): { modality: string; source: string } {
  if (KIND_META[kind]) return KIND_META[kind];
  if (/^probe_|_rtt|loss|latency/.test(kind)) return { modality: "active_probe", source: "synthetic probes" };
  if (/dns_/.test(kind)) return { modality: "active_probe", source: "DNS probes" };
  if (/bgp|ospf|isis|link|lldp|adjacency|_state_/.test(kind)) return { modality: "control_plane", source: "syslog / routing telemetry" };
  if (/flow|^cloud|lb_/.test(kind)) return { modality: "passive_flow", source: "flow / cloud telemetry" };
  return { modality: "device_telemetry", source: "device metrics" };
}

// Friendly NOC names for the engine's signal kinds. Used everywhere a kind is
// shown to an operator (timeline labels, marker panel, tooltips). Debug surfaces
// that need the exact engine kind use the raw `kind` string directly instead.
const KIND_NOC: Record<string, string> = {
  probe_rtt_anomaly: "Slower response", probe_latency_departure: "Response-time change",
  probe_loss: "Packet loss", dns_latency_high: "Slow DNS", dns_failure_rate: "DNS failures",
  if_metric_anomaly: "Interface counter change", if_util_high: "High link utilization",
  if_errors: "Interface errors", metric_anomaly: "Metric change",
  device_resource_anomaly: "Device CPU/memory change", qos_drops: "QoS drops",
  link_state_change: "Link up/down", lldp_neighbor_change: "Neighbor change",
  bgp_adjacency_change: "BGP neighbor change", bgp_state_anomaly: "BGP state change",
  bgp_path_change: "Route change", ospf_adjacency_change: "OSPF neighbor change",
  flow_volume_anomaly: "Traffic volume change", lb_5xx: "Gateway errors",
  cloud_gw_anomaly: "Cloud gateway change", cloud_health_event: "Cloud health event",
  tunnel_degraded: "Tunnel degraded", tunnel_flap: "Tunnel flap",
  // Cloud App Observability kinds (#81 P3G) — operator language for the cloud plane.
  cloud_health: "Cloud app health event", cloud_resource_health: "Cloud resource health change",
  cloud_metric: "Cloud metric change", database_metric: "Database metric change",
  cloud_flow_log: "Cloud flow-log change", cloud_lb_log: "Load-balancer error rate",
  cloud_change: "Cloud configuration change", cloud_audit: "Cloud audit event",
  security_policy_change: "Security policy change",
};
// "probe_latency_departure" → "Response-time change"; trims a trailing _clear.
export function kindLabel(kind: string): string {
  const base = kind.replace(/_clear$/, "");
  if (KIND_NOC[base]) return KIND_NOC[base];
  const words = base.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// Operator-facing evidence CLASS for a signal — the lane a NOC reads it as.
// Routing-protocol kinds (BGP/OSPF/ISIS/…) read as "routing/link" regardless of
// HOW they were observed: a *polled* BGP state metric (modality device_telemetry)
// is still routing evidence to an operator, NOT device health. So this classifies
// by isRoutingKind() over the raw modality_class. The engine's independence /
// verdict math always uses modality_class; this is DISPLAY-only. Pure + testable.
export function signalClassKey(s: { kind: string; modality_class: string }): string {
  return isRoutingKind(s.kind.replace(/_clear$/, "")) ? "control_plane" : s.modality_class;
}
// class key → the "<Class> signal:" prefix used on the selected-evidence panel.
const CLASS_SIGNAL_LABEL: Record<string, string> = {
  control_plane: "Routing/link signal",
  device_telemetry: "Device-health signal",
  passive_flow: "Traffic-flow signal",
  active_probe: "Active-check signal",
};
// class key → short noun for inline prose ("supporting routing/link evidence").
export const CLASS_NOUN: Record<string, string> = {
  control_plane: "routing/link", device_telemetry: "device-health",
  passive_flow: "traffic-flow", active_probe: "active-check",
};
// "Routing/link signal: BGP state change" — the operator title for one signal.
export function signalClassTitle(s: { kind: string; modality_class: string }): string {
  const key = signalClassKey(s);
  return `${CLASS_SIGNAL_LABEL[key] ?? "Signal"}: ${kindLabel(s.kind)}`;
}

// Probe authority model (Step 3) — operator labels + colors.
export const PROBE_AUTHORITY_META: Record<string, { label: string; color: string }> = {
  high: { label: "High authority", color: C.ok },
  medium: { label: "Medium authority", color: C.info },
  low: { label: "Low authority — support only", color: C.warn },
  debug_only: { label: "Debug / lab — excluded", color: C.faint },
};
export const PROBE_SCOPE_LABEL: Record<string, string> = {
  customer_path: "Customer path",
  service_dependency: "Service dependency",
  internal_self_probe: "Internal self-probe",
  synthetic_lab_probe: "Synthetic / lab probe",
  unknown: "Unclassified probe",
};
export function probeAuthorityLabel(a?: string): string {
  return a ? (PROBE_AUTHORITY_META[a]?.label ?? a) : "";
}
export function probeScopeLabel(s?: string): string {
  return s ? (PROBE_SCOPE_LABEL[s] ?? s) : "";
}
export function canConfirm(a?: string): boolean {
  return a === "high" || a === "medium";
}

// Display-name / entity-label layer (Operator View). Internal platform-service /
// container / storage names are replaced with NOC-safe role labels so the product
// never leaks its own infrastructure (backend component names, raw service /
// storage / database names). Real network device + path names (leaf1, wan-r2, …)
// pass through — they ARE NOC-meaningful. Bare IPs with no metadata genericize to
// "Monitored target". Raw entity ids stay available in Debug View only.
const INFRA_DISPLAY: Record<string, string> = {
  // our own telemetry/data stores → generic, never product-internal names
  clickhouse: "Monitoring data store", opensearch: "Monitoring data store",
  "opensearch-dashboards": "Monitoring data store", prometheus: "Monitoring data store",
  victoriametrics: "Monitoring data store", victoria: "Monitoring data store",
  loki: "Monitoring data store", redpanda: "Internal service", redis: "Internal service",
  postgres: "Internal service", "netbox-postgres": "Internal service",
  // app / gateway / platform services
  nginx: "Web gateway", api: "Platform service", backend: "Platform service",
  frontend: "Web app", correlation: "Monitoring service", netbox: "Inventory service",
  grafana: "Monitoring service",
  // pipeline / collectors
  vector: "Ingest pipeline", "vector-aggregator": "Ingest pipeline", "vector-router": "Ingest pipeline",
  promtail: "Internal service", "syslog-ng": "Internal service", goflow2: "Internal service",
  "node-exporter": "Internal service", cadvisor: "Internal service",
  // monitoring agents / probes
  prober: "Monitoring agent", reflector: "Monitoring agent", stamp: "Monitoring agent",
  // identity / platform sidecars / generators — never surface product internals
  keycloak: "Identity service", alertmanager: "Internal service", gotenberg: "Internal service",
  swtpm: "Internal service", "swtpm-sidecar": "Internal service", gnmic: "Ingest pipeline",
  telegraf: "Ingest pipeline", tgen: "Traffic generator",
};
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// Entity-type prefixes the engine stamps onto ids (path:a->b, device:leaf1). They
// are engine vocabulary — strip them for the operator display so a name never
// reads as "path:prober". (An interface id like "leaf1:Ethernet1" carries no such
// keyword prefix, so it survives intact.)
const ENTITY_PREFIX = /^(?:path|device|host|node|segment|site|service|prefix):/i;
// Internal / test markers — never customer-meaningful. Genericized even when the
// exact name isn't in the infra map, so a lab/demo/sidecar target can't leak into
// Operator View (item 6). Matched only as a delimited word to spare real devices.
const INTERNAL_HINT = /(?:^|[-_.])(?:demo|scratch|sidecar|dummy|sandbox|fixture|selftest|test)(?:[-_.]|$)/i;
function mapToken(t: string): string {
  const s = t.trim().replace(ENTITY_PREFIX, "");         // drop entity-type prefix for display
  const base = s.split(":")[0].trim().toLowerCase();
  if (INFRA_DISPLAY[base]) return INFRA_DISPLAY[base];
  if (INTERNAL_HINT.test(base)) return "Internal / test target";
  if (IPV4.test(base)) return "Monitored endpoint";      // bare IP, no metadata → generic
  return s;                                              // real device / interface / path name
}
// Friendly entity label. "prober->clickhouse" → "Monitoring agent → Monitoring data store".
export function entityLabel(raw: string): string {
  if (!raw) return raw;
  if (raw.includes("->")) return raw.split("->").map((s) => mapToken(s)).join(" → ");
  return mapToken(raw);
}

// isInternalEntity — true when EVERY part of the entity resolves to the platform's
// own infrastructure / a test target (clickhouse, nginx, api, prober, …). Used to
// keep internal self-monitoring objects out of the customer-facing RCA view (RCA is
// for customer networks, not our own stack). A mixed entity (one real device) is
// NOT internal, so a genuine incident touching a customer device is never hidden.
export function isInternalEntity(raw: string): boolean {
  if (!raw) return false;
  const parts = raw.includes("->") ? raw.split("->") : [raw];
  return parts.every((p) => {
    const s = p.trim().replace(ENTITY_PREFIX, "");
    const base = s.split(":")[0].trim().toLowerCase();
    return !!INFRA_DISPLAY[base] || INTERNAL_HINT.test(base);
  });
}

// mentionsInternal — true when ANY part of the entity is platform infra / a
// monitoring agent. Used for ENTITY-LEVEL display filtering: a path episode like
// "api->10.70.245.120" must NOT show to the operator (its source is a platform
// service), even though isInternalEntity() (all-parts) returns false for it.
// (Object-level HIDING still uses the conservative all-parts isInternalEntity so a
// real customer incident touching some infra is never hidden wholesale.)
export function mentionsInternal(raw: string): boolean {
  if (!raw) return false;
  const parts = raw.includes("->") ? raw.split("->") : [raw];
  return parts.some((p) => {
    const s = p.trim().replace(ENTITY_PREFIX, "");
    const base = s.split(":")[0].trim().toLowerCase();
    return !!INFRA_DISPLAY[base] || INTERNAL_HINT.test(base);
  });
}

// isInternalStackAffected — true when a correlation object's `affected` JSON
// touches ONLY internal infrastructure (every entity internal). Shared by the
// Correlations tab + the front-page Top Issues so internal self-monitoring never
// shows as a customer incident (decision #76).
export function isInternalStackAffected(affectedJSON: string): boolean {
  try {
    const a = JSON.parse(affectedJSON || "{}");
    const ents: string[] = [];
    for (const k of ["devices", "interfaces", "paths", "services", "segments", "prefixes", "sites"]) {
      (a[k] || []).forEach((e: string) => ents.push(e));
    }
    if (ents.length === 0) return false;
    return ents.every(isInternalEntity);
  } catch {
    return false;
  }
}

// Verdict owner → who acts.
export const OWNER_LABEL: Record<string, string> = {
  netops: "NetOps", isp: "ISP / carrier", carrier: "Carrier", cloud_provider: "Cloud provider",
  app_team: "App team", colo_provider: "Colo provider", sdwan_vendor: "SD-WAN vendor",
};
export function ownerLabel(o?: string): string {
  return o ? (OWNER_LABEL[o] ?? o) : "";
}

// --- Operator wording for the causal-graph / boundary view (item 10) ----------
// Engine vocabulary ("seam", "topo", "grounding", "visibility partial/blind") is
// backend language; Operator View uses plain NOC phrasing. Debug View keeps raw.

// Seam control_plane_owner → who owns the boundary (NOC phrasing).
export const SEAM_OWNER_LABEL: Record<string, string> = {
  enterprise: "Internal", isp: "ISP", carrier: "Carrier", cloud: "Cloud",
  sdwan_controller: "SD-WAN", colo: "Colo", unknown: "Provider",
};
export function seamOwnerLabel(o?: string): string {
  return o ? (SEAM_OWNER_LABEL[o] ?? o) : "Provider";
}
// Seam control_plane_owner → color, so a boundary reads "whose domain / whose
// fault" at a glance (the ThousandEyes responsibility-split idea, validated in
// docs/design/research/cisco-cloud-control-aicanvas-study.md). Always paired with
// the owner LABEL on the node, so color is reinforcing — never the sole carrier
// (colorblind-safe). One source of truth across SeamGraph, the summary mini-graph,
// and the relationship preview.
export const SEAM_OWNER_COLOR: Record<string, string> = {
  enterprise: C.info,           // internal — blue
  isp: C.warn,                  // ISP — amber
  carrier: "#C2410C",           // carrier — deep orange (distinct from ISP)
  cloud: C.discriminates,       // cloud — violet
  sdwan_controller: C.flow,     // SD-WAN — teal
  colo: "#0EA5E9",              // colo — sky
  unknown: C.faint,             // unknown owner — grey
};
export function seamOwnerColor(o?: string): string {
  return SEAM_OWNER_COLOR[o ?? "unknown"] ?? SEAM_OWNER_COLOR.unknown;
}
// Seam visibility → how much we can see across the boundary.
export function visibilityLabel(v?: string): string {
  switch (v) {
    case "partial": return "limited visibility";
    case "blind": return "no provider visibility";
    case "full": return "full visibility";
    default: return v ? `${v} visibility` : "";
  }
}
// grounding_kind → how the evidence relates (operator phrasing).
export function relationLabel(kind?: string): string {
  return kind === "seam" ? "related through provider boundary" : "related on the same path / device area";
}

// --- Affected scope (item 1) -------------------------------------------------
// engine `affected` bucket key → operator label. The engine emits only buckets
// it populated (devices/interfaces/sites/paths/segments/services/prefixes).
export const AFFECTED_LABEL: Record<string, string> = {
  devices: "Devices", interfaces: "Interfaces", sites: "Sites", paths: "Paths",
  segments: "Boundary segments", services: "Apps / services", prefixes: "Networks",
};

// --- Escalation decision (item 5) --------------------------------------------
// Owners that sit OUTSIDE our walls — a confirmed issue owned by one of these is
// escalated to that provider, not worked internally.
export const OWNER_EXTERNAL = new Set([
  "isp", "carrier", "cloud_provider", "colo_provider", "sdwan_vendor",
]);

// --- "Not tied to this issue" reason (item 4) --------------------------------
// Operator-safe explanation for why a signal was NOT counted toward the issue.
// Maps the engine's raw link_reason (which uses seam/topology/grounding words) to
// plain NOC phrasing; the raw link_reason stays in Debug View only.
export function nocUnlinkedReason(s: {
  link_status: string; link_reason?: string; probe_authority?: string;
}): string {
  if (s.probe_authority === "debug_only")
    return "Internal/test check — kept for context, but it can't confirm a customer-impacting issue on its own.";
  switch (s.link_status) {
    case "attached": return "";
    case "recovery": return "This marks a recovery / all-clear, not the problem itself.";
    case "malformed": return "The source didn't identify what it measured, so it couldn't be tied to this issue.";
    default: {
      const r = s.link_reason || "";
      if (/threshold|weight|reinforc|single-modality|too far|fell short/i.test(r))
        return "Happened in the same window, but the change wasn't strong or corroborated enough to tie it to this issue.";
      return "Happened in the same window, but on a different path or device area — not part of this issue.";
    }
  }
}

// ── Application identity (#81 P5) — confidence bands + identification techniques
// in plain operator language (customer-facing rule: no raw enum tokens in the UI).
export function bandLabel(b?: string): string {
  switch ((b || "").toLowerCase()) {
    case "authoritative": return "Authoritative";
    case "high": return "High confidence";
    case "medium": return "Medium confidence";
    case "low": return "Low confidence";
    default: return "Unresolved";
  }
}

export function bandTone(b?: string): Tone {
  switch ((b || "").toLowerCase()) {
    case "authoritative": case "high": return "green";
    case "medium": return "blue";
    case "low": return "orange";
    default: return "gray";
  }
}

export const APP_ID_SOURCE_LABEL: Record<string, string> = {
  ngfw_app_id: "Firewall App-ID",
  ipfix_app_id: "NBAR2 / IPFIX App-ID",
  operator: "Operator catalog",
  sot: "Source of Truth",
  cloud_tag: "Cloud tag",
  cloud_graph: "Cloud resource graph",
  workload: "Workload identity",
  dns: "DNS",
  sni: "TLS SNI",
  ip_catalog: "IP / CIDR catalog",
  asn: "ASN",
  port: "Port heuristic",
};

export function appIdSourceLabel(s?: string): string {
  const k = (s || "").toLowerCase();
  return APP_ID_SOURCE_LABEL[k] || (s || "").replace(/_/g, " ");
}
