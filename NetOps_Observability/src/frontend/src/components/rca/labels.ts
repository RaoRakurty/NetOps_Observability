// Human-readable labels for the operator-facing RCA story. The engine speaks in
// signature ids and signal kinds; operators need plain language. These maps turn
// `sig.ent.middle-mile.dia-egress-latency` → "ISP / DIA egress latency" and
// `probe_latency_departure` → "Probe latency departure — active probe", while the
// raw id stays available (rendered small/gray) for debugging.

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
const SIG_NOC_TITLE: Record<string, string> = {
  "sig.ent.middle-mile.dia-egress-latency": "Possible WAN/provider issue",
  "sig.ent.wan-edge.bgp-peer-flap": "Possible routing issue",
  "sig.ent.access.local-link-fault": "Possible local link issue",
  "sig.ent.wan-edge.congestion": "Possible WAN/provider issue",
  "sig.ent.wan-edge.routing-instability": "Possible routing issue",
  "sig.ent.middle-mile.physical-degradation": "Possible WAN/provider issue",
  "sig.ent.internet.dns-impairment": "Possible WAN/provider issue",
  "sig.ent.cloud.region-degradation": "Possible WAN/provider issue",
  "sig.ent.wan-edge.tunnel-mtu-blackhole": "Possible routing issue",
};
// Dominant evidence plane → NOC headline when no signature has matched.
export const PLANE_NOC_TITLE: Record<string, string> = {
  active_probe: "Possible path slowdown",
  device_telemetry: "Possible device health issue",
  control_plane: "Possible routing issue",
  passive_flow: "Possible traffic issue",
};
export function signatureNocTitle(id: string): string {
  if (SIG_NOC_TITLE[id]) return SIG_NOC_TITLE[id];
  if (/dia|middle-mile|cloud|internet|provider|congestion/.test(id)) return "Possible WAN/provider issue";
  if (/bgp|ospf|isis|routing/.test(id)) return "Possible routing issue";
  if (/link|access/.test(id)) return "Possible local link issue";
  if (/device|resource|cpu|mem|hardware/.test(id)) return "Possible device health issue";
  return "Possible network issue";
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
};
// "probe_latency_departure" → "Response-time change"; trims a trailing _clear.
export function kindLabel(kind: string): string {
  const base = kind.replace(/_clear$/, "");
  if (KIND_NOC[base]) return KIND_NOC[base];
  const words = base.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
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
  // storage / data services
  clickhouse: "Analytics store", postgres: "App database", "netbox-postgres": "App database",
  opensearch: "Search store", "opensearch-dashboards": "Search store", redis: "Cache service",
  prometheus: "Metrics store", victoriametrics: "Metrics store", victoria: "Metrics store",
  loki: "Log store", redpanda: "Event bus",
  // app / gateway / platform services
  nginx: "Web gateway", api: "Platform service", backend: "Platform service",
  frontend: "Web app", correlation: "Correlation service", netbox: "Source of truth",
  grafana: "Dashboards",
  // pipeline / collectors
  vector: "Ingest pipeline", "vector-aggregator": "Ingest pipeline", "vector-router": "Ingest pipeline",
  promtail: "Log shipper", "syslog-ng": "Log collector", goflow2: "Flow collector",
  "node-exporter": "Host metrics", cadvisor: "Container metrics",
  // monitoring agents / probes
  prober: "Test check source",
};
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
function mapToken(t: string): string {
  const base = t.split(":")[0].trim().toLowerCase();
  if (INFRA_DISPLAY[base]) return INFRA_DISPLAY[base];
  if (IPV4.test(base)) return "Monitored target";        // no metadata → generic
  return t;                                              // real device / path name
}
// Friendly entity label. "prober->clickhouse" → "Test check source → Analytics store".
export function entityLabel(raw: string): string {
  if (!raw) return raw;
  if (raw.includes("->")) return raw.split("->").map((s) => mapToken(s)).join(" → ");
  return mapToken(raw);
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
