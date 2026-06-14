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
export const C = {
  // severity — the alarm palette (legible across a room)
  crit: "#FF5366",        // critical / contradicts / malformed
  warn: "#F2B705",        // warning / caution / missing-required / control-plane / seam
  ok: "#35D6A4",          // healthy / linked / supports (calm emerald, not neon)
  info: "#5B9DFF",        // info / device-telemetry / present-not-linked
  flow: "#2DD4BF",        // flows (teal)
  discriminates: "#A78BFA", // discriminating evidence (violet)
  // calm surfaces (fallbacks; the app theme vars take precedence where set)
  fg: "#E6EDF6",          // off-white, never #FFF
  muted: "#8B97AD",       // secondary text (≥3:1 on slate)
  faint: "#5A6473",       // tertiary / absent
  line: "#2A3346",        // borders/dividers
  bg: "#0E1320",          // deepest surface, never #000
  panel: "#151B2B",       // card surface
} as const;

// Evidence planes — distinct, calm hues; always positioned + labeled so they read
// without relying on color alone.
export const MODALITY_META: Record<string, { label: string; color: string }> = {
  device_telemetry: { label: "Device telemetry", color: C.info },
  control_plane: { label: "Control plane", color: C.warn },
  passive_flow: { label: "Flows", color: C.flow },
  active_probe: { label: "Probes", color: C.ok },
};

export const MODALITY_ORDER = ["device_telemetry", "control_plane", "passive_flow", "active_probe"];

export function modalityLabel(key: string): string {
  return MODALITY_META[key]?.label ?? key.replace(/_/g, " ");
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

// "probe_latency_departure" → "Probe latency departure"; trims a trailing _clear.
export function kindLabel(kind: string): string {
  const base = kind.replace(/_clear$/, "");
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
