// Human-readable labels for the operator-facing RCA story. The engine speaks in
// signature ids and signal kinds; operators need plain language. These maps turn
// `sig.ent.middle-mile.dia-egress-latency` → "ISP / DIA egress latency" and
// `probe_latency_departure` → "Probe latency departure — active probe", while the
// raw id stays available (rendered small/gray) for debugging.

export const MODALITY_META: Record<string, { label: string; color: string }> = {
  device_telemetry: { label: "Device telemetry", color: "#4c8dff" },
  control_plane: { label: "Control plane", color: "#f0a020" },
  passive_flow: { label: "Flows", color: "#1bc5bd" },
  active_probe: { label: "Probes", color: "#3fb950" },
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
