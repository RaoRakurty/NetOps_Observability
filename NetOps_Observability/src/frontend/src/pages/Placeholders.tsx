// Placeholder / stub pages for nav sections that are mapped in the information
// architecture but not yet backed by a live feature. Each renders a consistent
// "coming soon" card describing the intended capability so the nav is complete
// and self-documenting. Replace a stub with a real page by swapping the import
// in nav.tsx — the route/label stay the same.
import { ReactNode } from "react";
import Icon from "../components/Icon";
import SavedDashboards from "./SavedDashboards";

// Stub — a titled empty-state card with an icon, one-line summary and a short
// list of the capabilities planned for the area. Purely presentational.
export function Stub({
  icon,
  title,
  summary,
  planned,
  children,
}: {
  icon: string;
  title: string;
  summary: string;
  planned?: string[];
  children?: ReactNode;
}) {
  return (
    <div className="card" style={{ maxWidth: 760 }}>
      <div className="empty-state" style={{ paddingBottom: 16 }}>
        <div className="empty-state-icon" style={{ display: "flex", justifyContent: "center", marginBottom: 10 }}>
          <Icon name={icon} size={40} />
        </div>
        <h2 style={{ marginBottom: 6 }}>{title}</h2>
        <p style={{ color: "var(--muted)", maxWidth: 520, margin: "0 auto" }}>{summary}</p>
        <span
          className="ds-badge"
          style={{
            display: "inline-block",
            marginTop: 12,
            padding: "2px 10px",
            borderRadius: 999,
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.04em",
            textTransform: "uppercase",
            color: "var(--accent)",
            background: "var(--accent-soft)",
          }}
        >
          Planned
        </span>
      </div>
      {planned && planned.length > 0 && (
        <ul style={{ margin: "0 auto", maxWidth: 520, color: "var(--muted)", fontSize: 13, lineHeight: 1.9 }}>
          {planned.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {children}
    </div>
  );
}

// ── Dashboards ────────────────────────────────────────────────────────────
// Dashboard List — the catalog of curated dashboards. Today it surfaces the
// saved-dashboards catalog plus the named metric dashboards we intend to ship
// as first-class views (device / interface / BGP / bandwidth / WAN circuit).
const NAMED_DASHBOARDS = [
  { id: "device-metric", label: "Device Metrics", desc: "Per-device health: CPU, memory, temperature, uptime." },
  { id: "interface-metric", label: "Interface Metrics", desc: "Throughput, errors, discards and utilization per interface." },
  { id: "bgp-metric", label: "BGP Metrics", desc: "Session state, prefixes received/advertised, flaps." },
  { id: "bandwidth", label: "Bandwidth Utilization", desc: "Link bandwidth utilization and capacity trends." },
  { id: "wan-circuit", label: "WAN Circuit Utilization", desc: "Per-circuit utilization, SLA and overlay health." },
];

export function DashboardList() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div className="card">
        <h2>Dashboard List</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
          Curated, ready-to-use dashboards. The named views below are planned templates; saved dashboards you
          create are listed underneath.
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
            gap: 12,
            marginTop: 8,
          }}
        >
          {NAMED_DASHBOARDS.map((d) => (
            <div
              key={d.id}
              id={d.id}
              className="panel"
              style={{ padding: 14, display: "flex", flexDirection: "column", gap: 6 }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Icon name="dashboards" size={16} />
                <strong style={{ fontSize: 13 }}>{d.label}</strong>
              </div>
              <span style={{ color: "var(--muted)", fontSize: 12, lineHeight: 1.5 }}>{d.desc}</span>
              <span style={{ marginTop: 4, fontSize: 10, fontWeight: 600, letterSpacing: "0.04em", color: "var(--accent)", textTransform: "uppercase" }}>
                Planned
              </span>
            </div>
          ))}
        </div>
      </div>
      <SavedDashboards />
    </div>
  );
}

// ── Monitoring ──────────────────────────────────────────────────────────────
export function NewMonitor() {
  return (
    <Stub
      icon="alerts"
      title="New Monitor"
      summary="Guided creation of a new monitor from a template — pick a signal, threshold or anomaly model, and notification targets."
      planned={[
        "Template gallery (the 16 built-in rule templates under Monitors)",
        "Metric / log / anomaly monitor types",
        "Threshold + rolling z-score conditions",
        "Notification routing to your Incident Response channels",
      ]}
    />
  );
}

export function Quality() {
  return (
    <Stub
      icon="analytics"
      title="Quality"
      summary="Service- and link-quality scoring across the fleet — SLA attainment, QoE, and degradation trends."
      planned={[
        "Per-link / per-circuit quality (latency, jitter, loss, QoE)",
        "SLA attainment and error-budget burn",
        "Quality regressions surfaced as monitor candidates",
      ]}
    />
  );
}

export function Events() {
  return (
    <Stub
      icon="bell"
      title="Events"
      summary="A unified event stream — every change, deploy, alert transition and integration signal on one timeline, ready to correlate with metrics and logs."
      planned={[
        "Unified event feed across collectors, alerts and integrations",
        "Faceted search + filtering (source, severity, tag)",
        "Correlate events with metric/log spikes",
        "Promote an event to an incident",
      ]}
    />
  );
}

// ── Incident Response ────────────────────────────────────────────────────────
export function IncidentResponse() {
  return (
    <Stub
      icon="incident"
      title="Incident Response"
      summary="Coordinate response across your chat and collaboration tools. Connect Microsoft Teams, Slack and Google Chat to route incident notifications and run response from where your team already works."
      planned={[
        "Microsoft Teams channel integration",
        "Slack channel + action buttons (already available under Notifications)",
        "Google Chat spaces",
        "Bi-directional incident sync with ITSM (ServiceNow / Jira)",
      ]}
    />
  );
}

// ── Infrastructure ───────────────────────────────────────────────────────────
// Flow Trace — our equivalent of Datadog "Network Path": host-level,
// traceroute-based path monitoring that maps the hop-by-hop route from a source
// to a destination and measures latency at every hop, so you can tell whether a
// problem is internal, in the ISP, or due to misrouting. Two collection modes:
// scheduled tests (defined source→destination pairs) and dynamic tests
// (auto-discovered from observed flow traffic). Probes over TCP/UDP.
export function FlowTrace() {
  return (
    <Stub
      icon="flows"
      title="Flow Trace"
      summary="Network-path monitoring (Datadog 'Network Path' equivalent): traceroute a source → destination and visualize the hop-by-hop route with per-hop latency, to pinpoint whether loss/latency is internal, in the ISP, or a misroute — including hops outside your network."
      planned={[
        "Scheduled tests — defined source → destination pairs probed continuously (TCP/UDP)",
        "Dynamic tests — paths auto-discovered from observed flow traffic",
        "List view — source · destination · protocol · port · tags · avg reachability · avg RTT",
        "Path view — hop-by-hop visualization showing where issues sit (internal vs ISP)",
        "Detect & alert on path changes and added/dropped hops over time",
        "Correlate the path with live flows, topology and device telemetry",
      ]}
    />
  );
}

// BGP / OSPF Overview — routing-protocol session & adjacency health. Data-blocked
// today: device_bgp_peer_state / device_ospf_nbr_state are referenced in alert
// rules but emitted by no collector — needs a BGP4-MIB/OSPF-MIB SNMP collector.
export function BgpOspfOverview() {
  return (
    <Stub
      icon="topology"
      title="BGP / OSPF Overview"
      summary="Routing-protocol health: BGP session state, flaps, update rate and accepted prefixes, plus OSPF interface and neighbor adjacency state — confirming the control plane behind the data plane."
      planned={[
        "BGP — peer state, established transitions, update rate, accepted prefixes (BGP4-MIB)",
        "OSPF — interface state and neighbor adjacency state (OSPF-MIB)",
        "Device context — uptime + interface admin/oper status",
        "Needs a new SNMP collector (collectors/routing.go) — currently no BGP/OSPF metrics are collected",
      ]}
    />
  );
}

// Troubleshooting — collection-pipeline health (agents, SNMP, traps, NetFlow).
export function Troubleshooting() {
  return (
    <Stub
      icon="stack"
      title="Troubleshooting"
      summary="Health of the collection pipeline itself — collector availability, SNMP reachability and poll duration, and the NetFlow/trap ingest path — so you can tell 'no data' from 'all good'."
      planned={[
        "Fleet counts — devices monitored, flows/traps indexed, submitted metrics",
        "Collectors — availability, CPU/memory, restarts (collector_* self-metrics)",
        "SNMP — reachable/unreachable, check duration & interval by device",
        "NetFlow — records received/flushed/stored, exporters, packet drop & sequence gaps",
      ]}
    />
  );
}

export function DeviceGeomap() {
  return (
    <Stub
      icon="topology"
      title="Device Geomap"
      summary="A geographic map of the device fleet — sites and devices plotted by location with live health overlays."
      planned={[
        "Site/region placement from inventory metadata",
        "Health + reachability overlays per location",
        "Drill from a site into its devices and topology",
      ]}
    />
  );
}

// ── Security ─────────────────────────────────────────────────────────────────
export function VulnerabilityManagement() {
  return (
    <Stub
      icon="shield"
      title="Vulnerability Management"
      summary="Track device-software vulnerabilities (CVEs) across the fleet, prioritized by exposure and severity."
      planned={[
        "OS/firmware version inventory per device",
        "CVE matching against known advisories (PSIRT feeds)",
        "Risk-prioritized remediation backlog",
      ]}
    />
  );
}

export function ThreatDetection() {
  return (
    <Stub
      icon="shield"
      title="Threat Detection"
      summary="Detect suspicious network behavior from flows, logs and telemetry — anomalous traffic, scans, and policy violations."
      planned={[
        "Flow-based anomaly detection (exfiltration, scans, beaconing)",
        "Log-based detections and signatures",
        "Tie detections into the correlation + incident pipeline",
      ]}
    />
  );
}

export function ComplianceMonitoring() {
  return (
    <Stub
      icon="lock"
      title="Compliance Monitoring"
      summary="Continuously check device configuration against baselines and standards, and report drift."
      planned={[
        "Config baselines and golden templates",
        "Drift detection against intended state (Source of Truth)",
        "Framework reporting (CIS / PCI / internal policy)",
      ]}
    />
  );
}
