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
// Dashboard List (build-order #10) — a curated DIRECTORY of the live boards.
// Every card links to a real, data-backed view; the classic NMS dashboard names
// (Device Metrics, Bandwidth Utilization, …) map onto the board that answers
// that question. Cards keep stable ids so the nav's sub-item deeplinks scroll
// to them.
type DashboardCard = { id: string; label: string; desc: string; href: string; icon: string };

const DASHBOARD_GROUPS: { title: string; cards: DashboardCard[] }[] = [
  {
    title: "Network monitoring",
    cards: [
      { id: "device-metric", label: "Device Metrics", desc: "Fleet cockpit — reachability, CPU/memory, interfaces, uptime, tunnels.", href: "#/infrastructure/monitoring", icon: "infrastructure" },
      { id: "interface-metric", label: "Interface Metrics", desc: "Per-interface throughput, errors, discards and utilization, with flow drill-down.", href: "#/infrastructure/ifperf", icon: "metrics" },
      { id: "bgp-metric", label: "BGP Metrics", desc: "BGP session state and churn, OSPF adjacencies, routing health.", href: "#/infrastructure/bgpospf", icon: "topology" },
      { id: "bandwidth", label: "Bandwidth Utilization", desc: "Fleet throughput and line-speed utilization (Device Monitoring → Throughput).", href: "#/infrastructure/monitoring", icon: "metrics" },
      { id: "wan-circuit", label: "WAN Circuit Utilization", desc: "Overlay circuits (IPsec / GRE / SD-WAN) — state, latency, loss, QoE.", href: "#/infrastructure/tunnels", icon: "stack" },
    ],
  },
  {
    title: "Traffic & paths",
    cards: [
      { id: "flows-board", label: "Flow Analytics", desc: "NetFlow/IPFIX/sFlow — talkers, conversations, ports, protocols, flags, geo.", href: "#/flows", icon: "flows" },
      { id: "network-path", label: "Network Path", desc: "Traceroute topology and STAMP path SLA from the active prober.", href: "#/infrastructure/flowtrace", icon: "explore" },
      { id: "quality-board", label: "Quality", desc: "Error/discard rates, saturation, QoE overlay and the Path Health composite.", href: "#/monitoring/quality", icon: "monitoring" },
    ],
  },
  {
    title: "Health & operations",
    cards: [
      { id: "troubleshooting-board", label: "Troubleshooting", desc: "Collection-pipeline health — collector status, flow/trap arrival, gaps.", href: "#/infrastructure/troubleshooting", icon: "alerts" },
      { id: "datasources-board", label: "Data Sources", desc: "Per-device coverage matrix: SNMP, flows, syslog, traps — what's live and fresh.", href: "#/infrastructure/datasources", icon: "datasets" },
      { id: "events-board", label: "Events", desc: "Unified syslog + trap + alert timeline.", href: "#/monitoring/events", icon: "logs" },
      { id: "threat-board", label: "Threat Detection", desc: "Flow fan-out scan detection over IPFIX.", href: "#/security/threat", icon: "reports" },
    ],
  },
];

export function DashboardList() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div className="card">
        <h2>Dashboard List</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
          Every board, one directory — each card opens the live view that answers that question.
          Boards you compose yourself are listed underneath.
        </p>
        {DASHBOARD_GROUPS.map((g) => (
          <div key={g.title} style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--muted)", margin: "0 0 8px" }}>{g.title}</div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                gap: 12,
              }}
            >
              {g.cards.map((d) => (
                <a
                  key={d.id}
                  id={d.id}
                  href={d.href}
                  className="panel"
                  style={{ padding: 14, display: "flex", flexDirection: "column", gap: 6, textDecoration: "none", color: "inherit", cursor: "pointer" }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Icon name={d.icon} size={16} />
                    <strong style={{ fontSize: 13 }}>{d.label}</strong>
                  </div>
                  <span style={{ color: "var(--muted)", fontSize: 12, lineHeight: 1.5 }}>{d.desc}</span>
                  <span style={{ marginTop: 4, fontSize: 11, fontWeight: 700, color: "var(--accent)" }}>Open →</span>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
      <SavedDashboards />
    </div>
  );
}

// ── Monitoring ──────────────────────────────────────────────────────────────
// (New Monitor graduated to pages/NewMonitor.tsx — build-order #9.)

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
// (Command Center graduated to pages/CommandCenter.tsx — build-order #11.)

// ── Infrastructure ───────────────────────────────────────────────────────────
// Flow Trace — network-path monitoring: host-level,
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
      summary="Network-path monitoring: traceroute a source → destination and visualize the hop-by-hop route with per-hop latency, to pinpoint whether loss/latency is internal, in the ISP, or a misroute — including hops outside your network."
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
