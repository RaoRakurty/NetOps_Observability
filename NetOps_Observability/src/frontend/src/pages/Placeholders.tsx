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

// ── Infrastructure ───────────────────────────────────────────────────────────
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
