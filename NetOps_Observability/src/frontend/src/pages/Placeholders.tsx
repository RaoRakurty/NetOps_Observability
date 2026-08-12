// Dashboard List — the curated directory of live boards. (This file once held
// the IA's "coming soon" stub pages; every stub has graduated to a real page,
// so only the directory remains. New IA slots get their own page files.)
import Icon from "../components/Icon";
import SavedDashboards from "./SavedDashboards";

// ── Dashboards ────────────────────────────────────────────────────────────
// Dashboard List (build-order #10) — a curated DIRECTORY of the live boards.
// Every card links to a real, data-backed view; the classic NMS dashboard names
// (Device Metrics, Bandwidth Utilization, …) map onto the board that answers
// that question. Cards keep stable ids so the nav's sub-item deeplinks scroll
// to them.
type DashboardCard = { id: string; label: string; href: string; icon: string };

const DASHBOARD_GROUPS: { title: string; cards: DashboardCard[] }[] = [
  {
    title: "Network monitoring",
    cards: [
      { id: "device-metric", label: "Device Metrics", href: "#/analytics/device-monitoring", icon: "infrastructure" },
      { id: "interface-metric", label: "Interface Metrics", href: "#/analytics/interface-performance", icon: "metrics" },
      { id: "bgp-metric", label: "BGP Metrics", href: "#/analytics/protocols", icon: "topology" },
      { id: "bandwidth", label: "Bandwidth Utilization", href: "#/analytics/device-monitoring", icon: "metrics" },
      { id: "wan-circuit", label: "WAN Interface Metrics", href: "#/investigate/wan-paths", icon: "stack" },
    ],
  },
  {
    title: "Traffic & paths",
    cards: [
      { id: "flows-board", label: "Flow Analytics", href: "#/explore/flows", icon: "flows" },
      { id: "network-path", label: "Network Path", href: "#/investigate/flowtrace", icon: "explore" },
      { id: "quality-board", label: "Quality", href: "#/operations/network-health", icon: "monitoring" },
    ],
  },
  {
    title: "Health & operations",
    cards: [
      { id: "troubleshooting-board", label: "Troubleshooting", href: "#/investigate/troubleshooting", icon: "alerts" },
      { id: "datasources-board", label: "Data Sources", href: "#/admin/datasources", icon: "datasets" },
      { id: "events-board", label: "Events", href: "#/explore/events", icon: "logs" },
      { id: "threat-board", label: "Threat Detection", href: "#/security/threat", icon: "reports" },
    ],
  },
];

export function DashboardList() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div className="card">
        <h2>Dashboard List</h2>
        {DASHBOARD_GROUPS.map((g) => (
          <div key={g.title} style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--muted)", margin: "0 0 8px" }}>{g.title}</div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(164px, 1fr))",
                gap: 7,
              }}
            >
              {g.cards.map((d) => (
                // Small, single-line directory boxes (UI-8): just icon · label · →.
                // No description — the label names the board it opens.
                <a key={d.id} id={d.id} href={d.href} className="dash-card">
                  <Icon name={d.icon} size={14} />
                  <strong className="dash-card-label">{d.label}</strong>
                  <span className="dash-card-go" aria-hidden>→</span>
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
