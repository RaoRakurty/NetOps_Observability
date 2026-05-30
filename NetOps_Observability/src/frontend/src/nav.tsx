import { SectionCtx } from "./context/shell";

// Pages / tabs (existing components, reparented into product sections).
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Reports from "./pages/Reports";
import SavedDashboards from "./pages/SavedDashboards";
import Topology from "./tabs/Topology";
import Collectors from "./tabs/Collectors";
import SnmpCredentials from "./tabs/SnmpCredentials";
import Alerts from "./tabs/Alerts";
import Rules from "./tabs/Rules";
import Findings from "./tabs/Findings";
import Logs from "./tabs/Logs";
import SavedSearches from "./tabs/SavedSearches";
import Flows from "./tabs/Flows";
import Tunnels from "./tabs/Tunnels";
import MetricsExplorer from "./tabs/MetricsExplorer";
import PrometheusTab from "./tabs/Prometheus";
import GrafanaTab from "./tabs/Grafana";
import SearchDashboardsTab from "./tabs/SearchDashboards";
import Settings from "./tabs/Settings";
import {
  UsersAdmin,
  RolesAdmin,
  TenantsAdmin,
  AuthenticationAdmin,
  ApiAccessAdmin,
  IntegrationsAdmin,
} from "./tabs/admin";

// A leaf is one rendered view. Sections with multiple leaves get a SubNav.
export type NavLeaf = {
  id: string;
  label: string;
  render: (c: SectionCtx) => JSX.Element;
};

export type NavSection = {
  id: string;
  label: string;
  icon: string;
  children?: NavLeaf[];
  render?: (c: SectionCtx) => JSX.Element;
  action?: "copilot"; // opens the slide-over instead of routing
  footer?: boolean; // pinned to the bottom of the sidebar
};

// The information architecture. Labels/grouping follow the conventions shared
// by Datadog, Zabbix 7, Splunk Observability and Grafana:
//   Overview · Explore (ad-hoc query) · Dashboards (curated) · Alerts ·
//   Infrastructure (fleet) · Topology · Reports, with Administration (settings
//   + raw-tool escape hatches: Grafana/Prometheus/OpenSearch) pinned at the
//   bottom. Order here is the sidebar order.
export const NAV: NavSection[] = [
  // Overview — the home landing. The modular panel board lives at the top;
  // curated saved Dashboards are nested beneath it (expand in the sidebar).
  {
    id: "overview",
    label: "Overview",
    icon: "overview",
    children: [
      { id: "board", label: "Overview", render: () => <Dashboard /> },
      { id: "dashboards", label: "Dashboards", render: () => <SavedDashboards /> },
    ],
  },
  // Explore — ad-hoc, query-first work across the data types (Grafana
  // "Explore" / Datadog "Metrics Explorer"), kept distinct from Dashboards.
  {
    id: "explore",
    label: "Explore",
    icon: "explore",
    children: [
      { id: "logs", label: "Logs", render: (c) => <Logs initialQuery={c.query} rangeMinutes={c.rangeMinutes} /> },
      { id: "metrics", label: "Metrics", render: (c) => <MetricsExplorer rangeMinutes={c.rangeMinutes} /> },
      { id: "flows", label: "Flows", render: (c) => <Flows sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "saved", label: "Saved", render: () => <SavedSearches /> },
    ],
  },
  // Alerts — active state vs rule definitions vs correlated incidents
  // (Zabbix "Problems"/"Alerts", Splunk "Active"/"Detectors").
  {
    id: "alerts",
    label: "Alerts",
    icon: "alerts",
    children: [
      { id: "active", label: "Active", render: () => <Alerts /> },
      { id: "rules", label: "Rules", render: () => <Rules /> },
      { id: "incidents", label: "Incidents", render: () => <Findings /> },
    ],
  },
  // Infrastructure — the device fleet + collection health (Datadog
  // "Infrastructure", Zabbix "Hosts"/"Data collection").
  {
    id: "infrastructure",
    label: "Infrastructure",
    icon: "infrastructure",
    children: [
      { id: "devices", label: "Devices", render: () => <Devices /> },
      { id: "collectors", label: "Collectors", render: () => <Collectors /> },
      { id: "snmp", label: "SNMP Credentials", render: () => <SnmpCredentials /> },
    ],
  },
  {
    id: "topology",
    label: "Topology",
    icon: "topology",
    children: [
      { id: "map", label: "Map", render: () => <Topology /> },
      { id: "tunnels", label: "Tunnels", render: () => <Tunnels /> },
    ],
  },
  {
    id: "reports",
    label: "Reports",
    icon: "reports",
    render: () => <Reports />,
  },
  {
    id: "copilot",
    label: "Copilot",
    icon: "copilot",
    action: "copilot",
    footer: true,
  },
  // Administration — config + power-user escape hatches to the raw backend
  // tools, kept out of the day-to-day monitoring sections (as Grafana/Datadog
  // do: backends live under admin/connections, not next to dashboards).
  {
    id: "admin",
    label: "Administration",
    icon: "settings",
    footer: true,
    children: [
      { id: "settings", label: "Settings", render: () => <Settings /> },
      // Identity & access (planned scaffolding — see tabs/admin.tsx + docs/).
      { id: "users", label: "Users", render: () => <UsersAdmin /> },
      { id: "roles", label: "Roles", render: () => <RolesAdmin /> },
      { id: "tenants", label: "Tenants", render: () => <TenantsAdmin /> },
      { id: "auth", label: "Authentication", render: () => <AuthenticationAdmin /> },
      { id: "api", label: "API Access", render: () => <ApiAccessAdmin /> },
      { id: "integrations", label: "Integrations", render: () => <IntegrationsAdmin /> },
      // Raw-backend escape hatches.
      { id: "grafana", label: "Grafana", render: () => <GrafanaTab /> },
      { id: "prometheus", label: "Prometheus", render: () => <PrometheusTab /> },
      { id: "opensearch", label: "OpenSearch", render: () => <SearchDashboardsTab /> },
    ],
  },
];

export type Resolved = {
  section: NavSection;
  leaf?: NavLeaf;
};

// Parse "#/section/leaf" into the section + active leaf, with fallbacks.
export function resolveRoute(hash: string): Resolved {
  const path = hash.replace(/^#\/?/, "");
  const [sectionId, leafId] = path.split("/");
  const section = NAV.find((s) => s.id === sectionId) ?? NAV[0];
  if (!section.children) return { section };
  const leaf = section.children.find((l) => l.id === leafId) ?? section.children[0];
  return { section, leaf };
}

// Build the canonical route string for a section (first leaf if grouped).
export function routeFor(section: NavSection, leaf?: NavLeaf): string {
  if (section.children) return `${section.id}/${(leaf ?? section.children[0]).id}`;
  return section.id;
}
