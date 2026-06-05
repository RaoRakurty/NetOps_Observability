import { SectionCtx } from "./context/shell";

// Pages / tabs (existing components, reparented into product sections).
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Reports from "./pages/Reports";
import SavedDashboards from "./pages/SavedDashboards";
import Topology from "./tabs/Topology";
import Collectors from "./tabs/Collectors";
import SnmpProfileManager from "./tabs/SnmpProfileManager";
import Alerts from "./tabs/Alerts";
import Rules from "./tabs/Rules";
import Findings from "./tabs/Findings";
import Incidents from "./tabs/Incidents";
import Logs from "./tabs/Logs";
import SavedSearches from "./tabs/SavedSearches";
import Flows from "./tabs/Flows";
import Tunnels from "./tabs/Tunnels";
import MetricsExplorer from "./tabs/MetricsExplorer";
import PrometheusTab from "./tabs/Prometheus";
import GrafanaTab from "./tabs/Grafana";
import SearchDashboardsTab from "./tabs/SearchDashboards";
import Settings from "./tabs/Settings";
import StackHealth from "./tabs/StackHealth";
import AuditLog from "./tabs/AuditLog";
import {
  UsersAdmin,
  RolesAdmin,
  TenantsAdmin,
  AuthenticationAdmin,
  ApiAccessAdmin,
  IntegrationsAdmin,
  NotificationsAdmin,
} from "./tabs/admin";

// A leaf is one rendered view. Sections with multiple leaves get a SubNav.
export type NavLeaf = {
  id: string;
  label: string;
  render: (c: SectionCtx) => JSX.Element;
  platformOnly?: boolean; // visible only to the cross-tenant platform owner
};

export type NavSection = {
  id: string;
  label: string;
  icon: string;
  children?: NavLeaf[];
  render?: (c: SectionCtx) => JSX.Element;
  action?: "copilot"; // opens the slide-over instead of routing
  footer?: boolean; // pinned to the bottom of the sidebar
  platformOnly?: boolean; // visible only to the cross-tenant platform owner
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
      { id: "incidents", label: "Incidents", render: () => <Incidents /> },
      { id: "anomalies", label: "Anomalies", render: () => <Findings /> },
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
      // Collectors = shared poller-engine status (fleet aggregate) → platform owner only.
      { id: "collectors", label: "Collectors", platformOnly: true, render: () => <Collectors /> },
      { id: "snmp", label: "SNMP Profile Manager", render: () => <SnmpProfileManager /> },
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
  // Stack — the platform's OWN infra plumbing + raw-backend tools, grouped into
  // one section instead of being scattered in Administration. Platform-owner only
  // (tenant admins manage their tenant, never the stack); the backend enforces it
  // independently (/api/stack/health 403, nginx auth_request on /search, etc.).
  {
    id: "stack",
    label: "Stack",
    icon: "stack",
    platformOnly: true,
    children: [
      { id: "health", label: "Stack Health", render: () => <StackHealth /> },
      { id: "grafana", label: "Grafana", render: () => <GrafanaTab /> },
      { id: "prometheus", label: "Prometheus", render: () => <PrometheusTab /> },
      { id: "opensearch", label: "OpenSearch", render: () => <SearchDashboardsTab /> },
    ],
  },
  {
    id: "copilot",
    label: "ChatGPT",
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
      // Platform-owner only: the tenant registry is the platform's namespace map,
      // not a tenant's to see or manage (a tenant admin governs WITHIN its tenant).
      // Backend already enforces this (handleTenants: POST needs cross; GET shows
      // only the caller's own tenant) — this just stops surfacing the section.
      { id: "tenants", label: "Tenants", platformOnly: true, render: () => <TenantsAdmin /> },
      { id: "auth", label: "Authentication", render: () => <AuthenticationAdmin /> },
      { id: "api", label: "API Access", render: () => <ApiAccessAdmin /> },
      { id: "integrations", label: "Integrations", render: () => <IntegrationsAdmin /> },
      { id: "notifications", label: "Notifications", render: () => <NotificationsAdmin /> },
      { id: "audit", label: "Audit Log", render: () => <AuditLog /> },
    ],
  },
];

export type Resolved = {
  section: NavSection;
  leaf?: NavLeaf;
};

// filteredNav drops platform-owner-only sections/leaves for tenant-scoped users.
// The platform owner sees the full tree. This is UX gating; the backend enforces
// the boundary independently (e.g. /api/stack/health returns 403).
export function filteredNav(platformAdmin: boolean): NavSection[] {
  if (platformAdmin) return NAV;
  return NAV.filter((s) => !s.platformOnly).map((s) =>
    s.children ? { ...s, children: s.children.filter((l) => !l.platformOnly) } : s,
  );
}

// Parse "#/section/leaf" into the section + active leaf, with fallbacks. The nav
// defaults to the full tree; pass a filtered tree to keep hidden routes
// unreachable via the hash (they fall back to the first visible entry).
export function resolveRoute(hash: string, nav: NavSection[] = NAV): Resolved {
  const path = hash.replace(/^#\/?/, "");
  const [sectionId, leafId] = path.split("/");
  const section = nav.find((s) => s.id === sectionId) ?? nav[0];
  if (!section.children) return { section };
  const leaf = section.children.find((l) => l.id === leafId) ?? section.children[0];
  return { section, leaf };
}

// Build the canonical route string for a section (first leaf if grouped).
export function routeFor(section: NavSection, leaf?: NavLeaf): string {
  if (section.children) return `${section.id}/${(leaf ?? section.children[0]).id}`;
  return section.id;
}

// A flat, navigable destination — one entry per leaf (or per leafless section).
// Powers the ⌘K command palette. `action` mirrors NavSection.action (copilot).
export type NavDestination = {
  label: string; // "Section · Leaf"
  section: string; // section label, for grouping/secondary text
  route: string; // hash route (without leading #/)
  action?: "copilot";
};

// navDestinations flattens the nav into the list of places ⌘K can jump to.
// Defaults to the full tree; pass a filtered tree so the palette can't jump to
// sections the current user isn't allowed to see.
export function navDestinations(nav: NavSection[] = NAV): NavDestination[] {
  const out: NavDestination[] = [];
  for (const s of nav) {
    if (s.action) {
      out.push({ label: s.label, section: s.label, route: s.id, action: s.action });
      continue;
    }
    if (s.children) {
      for (const l of s.children) {
        const label = l.label === s.label ? s.label : `${s.label} · ${l.label}`;
        out.push({ label, section: s.label, route: `${s.id}/${l.id}` });
      }
    } else {
      out.push({ label: s.label, section: s.label, route: s.id });
    }
  }
  return out;
}
