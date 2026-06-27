import { SectionCtx } from "./context/shell";

// Pages / tabs (existing components, reparented into product sections).
import Dashboard from "./pages/Dashboard";
import FrontPage from "./pages/FrontPage";
import Devices from "./pages/Devices";
import DeviceMonitoring from "./pages/DeviceMonitoring";
import InterfacePerformance from "./pages/InterfacePerformance";
import BgpOspf from "./pages/BgpOspf";
import Troubleshooting from "./pages/Troubleshooting";
import ThreatDetection from "./pages/ThreatDetection";
import Events from "./pages/Events";
import Correlations from "./tabs/Correlations";
import AppObservability from "./pages/AppObservability";
import ReliabilityScorecard from "./pages/ReliabilityScorecard";
import Quality from "./pages/Quality";
import DataSources from "./pages/DataSources";
import NetworkPath from "./pages/NetworkPath";
import Reports from "./pages/Reports";
import TopologyCanvas from "./features/topology/renderers/react-flow/TopologyCanvas";
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
import SourceOfTruth from "./tabs/SourceOfTruth";
import StackHealth from "./tabs/StackHealth";
import AuditLog from "./tabs/AuditLog";
import AccessExplorer from "./tabs/AccessExplorer";
import {
  IdentityAccess,
  RegionsAdmin,
  BindingsAdmin,
  SessionsAdmin,
  AuthenticationAdmin,
  ApiAccessAdmin,
  IntegrationsAdmin,
  NotificationsAdmin,
  IncidentPoliciesAdmin,
  GraphQLExplorer,
} from "./tabs/admin";
import { DashboardList } from "./pages/Placeholders";
import DeviceGeomap from "./pages/DeviceGeomap";
import VulnerabilityManagement from "./pages/VulnerabilityManagement";
import ComplianceMonitoring from "./pages/ComplianceMonitoring";
import NewMonitor from "./pages/NewMonitor";
import CommandCenter from "./pages/CommandCenter";

// A leaf is one rendered view. Sections with multiple leaves get a SubNav.
export type NavLeaf = {
  id: string;
  label: string;
  render: (c: SectionCtx) => JSX.Element;
  platformOnly?: boolean; // visible only to the cross-tenant platform owner
  // group: render this leaf under a labelled heading in the hover flyout
  // (e.g. "Developer"). Consecutive leaves sharing a group sit under one header.
  group?: string;
  // subItems: in-page sub-categories shown (small) beneath this leaf in the
  // flyout. They deep-link to `#/section/leaf/<subId>`; the page reads the
  // suffix to open the matching tile/modal. Not separate routes.
  subItems?: { id: string; label: string }[];
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

// The information architecture. The product is organized into three zones that
// the IconRail renders with thin-line dividers:
//   Monitor    — Dashboards · Monitoring · Incident Response · Automation
//   Infra      — Infrastructure (the device fleet) · Security
//   Data       — Metrics · Flows · Logs (the raw telemetry planes)
// with Correlix AI pinned to the foot and Governance (Explain · Stack ·
// Administration) anchored beneath it. Order here is the canonical order; the
// rail's GROUPS map sections into the zones above.
export const NAV: NavSection[] = [
  // ── Monitor zone ──────────────────────────────────────────────────────────
  // Dashboards — curated views + the dashboard catalog + scheduled Reports.
  {
    id: "dashboards",
    label: "Dashboards",
    icon: "dashboards",
    children: [
      { id: "home", label: "Home", render: () => <FrontPage /> },
      { id: "board", label: "My Dashboard", render: () => <Dashboard /> },
      {
        id: "list",
        label: "Dashboard List",
        render: () => <DashboardList />,
        subItems: [
          { id: "device-metric", label: "Device Metrics" },
          { id: "interface-metric", label: "Interface Metrics" },
          { id: "bgp-metric", label: "BGP Metrics" },
          { id: "bandwidth", label: "Bandwidth Utilization" },
          { id: "wan-circuit", label: "WAN Circuit Utilization" },
        ],
      },
      { id: "reports", label: "Reports", render: () => <Reports /> },
    ],
  },
  // Monitoring — one section, two labelled sub-hierarchies (the flyout AND the
  // in-page tab bar render the groups as headers): "Monitors" (definitions, live
  // state, quality) and "Event Management" (events · incidents · anomalies ·
  // correlations). Routes stay monitoring/* so deep links are stable.
  {
    id: "monitoring",
    label: "Monitoring",
    icon: "monitoring",
    children: [
      { id: "monitors", label: "Monitor Rules", group: "Monitors", render: () => <Rules /> },
      { id: "new", label: "Create Monitor", group: "Monitors", render: () => <NewMonitor /> },
      { id: "triggered", label: "Active Alerts", group: "Monitors", render: () => <Alerts /> },
      { id: "quality", label: "Link Quality", group: "Monitors", render: (c) => <Quality rangeMinutes={c.rangeMinutes} /> },
      { id: "events", label: "Events", group: "Event Management", render: (c) => <Events sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "incidents", label: "Incidents", group: "Event Management", render: () => <Incidents /> },
      { id: "anomalies", label: "Anomalies", group: "Event Management", render: () => <Findings /> },
      { id: "correlations", label: "Correlations", group: "Event Management", render: () => <Correlations /> },
      { id: "appobs", label: "App Observability", group: "Event Management", render: () => <AppObservability />, subItems: [
        { id: "overview", label: "Overview" }, { id: "applications", label: "Applications" },
        { id: "attribution", label: "Attribution" }, { id: "unknowns", label: "Unknowns" },
        { id: "evidence", label: "Evidence" },
      ] },
      { id: "reliability", label: "Recovery Scorecard", group: "Event Management", render: () => <ReliabilityScorecard /> },
    ],
  },
  // Incident Response — coordinate response across chat/collaboration tools, and
  // configure the notification + ITSM integrations that route incidents.
  {
    id: "incident",
    label: "Incident Response",
    icon: "incident",
    children: [
      { id: "overview", label: "Command Center", render: () => <CommandCenter /> },
      { id: "notifications", label: "Notifications", render: () => <NotificationsAdmin /> },
      { id: "integrations", label: "Integrations", render: () => <IntegrationsAdmin /> },
      { id: "rca-ticketing", label: "RCA Auto-Ticketing", render: () => <IncidentPoliciesAdmin /> },
    ],
  },
  // Automation — system-of-record (Source of Truth) + automation integrations.
  // Platform-owner only (the SoT config is platform infrastructure).
  {
    id: "automation",
    label: "Automation",
    icon: "automation",
    platformOnly: true,
    children: [
      { id: "sot", label: "Source Of Truth", render: () => <SourceOfTruth /> },
    ],
  },
  // ── Infrastructure zone ─────────────────────────────────────────────────────
  // Infrastructure — the device fleet: devices, maps, netflow, tunnels, and the
  // collection plumbing (collectors / SNMP profiles).
  {
    id: "infrastructure",
    label: "Infrastructure",
    icon: "infrastructure",
    // Two-layer hierarchy: every leaf sits under a named group (the flyout
    // renders the group label as a sub-header), ordered by how an operator
    // works — what do I have → how is it doing → where is it → how does
    // traffic get there → how is it collected.
    children: [
      { id: "devices", label: "Devices", group: "Inventory", render: () => <Devices /> },
      // Dashboards — the device-monitoring board suite (see
      // docs/design/device-monitoring-dashboards.md).
      { id: "monitoring", label: "Device Monitoring", group: "Dashboards", render: (c) => <DeviceMonitoring rangeMinutes={c.rangeMinutes} /> },
      { id: "ifperf", label: "Interface Performance", group: "Dashboards", render: (c) => <InterfacePerformance rangeMinutes={c.rangeMinutes} /> },
      { id: "bgpospf", label: "Protocol Monitoring", group: "Dashboards", render: (c) => <BgpOspf rangeMinutes={c.rangeMinutes} /> },
      { id: "troubleshooting", label: "Troubleshooting", group: "Dashboards", render: (c) => <Troubleshooting rangeMinutes={c.rangeMinutes} /> },
      // Correlix Topology Operating Canvas (React Flow + ELK). Evidence-backed,
      // renderer-agnostic; see docs/Correlix_Topology_Operating_Canvas_Guide.
      // Now the SINGLE topology view — the legacy Device Topology Map was retired.
      { id: "topology-canvas", label: "Topology Canvas", group: "Maps", render: () => <TopologyCanvas /> },
      { id: "geomap", label: "Device Geomap", group: "Maps", render: () => <DeviceGeomap /> },
      // Paths & overlays — how traffic actually traverses the network:
      // hop-by-hop active paths (Flow Trace) and overlay circuits (Tunnels).
      { id: "flowtrace", label: "Flow Trace", group: "Paths & Overlays", render: (c) => <NetworkPath rangeMinutes={c.rangeMinutes} /> },
      { id: "tunnels", label: "Tunnels", group: "Paths & Overlays", render: () => <Tunnels /> },
    ],
  },
  // Security — vulnerability, threat and compliance posture across the fleet.
  {
    id: "security",
    label: "Security",
    icon: "shield",
    children: [
      { id: "vuln", label: "Vulnerability Management", render: () => <VulnerabilityManagement /> },
      { id: "threat", label: "Threat Detection", render: (c) => <ThreatDetection sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "compliance", label: "Compliance Monitoring", render: () => <ComplianceMonitoring /> },
    ],
  },
  // ── Data zone (raw telemetry planes) ────────────────────────────────────────
  {
    id: "metrics",
    label: "Metrics",
    icon: "metrics",
    render: (c) => <MetricsExplorer rangeMinutes={c.rangeMinutes} />,
  },
  {
    id: "flows",
    label: "Flows",
    icon: "flows",
    render: (c) => <Flows sinceSeconds={c.rangeMinutes * 60} />,
  },
  {
    id: "logs",
    label: "Logs",
    icon: "logs",
    children: [
      { id: "logs", label: "Log Explorer", render: (c) => <Logs initialQuery={c.query} rangeMinutes={c.rangeMinutes} /> },
      { id: "saved", label: "Saved Searches", render: () => <SavedSearches /> },
    ],
  },
  // Explain (L3) — the access-reasoning layer: who can reach what, and WHY.
  {
    id: "explain",
    label: "Explain",
    icon: "key", // access-reasoning layer (Access Explorer) — a key reads as "access", not another chart
    children: [
      { id: "access", label: "Access Explorer", render: () => <AccessExplorer /> },
    ],
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
      // Developer — power-user, API-first tooling.
      { id: "graphql", label: "GraphQL Explorer", group: "Developer", render: () => <GraphQLExplorer /> },
    ],
  },
  {
    id: "copilot",
    label: "Correlix AI",
    icon: "copilot",
    action: "copilot",
    footer: true,
  },
  // Administration — config + power-user escape hatches to the raw backend
  // tools, kept out of the day-to-day monitoring sections (as Grafana
  // do: backends live under admin/connections, not next to dashboards).
  {
    id: "admin",
    label: "Administration",
    icon: "settings",
    footer: true,
    children: [
      { id: "settings", label: "Settings", render: () => <Settings /> },
      // Data Collection — moved out of Infrastructure (kept it uncrowded): the
      // sources + the poller plumbing that feed telemetry.
      { id: "datasources", label: "Data Sources", group: "Data Collection", render: () => <DataSources /> },
      { id: "collectors", label: "Collectors", group: "Data Collection", platformOnly: true, render: () => <Collectors /> },
      { id: "snmp", label: "SNMP Profile Manager", group: "Data Collection", render: () => <SnmpProfileManager /> },
      // Identity & Access — consolidates Users · Roles · Security Settings,
      // split into Global (platform-wide) and Tenants (per tenant, configured
      // independently). The tenant registry + per-tenant drill-in live inside it.
      { id: "regions", label: "Regions", platformOnly: true, render: () => <RegionsAdmin /> },
      { id: "identity", label: "Identity & Access", render: () => <IdentityAccess /> },
      { id: "access", label: "Access Grants", render: () => <BindingsAdmin /> },
      { id: "sessions", label: "Sessions", platformOnly: true, render: () => <SessionsAdmin /> },
      { id: "auth", label: "Authentication", render: () => <AuthenticationAdmin /> },
      {
        id: "api", label: "API Access", render: () => <ApiAccessAdmin />,
        subItems: [
          { id: "keys", label: "Generate API key" },
          { id: "token", label: "Token Policy" },
          { id: "rest", label: "REST API Reference" },
        ],
      },
      // Notifications + Integrations live under Incident Response (their
      // operational home), not duplicated here.
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
  const path = hash.replace(/^#\/?/, "").split("?")[0]; // drop ?query (deep-link params)
  const [sectionId, leafId] = path.split("/");
  const section = nav.find((s) => s.id === sectionId) ?? nav[0];
  if (!section.children) return { section };
  const leaf = section.children.find((l) => l.id === leafId) ?? section.children[0];
  return { section, leaf };
}

// landingResolves reports whether an administratively-configured landing route
// points at a REAL, ACCESSIBLE leaf in the given (already principal-filtered) nav —
// i.e. resolveRoute round-trips it instead of silently falling back. Used to apply a
// configured default landing only when it's valid for this user; otherwise the app
// keeps its built-in home. (resolveRoute never reports "not found", so we compare.)
export function landingResolves(hash: string, nav: NavSection[] = NAV): boolean {
  const path = hash.replace(/^#\/?/, "").split("?")[0];
  const [sectionId, leafId] = path.split("/");
  if (!sectionId) return false;
  const r = resolveRoute(hash, nav);
  if (r.section.id !== sectionId) return false;
  return !leafId || r.leaf?.id === leafId;
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
        // Deep-link sub-categories (e.g. API Access ▸ Token Policy) into ⌘K.
        for (const sub of l.subItems ?? []) {
          out.push({ label: `${s.label} · ${sub.label}`, section: s.label, route: `${s.id}/${l.id}/${sub.id}` });
        }
      }
    } else {
      out.push({ label: s.label, section: s.label, route: s.id });
    }
  }
  return out;
}
