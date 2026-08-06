import { lazy } from "react";
import { SectionCtx } from "./context/shell";
import { AI_NAME } from "./brand";

// Pages / tabs (existing components, reparented into product sections).
// Every page is route-level code-split via React.lazy — the shell renders the
// active leaf inside ONE <Suspense> boundary in App.tsx, so only the visited
// page's chunk is fetched. nav.tsx itself stays in the initial bundle (it is
// the route table), which is why nothing here may import a page eagerly.
const Dashboard = lazy(() => import("./pages/Dashboard"));
const DemoShowcase = lazy(() => import("./pages/DemoShowcase"));
const FrontPage = lazy(() => import("./pages/FrontPage"));
const Devices = lazy(() => import("./pages/Devices"));
const DeviceMonitoring = lazy(() => import("./pages/DeviceMonitoring"));
const InterfacePerformance = lazy(() => import("./pages/InterfacePerformance"));
const PortsWorkbench = lazy(() => import("./pages/PortsWorkbench"));
const NmsIntegrations = lazy(() => import("./pages/NmsIntegrations"));
const Wireless = lazy(() => import("./pages/Wireless"));
const BgpOspf = lazy(() => import("./pages/BgpOspf"));
const Troubleshooting = lazy(() => import("./pages/Troubleshooting"));
const ThreatDetection = lazy(() => import("./pages/ThreatDetection"));
const Events = lazy(() => import("./pages/Events"));
const Correlations = lazy(() => import("./tabs/Correlations"));
const RcaReports = lazy(() => import("./pages/RcaReports"));
const AppObservability = lazy(() => import("./pages/AppObservability"));
const ReliabilityScorecard = lazy(() => import("./pages/ReliabilityScorecard"));
const Quality = lazy(() => import("./pages/Quality"));
const DataSources = lazy(() => import("./pages/DataSources"));
const NetworkPath = lazy(() => import("./pages/NetworkPath"));
const Reports = lazy(() => import("./pages/Reports"));
const TopologyCanvas = lazy(() => import("./features/topology/renderers/react-flow/TopologyCanvas"));
const Collectors = lazy(() => import("./tabs/Collectors"));
const SnmpProfileManager = lazy(() => import("./tabs/SnmpProfileManager"));
const Alerts = lazy(() => import("./tabs/Alerts"));
const MaintenanceWindows = lazy(() => import("./tabs/MaintenanceWindows"));
const ProcessorsAdmin = lazy(() => import("./tabs/ProcessorsAdmin"));
const SensitiveDataAccess = lazy(() => import("./tabs/SensitiveDataAccess"));
const Rules = lazy(() => import("./tabs/Rules"));
const Findings = lazy(() => import("./tabs/Findings"));
const Incidents = lazy(() => import("./tabs/Incidents"));
const Logs = lazy(() => import("./tabs/Logs"));
const CloudLogs = lazy(() => import("./pages/CloudLogs"));
const SavedSearches = lazy(() => import("./tabs/SavedSearches"));
const Flows = lazy(() => import("./tabs/Flows"));
const Tunnels = lazy(() => import("./tabs/Tunnels"));
const WanCircuits = lazy(() => import("./pages/WanCircuits"));
const MetricsExplorer = lazy(() => import("./tabs/MetricsExplorer"));
const GrafanaTab = lazy(() => import("./tabs/Grafana"));
const SearchDashboardsTab = lazy(() => import("./tabs/SearchDashboards"));
const Settings = lazy(() => import("./tabs/Settings"));
const SourceOfTruth = lazy(() => import("./tabs/SourceOfTruth"));
const StackHealth = lazy(() => import("./tabs/StackHealth"));
const AuditLog = lazy(() => import("./tabs/AuditLog"));
const TransportSecurity = lazy(() => import("./tabs/TransportSecurity"));
const AccessExplorer = lazy(() => import("./tabs/AccessExplorer"));
// tabs/admin exports its 9 views by name; lazy() needs a default, so each
// wrapper re-shapes the named export. They all share the one admin chunk.
const IdentityAccess = lazy(() => import("./tabs/admin").then((m) => ({ default: m.IdentityAccess })));
const RegionsAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.RegionsAdmin })));
const SessionsAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.SessionsAdmin })));
const AuthenticationAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.AuthenticationAdmin })));
const ApiAccessAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.ApiAccessAdmin })));
const IntegrationsAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.IntegrationsAdmin })));
const NotificationsAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.NotificationsAdmin })));
const IncidentPoliciesAdmin = lazy(() => import("./tabs/admin").then((m) => ({ default: m.IncidentPoliciesAdmin })));
const GraphQLExplorer = lazy(() => import("./tabs/admin").then((m) => ({ default: m.GraphQLExplorer })));
const DashboardList = lazy(() => import("./pages/Placeholders").then((m) => ({ default: m.DashboardList })));
const DeviceGeomap = lazy(() => import("./pages/DeviceGeomap"));
const VulnerabilityManagement = lazy(() => import("./pages/VulnerabilityManagement"));
const ComplianceMonitoring = lazy(() => import("./pages/ComplianceMonitoring"));
const NewMonitor = lazy(() => import("./pages/NewMonitor"));
const CommandCenter = lazy(() => import("./pages/CommandCenter"));

// A leaf is one rendered view. Sections with multiple leaves get a SubNav.
export type NavLeaf = {
  id: string;
  label: string;
  render: (c: SectionCtx) => JSX.Element;
  platformOnly?: boolean; // visible only to the cross-tenant platform owner
  requiresGrafana?: boolean; // shown only when the self-monitoring add-on runs
  // group: render this leaf under a labelled heading in the hover flyout
  // (e.g. "Developer"). Consecutive leaves sharing a group sit under one header.
  group?: string;
  // subItems: in-page sub-categories shown (small) beneath this leaf in the
  // flyout. They deep-link to `#/section/leaf/<subId>`; the page reads the
  // suffix to open the matching tile/modal. Not separate routes.
  // `route` (optional): when set, the flyout sub-item navigates to that full
  // hash route (e.g. "infrastructure/monitoring") instead of scrolling to an
  // in-page anchor — used by the Dashboard List directory to deep-link to the
  // real board each name opens.
  subItems?: { id: string; label: string; route?: string }[];
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
// with Iris AI pinned to the foot and Governance (Explain · Stack ·
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
      // Home IS the operational control plane (Command Center) — consistently, on
      // first load, in-app navigation, and refresh alike. Previously Home rendered
      // the Operations Overview while a configured default-landing redirected to
      // Command Center only on reload, so Home flipped between the two (UI-7).
      // Operations Overview keeps its own leaf below.
      { id: "home", label: "Home", render: () => <CommandCenter /> },
      { id: "operations", label: "Operations Overview", render: () => <FrontPage /> },
      { id: "board", label: "My Dashboard", render: () => <Dashboard /> },
      // Marketing demo board: same live panel registry, flashier chrome
      // (gauge wheels + ranked bars + donuts). Style over depth, on purpose.
      { id: "demo", label: "Demo Showcase", render: () => <DemoShowcase /> },
      {
        id: "list",
        label: "Dashboard List",
        render: () => <DashboardList />,
        subItems: [
          { id: "device-metric", label: "Device Metrics", route: "infrastructure/monitoring" },
          { id: "interface-metric", label: "Interface Metrics", route: "infrastructure/ifperf" },
          { id: "bgp-metric", label: "BGP Metrics", route: "infrastructure/bgpospf" },
          { id: "bandwidth", label: "Bandwidth Utilization", route: "infrastructure/monitoring" },
          { id: "wan-circuit", label: "WAN Interface Metrics", route: "infrastructure/wan-circuits" },
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
      // Item 121: planned-work windows — pause notifications, stamp reliability
      // rollups as planned maintenance. Sits with the alert surface it governs.
      { id: "maintenance", label: "Maintenance Windows", group: "Monitors", render: () => <MaintenanceWindows /> },
      { id: "quality", label: "Link Quality", group: "Monitors", render: (c) => <Quality rangeMinutes={c.rangeMinutes} /> },
      { id: "events", label: "Events", group: "Event Management", render: (c) => <Events sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "incidents", label: "Incidents", group: "Event Management", render: () => <Incidents /> },
      { id: "anomalies", label: "Anomalies", group: "Event Management", render: () => <Findings /> },
      { id: "correlations", label: "Correlations", group: "Event Management", render: () => <Correlations /> },
      // #113: the management library — ONLY promoted real outages + documents.
      // Correlations above stays the full engineer surface (every candidate).
      { id: "rca-reports", label: "RCA Reports", group: "Event Management", render: () => <RcaReports /> },
      // Sub-items mirror the page's REAL 5-tab IA (2026-07 review: the flyout
      // still advertised the retired 11-tab vocabulary — two names for one view).
      { id: "appobs", label: "Service View", group: "Event Management", render: () => <AppObservability />, subItems: [
        { id: "overview", label: "Overview" }, { id: "services", label: "Services" },
        { id: "investigations", label: "Investigations" }, { id: "resources", label: "Resources" },
        { id: "datasources", label: "Data Sources" },
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
      // Port Intelligence workbench (#94) — fleet interfaces/ports/optics/DDM.
      { id: "ports", label: "Interfaces & Optics", group: "Inventory", render: () => <PortsWorkbench /> },
      // NMS vendor-controller integrations (#95): harvest 3rd-party controller
      // intelligence (Meraki / Catalyst / vManage / NDFC / Versa / Prime) as
      // normalized RCA evidence. Dormant unless FEATURE_NMS_INTEGRATIONS.
      { id: "nms", label: "NMS Integrations", group: "Inventory", render: () => <NmsIntegrations /> },
      // Wireless canonical inventory (#128): controllers, APs + radios, WLANs.
      // Wired + wireless are ONE LAN domain (owner ruling) — this is the
      // wireless VIEW of it, filled by controller connectors (Catalyst 9800).
      { id: "wireless", label: "Wireless", group: "Inventory", render: () => <Wireless /> },
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
      { id: "wan-circuits", label: "WAN Interface Metrics", group: "Paths & Overlays", render: () => <WanCircuits /> },
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
      { id: "logs", label: "Log Search", render: (c) => <Logs initialQuery={c.query} rangeMinutes={c.rangeMinutes} /> },
      // Unified Cloud Logs — one screen, a lane per cloud log family (Inventory ·
      // Flow · Load Balancer · WAF · DNS · Change · Host). Lives in the Data zone
      // beside Log Search: it IS a raw telemetry plane (tagged cloud logs), the
      // cloud sibling of device syslog — not another correlation surface.
      { id: "cloud", label: "Cloud Logs", render: () => <CloudLogs /> },
      { id: "saved", label: "Saved Searches", render: () => <SavedSearches /> },
    ],
  },
  {
    id: "copilot",
    label: AI_NAME,
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
    icon: "sliders",
    footer: true,
    children: [
      { id: "settings", label: "Settings", render: () => <Settings /> },
      // Data Collection — moved out of Infrastructure (kept it uncrowded): the
      // sources + the poller plumbing that feed telemetry.
      { id: "datasources", label: "Data Sources", group: "Data Collection", render: () => <DataSources /> },
      // Item 121: per-tenant processor editor (redact/drop/set shaping compiled
      // into the ingest router). Admin-gated server-side; sits with the plumbing
      // that feeds telemetry.
      { id: "processors", label: "Processors", group: "Data Collection", render: () => <ProcessorsAdmin /> },
      // Sealed Fields (#129): who revealed protected data, when, and why. Sits
      // beside the processors that seal it. Server-gated on sensitive_data:admin
      // — the same permission revealing needs, because knowing WHICH values were
      // worth looking at is itself sensitive.
      { id: "sensitive-data-access", label: "Sensitive Data Access", group: "Data Collection", render: () => <SensitiveDataAccess /> },
      { id: "collectors", label: "Collectors", group: "Data Collection", platformOnly: true, render: () => <Collectors /> },
      { id: "snmp", label: "SNMP Profile Manager", group: "Data Collection", render: () => <SnmpProfileManager /> },
      // Identity & Access — consolidates Users · Roles · Security Settings,
      // split into Global (platform-wide) and Tenants (per tenant, configured
      // independently). The tenant registry + per-tenant drill-in live inside it.
      { id: "regions", label: "Regions", platformOnly: true, render: () => <RegionsAdmin /> },
      { id: "identity", label: "Identity & Access", render: () => <IdentityAccess /> },
      // Security — authentication providers, live sessions and the audit trail,
      // grouped at the same level as Data Collection.
      { id: "auth", label: "Authentication", group: "Security", render: () => <AuthenticationAdmin /> },
      // Access Explorer — the access-reasoning layer (who can reach what, and
      // WHY). Lives beside Authentication (was its own "Explain" rail section).
      { id: "access", label: "Access Explorer", group: "Security", render: () => <AccessExplorer /> },
      { id: "sessions", label: "Sessions", group: "Security", platformOnly: true, render: () => <SessionsAdmin /> },
      { id: "audit", label: "Audit Log", group: "Security", render: () => <AuditLog /> },
      // SEC-021.1: read-only TLS posture inventory. NOT platformOnly — tenant
      // admins get their scoped device-lane view; the backend enforces scope.
      { id: "transport", label: "Transport Security", group: "Security", render: () => <TransportSecurity /> },
      // Stack — the platform's OWN infra plumbing + raw-backend tools (was its
      // own rail section). Platform-owner only, leaf-stamped since the section
      // flag is gone; the backend enforces it independently (/api/stack/health
      // 403, nginx auth_request on /search, etc.).
      { id: "health", label: "Stack Health", group: "Stack", platformOnly: true, render: () => <StackHealth /> },
      { id: "grafana", label: "Self-Monitoring", group: "Stack", platformOnly: true, requiresGrafana: true, render: () => <GrafanaTab /> },
      { id: "opensearch", label: "OpenSearch", group: "Stack", platformOnly: true, render: () => <SearchDashboardsTab /> },
      { id: "graphql", label: "GraphQL Explorer", group: "Stack", platformOnly: true, render: () => <GraphQLExplorer /> },
      {
        id: "api", label: "API Access", render: () => <ApiAccessAdmin />,
        subItems: [
          { id: "keys", label: "Generate API key" },
          { id: "token", label: "Token Policy" },
          { id: "rest", label: "REST API Reference" },
        ],
      },
      // Notifications + Integrations live under Incident Response (their
      // operational home), not duplicated here. Assign-access merged into the
      // Identity & Access "＋ Add" guided flow (and each org's Access tab).
    ],
  },
];

export type Resolved = {
  section: NavSection;
  leaf?: NavLeaf;
};

// ── Permanent resource URLs (Wave 6 #20) ─────────────────────────────────────
// #/resource/{kind}/{id} is a first-class route OUTSIDE the section/leaf nav
// tree: a stable, shareable page per resource. The id is the canonical opaque
// id (URL-encoded; may itself contain "/" once encoded — everything after the
// kind segment is the id). resolveResourceRoute is checked BEFORE resolveRoute
// in the shell; a null means "not a resource URL, use the nav router".
export type ResourceRoute = { kind: string; id: string };

export function resolveResourceRoute(hash: string): ResourceRoute | null {
  const path = hash.replace(/^#\/?/, "").split("?")[0];
  const segs = path.split("/");
  if (segs[0] !== "resource" || segs.length < 3) return null;
  const kind = segs[1];
  const rawID = segs.slice(2).join("/");
  if (!kind || !rawID) return null;
  let id = rawID;
  try {
    id = decodeURIComponent(rawID);
  } catch {
    // malformed escapes: keep the raw form — the backend will honestly 404
  }
  return { kind, id };
}

/** The hash route (no leading "#/") for a resource's permanent page. */
export function resourceRouteFor(kind: string, id: string): string {
  return `resource/${kind}/${encodeURIComponent(id)}`;
}

// filteredNav drops platform-owner-only sections/leaves for tenant-scoped users.
// The platform owner sees the full tree. This is UX gating; the backend enforces
// the boundary independently (e.g. /api/stack/health returns 403).
export function filteredNav(platformAdmin: boolean, grafanaEnabled = true): NavSection[] {
  // Grafana is the self-monitoring ADD-ON's console: hide its tab entirely
  // when the deployment doesn't run it (a dead iframe is not navigation).
  const dropGrafana = (s: NavSection): NavSection =>
    s.children && !grafanaEnabled
      ? { ...s, children: s.children.filter((l) => !l.requiresGrafana) }
      : s;
  if (platformAdmin) return NAV.map(dropGrafana);
  return NAV.filter((s) => !s.platformOnly).map((s) =>
    dropGrafana(s.children ? { ...s, children: s.children.filter((l) => !l.platformOnly) } : s),
  );
}

// Parse "#/section/leaf" into the section + active leaf, with fallbacks. The nav
// defaults to the full tree; pass a filtered tree to keep hidden routes
// unreachable via the hash (they fall back to the first visible entry).
// Legacy route aliases — the Explain + Stack rail sections were dissolved into
// Administration (2026-07-10); bookmarks/deep links to the old sections must
// keep landing on the moved pages instead of silently falling back to home.
// Leaf ids were preserved in the move, so old section → admin is enough.
const LEGACY_SECTION_ALIAS: Record<string, string> = { explain: "admin", stack: "admin" };
function canonicalPath(hash: string): [string, string | undefined] {
  const path = hash.replace(/^#\/?/, "").split("?")[0]; // drop ?query (deep-link params)
  const [sectionId, leafId] = path.split("/");
  const aliased = LEGACY_SECTION_ALIAS[sectionId];
  // Old bare "#/explain" had a single leaf; map it to its moved page explicitly.
  if (aliased && sectionId === "explain" && !leafId) return [aliased, "access"];
  if (aliased && sectionId === "stack" && !leafId) return [aliased, "health"];
  return [aliased ?? sectionId, leafId];
}

export function resolveRoute(hash: string, nav: NavSection[] = NAV): Resolved {
  const [sectionId, leafId] = canonicalPath(hash);
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
  // Compare against the CANONICAL path so a landing saved before the Explain/
  // Stack → Administration move keeps validating (it resolves to the moved leaf).
  const [sectionId, leafId] = canonicalPath(hash);
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
          out.push({ label: `${s.label} · ${sub.label}`, section: s.label, route: sub.route ?? `${s.id}/${l.id}/${sub.id}` });
        }
      }
    } else {
      out.push({ label: s.label, section: s.label, route: s.id });
    }
  }
  return out;
}
