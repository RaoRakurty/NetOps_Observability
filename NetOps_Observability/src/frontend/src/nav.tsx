import React, { lazy } from "react";
import { SectionCtx } from "./context/shell";
import { AI_NAME } from "./brand";

// Pages / tabs (existing components, reparented into product sections).
// Every page is route-level code-split via React.lazy — the shell renders the
// active leaf inside ONE <Suspense> boundary in App.tsx, so only the visited
// page's chunk is fetched. nav.tsx itself stays in the initial bundle (it is
// the route table), which is why nothing here may import a page eagerly.
// Route-chunk registry (perf wave 2026-08-25): every page's import thunk,
// addressable OUTSIDE React.lazy so the shell can PREFETCH chunks (idle
// warm-up in App.tsx). lazy() below consumes the same thunk, so each page
// still code-splits exactly as before — one chunk, fetched once, shared
// between prefetch and first render.
export const ROUTE_CHUNKS: Record<string, () => Promise<unknown>> = {
  Dashboard: () => import("./pages/Dashboard"),
  DemoShowcase: () => import("./pages/DemoShowcase"),
  FrontPage: () => import("./pages/FrontPage"),
  Devices: () => import("./pages/Devices"),
  DeviceMonitoring: () => import("./pages/DeviceMonitoring"),
  InterfacePerformance: () => import("./pages/InterfacePerformance"),
  PortsWorkbench: () => import("./pages/PortsWorkbench"),
  Wireless: () => import("./pages/Wireless"),
  BgpOspf: () => import("./pages/BgpOspf"),
  BgpOps: () => import("./pages/BgpOps"),
  Troubleshooting: () => import("./pages/Troubleshooting"),
  Events: () => import("./pages/Events"),
  Correlations: () => import("./tabs/Correlations"),
  RcaReports: () => import("./pages/RcaReports"),
  AppObservability: () => import("./pages/AppObservability"),
  ReliabilityScorecard: () => import("./pages/ReliabilityScorecard"),
  Quality: () => import("./pages/Quality"),
  DataSources: () => import("./pages/DataSources"),
  NetworkPath: () => import("./pages/NetworkPath"),
  Reports: () => import("./pages/Reports"),
  TopologyCanvas: () => import("./features/topology/renderers/react-flow/TopologyCanvas"),
  Collectors: () => import("./tabs/Collectors"),
  SnmpProfileManager: () => import("./tabs/SnmpProfileManager"),
  Alerts: () => import("./tabs/Alerts"),
  MaintenanceWindows: () => import("./tabs/MaintenanceWindows"),
  ProcessorsAdmin: () => import("./tabs/ProcessorsAdmin"),
  SensitiveDataAccess: () => import("./tabs/SensitiveDataAccess"),
  Rules: () => import("./tabs/Rules"),
  Findings: () => import("./tabs/Findings"),
  Incidents: () => import("./tabs/Incidents"),
  SavedSearches: () => import("./tabs/SavedSearches"),
  Flows: () => import("./tabs/Flows"),
  Tunnels: () => import("./tabs/Tunnels"),
  WanCircuits: () => import("./pages/WanCircuits"),
  MetricsExplorer: () => import("./tabs/MetricsExplorer"),
  GrafanaTab: () => import("./tabs/Grafana"),
  SearchDashboardsTab: () => import("./tabs/SearchDashboards"),
  Settings: () => import("./tabs/Settings"),
  SourceOfTruth: () => import("./tabs/SourceOfTruth"),
  StackHealth: () => import("./tabs/StackHealth"),
  AuditLog: () => import("./tabs/AuditLog"),
  TransportSecurity: () => import("./tabs/TransportSecurity"),
  AccessExplorer: () => import("./tabs/AccessExplorer"),
  VulnerabilityManagement: () => import("./pages/VulnerabilityManagement"),
  // Security CTEM section (P3-T8) — one chunk per route, lazily fetched.
  SecurityOverview: () => import("./pages/security/SecurityOverview"),
  SecurityExposures: () => import("./pages/security/Exposures"),
  SecurityExposureStories: () => import("./pages/security/ExposureStories"),
  SecurityThreatDetection: () => import("./pages/security/ThreatDetectionView"),
  SecurityCompliance: () => import("./pages/security/SecurityCompliance"),
  SecurityRules: () => import("./pages/security/SecurityRules"),
  SecuritySavedViews: () => import("./pages/security/SavedViews"),
  NewMonitor: () => import("./pages/NewMonitor"),
  CommandCenter: () => import("./pages/CommandCenter"),
  ActionQueue: () => import("./pages/ActionQueue"),
  Sites: () => import("./pages/Sites"),
  Discovery: () => import("./pages/Discovery"),
  LogsExplore: () => import("./pages/LogsExplore"),
};

const Dashboard = lazy(ROUTE_CHUNKS["Dashboard"] as () => Promise<{ default: React.ComponentType<any> }>);
const DemoShowcase = lazy(ROUTE_CHUNKS["DemoShowcase"] as () => Promise<{ default: React.ComponentType<any> }>);
const FrontPage = lazy(ROUTE_CHUNKS["FrontPage"] as () => Promise<{ default: React.ComponentType<any> }>);
const Devices = lazy(ROUTE_CHUNKS["Devices"] as () => Promise<{ default: React.ComponentType<any> }>);
const DeviceMonitoring = lazy(ROUTE_CHUNKS["DeviceMonitoring"] as () => Promise<{ default: React.ComponentType<any> }>);
const InterfacePerformance = lazy(ROUTE_CHUNKS["InterfacePerformance"] as () => Promise<{ default: React.ComponentType<any> }>);
const PortsWorkbench = lazy(ROUTE_CHUNKS["PortsWorkbench"] as () => Promise<{ default: React.ComponentType<any> }>);
const Wireless = lazy(ROUTE_CHUNKS["Wireless"] as () => Promise<{ default: React.ComponentType<any> }>);
const BgpOspf = lazy(ROUTE_CHUNKS["BgpOspf"] as () => Promise<{ default: React.ComponentType<any> }>);
const BgpOps = lazy(ROUTE_CHUNKS["BgpOps"] as () => Promise<{ default: React.ComponentType<any> }>);
const Troubleshooting = lazy(ROUTE_CHUNKS["Troubleshooting"] as () => Promise<{ default: React.ComponentType<any> }>);
const Events = lazy(ROUTE_CHUNKS["Events"] as () => Promise<{ default: React.ComponentType<any> }>);
const Correlations = lazy(ROUTE_CHUNKS["Correlations"] as () => Promise<{ default: React.ComponentType<any> }>);
const RcaReports = lazy(ROUTE_CHUNKS["RcaReports"] as () => Promise<{ default: React.ComponentType<any> }>);
const AppObservability = lazy(ROUTE_CHUNKS["AppObservability"] as () => Promise<{ default: React.ComponentType<any> }>);
const ReliabilityScorecard = lazy(ROUTE_CHUNKS["ReliabilityScorecard"] as () => Promise<{ default: React.ComponentType<any> }>);
const Quality = lazy(ROUTE_CHUNKS["Quality"] as () => Promise<{ default: React.ComponentType<any> }>);
const DataSources = lazy(ROUTE_CHUNKS["DataSources"] as () => Promise<{ default: React.ComponentType<any> }>);
const NetworkPath = lazy(ROUTE_CHUNKS["NetworkPath"] as () => Promise<{ default: React.ComponentType<any> }>);
const Reports = lazy(ROUTE_CHUNKS["Reports"] as () => Promise<{ default: React.ComponentType<any> }>);
const TopologyCanvas = lazy(ROUTE_CHUNKS["TopologyCanvas"] as () => Promise<{ default: React.ComponentType<any> }>);
const Collectors = lazy(ROUTE_CHUNKS["Collectors"] as () => Promise<{ default: React.ComponentType<any> }>);
const SnmpProfileManager = lazy(ROUTE_CHUNKS["SnmpProfileManager"] as () => Promise<{ default: React.ComponentType<any> }>);
const Alerts = lazy(ROUTE_CHUNKS["Alerts"] as () => Promise<{ default: React.ComponentType<any> }>);
const MaintenanceWindows = lazy(ROUTE_CHUNKS["MaintenanceWindows"] as () => Promise<{ default: React.ComponentType<any> }>);
const ProcessorsAdmin = lazy(ROUTE_CHUNKS["ProcessorsAdmin"] as () => Promise<{ default: React.ComponentType<any> }>);
const SensitiveDataAccess = lazy(ROUTE_CHUNKS["SensitiveDataAccess"] as () => Promise<{ default: React.ComponentType<any> }>);
const Rules = lazy(ROUTE_CHUNKS["Rules"] as () => Promise<{ default: React.ComponentType<any> }>);
const Findings = lazy(ROUTE_CHUNKS["Findings"] as () => Promise<{ default: React.ComponentType<any> }>);
const Incidents = lazy(ROUTE_CHUNKS["Incidents"] as () => Promise<{ default: React.ComponentType<any> }>);
const SavedSearches = lazy(ROUTE_CHUNKS["SavedSearches"] as () => Promise<{ default: React.ComponentType<any> }>);
const Flows = lazy(ROUTE_CHUNKS["Flows"] as () => Promise<{ default: React.ComponentType<any> }>);
const Tunnels = lazy(ROUTE_CHUNKS["Tunnels"] as () => Promise<{ default: React.ComponentType<any> }>);
const WanCircuits = lazy(ROUTE_CHUNKS["WanCircuits"] as () => Promise<{ default: React.ComponentType<any> }>);
const MetricsExplorer = lazy(ROUTE_CHUNKS["MetricsExplorer"] as () => Promise<{ default: React.ComponentType<any> }>);
const GrafanaTab = lazy(ROUTE_CHUNKS["GrafanaTab"] as () => Promise<{ default: React.ComponentType<any> }>);
const SearchDashboardsTab = lazy(ROUTE_CHUNKS["SearchDashboardsTab"] as () => Promise<{ default: React.ComponentType<any> }>);
const Settings = lazy(ROUTE_CHUNKS["Settings"] as () => Promise<{ default: React.ComponentType<any> }>);
const SourceOfTruth = lazy(ROUTE_CHUNKS["SourceOfTruth"] as () => Promise<{ default: React.ComponentType<any> }>);
const StackHealth = lazy(ROUTE_CHUNKS["StackHealth"] as () => Promise<{ default: React.ComponentType<any> }>);
const AuditLog = lazy(ROUTE_CHUNKS["AuditLog"] as () => Promise<{ default: React.ComponentType<any> }>);
const TransportSecurity = lazy(ROUTE_CHUNKS["TransportSecurity"] as () => Promise<{ default: React.ComponentType<any> }>);
const AccessExplorer = lazy(ROUTE_CHUNKS["AccessExplorer"] as () => Promise<{ default: React.ComponentType<any> }>);
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
const VulnerabilityManagement = lazy(ROUTE_CHUNKS["VulnerabilityManagement"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityOverview = lazy(ROUTE_CHUNKS["SecurityOverview"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityExposures = lazy(ROUTE_CHUNKS["SecurityExposures"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityExposureStories = lazy(ROUTE_CHUNKS["SecurityExposureStories"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityThreatDetection = lazy(ROUTE_CHUNKS["SecurityThreatDetection"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityCompliance = lazy(ROUTE_CHUNKS["SecurityCompliance"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecurityRules = lazy(ROUTE_CHUNKS["SecurityRules"] as () => Promise<{ default: React.ComponentType<any> }>);
const SecuritySavedViews = lazy(ROUTE_CHUNKS["SecuritySavedViews"] as () => Promise<{ default: React.ComponentType<any> }>);
const NewMonitor = lazy(ROUTE_CHUNKS["NewMonitor"] as () => Promise<{ default: React.ComponentType<any> }>);
const CommandCenter = lazy(ROUTE_CHUNKS["CommandCenter"] as () => Promise<{ default: React.ComponentType<any> }>);
// Nav-redesign promotions (2026-08, owner tree): the extracted Action Queue
// page, the Sites page (Device Geomap folded in as its Map tab), the
// Discovery & NMS composite, and the Logs explorer (Log Search + Cloud Logs).
const ActionQueue = lazy(ROUTE_CHUNKS["ActionQueue"] as () => Promise<{ default: React.ComponentType<any> }>);
const Sites = lazy(ROUTE_CHUNKS["Sites"] as () => Promise<{ default: React.ComponentType<any> }>);
const Discovery = lazy(ROUTE_CHUNKS["Discovery"] as () => Promise<{ default: React.ComponentType<any> }>);
const LogsExplore = lazy(ROUTE_CHUNKS["LogsExplore"] as () => Promise<{ default: React.ComponentType<any> }>);

// A leaf is one rendered view. Sections with multiple leaves get a SubNav.
export type NavLeaf = {
  id: string;
  label: string;
  render: (c: SectionCtx) => JSX.Element;
  platformOnly?: boolean; // visible only to the cross-tenant platform owner
  requiresGrafana?: boolean; // shown only when the self-monitoring add-on runs
  // group: render this leaf under a labelled heading in the hover flyout
  // (e.g. "Monitors"). Consecutive leaves sharing a group sit under one header.
  group?: string;
  // subItems: in-page sub-categories shown (small) beneath this leaf in the
  // flyout. They deep-link to `#/section/leaf/<subId>`; the page reads the
  // suffix to open the matching tile/modal. Not separate routes.
  // `route` (optional): when set, the flyout sub-item navigates to that full
  // hash route (e.g. "analytics/device-monitoring") instead of scrolling to an
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

// The information architecture (owner tree, 2026-08 nav redesign). Organized by
// the operator journey rather than by signal type or implementation surface:
//   Overview      — where do I start? (Command Center · Operations · My board)
//   Operations    — what is happening right now? (incidents · alerts · queue)
//   Investigate   — why is it happening? (RCA · findings · topology · paths)
//   Infrastructure— what do I own / what is observed?
//   Explore       — the raw telemetry planes (metrics · logs · flows · events)
//   Security      — tenant-facing security posture
//   Analytics     — trends, boards and management views
// with Iris AI pinned to the foot and Administration anchored beneath it.
// Section/leaf ids ARE the URL space — every pre-redesign hash resolves via the
// alias tables below (see canonicalHash / LEGACY_ROUTE_ALIAS).
export const NAV: NavSection[] = [
  // ── Overview — the landing zone ─────────────────────────────────────────────
  {
    id: "overview",
    label: "Overview",
    icon: "overview",
    children: [
      // Home IS the operational control plane (Command Center) — consistently, on
      // first load, in-app navigation, and refresh alike (UI-7).
      { id: "home", label: "Home", render: () => <CommandCenter /> },
      { id: "operations", label: "Operations Overview", render: () => <FrontPage /> },
      { id: "board", label: "My Dashboard", render: () => <Dashboard /> },
    ],
  },
  // ── Operations — what is happening right now ────────────────────────────────
  {
    id: "operations",
    label: "Operations",
    icon: "monitoring",
    children: [
      { id: "incidents", label: "Incidents", render: () => <Incidents /> },
      { id: "alerts", label: "Active Alerts", render: () => <Alerts /> },
      // The Command Center's triage queue as a first-class routed page (it was a
      // panel with no route; the Command Center keeps its embedded copy).
      { id: "queue", label: "Action Queue", render: () => <ActionQueue /> },
      // Sub-items mirror the page's REAL 5-tab IA (2026-07 review).
      { id: "services", label: "Services", render: () => <AppObservability />, subItems: [
        { id: "overview", label: "Overview" }, { id: "services", label: "Services" },
        { id: "investigations", label: "Investigations" }, { id: "resources", label: "Resources" },
        { id: "datasources", label: "Data Sources" },
      ] },
      { id: "network-health", label: "Network Health", render: (c) => <Quality rangeMinutes={c.rangeMinutes} /> },
      { id: "rules", label: "Monitor Rules", group: "Monitors", render: () => <Rules /> },
      { id: "new", label: "Create Monitor", group: "Monitors", render: () => <NewMonitor /> },
      // Item 121: planned-work windows — pause notifications, stamp reliability
      // rollups as planned maintenance. Sits with the alert surface it governs.
      { id: "maintenance", label: "Maintenance Windows", group: "Monitors", render: () => <MaintenanceWindows /> },
    ],
  },
  // ── Investigate — why is it happening (the RCA heart) ───────────────────────
  {
    id: "investigate",
    label: "Investigate",
    icon: "explore",
    children: [
      // The full engineer surface (every candidate); the promoted-outage library
      // lives under Analytics → RCA Reports (#113).
      { id: "rca", label: "RCA", render: () => <Correlations /> },
      // Label unified to "Findings" (the component was Findings.tsx all along;
      // the old nav called it "Anomalies" — two names for one view).
      { id: "findings", label: "Findings", render: () => <Findings /> },
      // Correlix Topology Operating Canvas (React Flow + ELK) — the SINGLE
      // topology view; Capacity/Change-Review/Executive stay in-canvas modes.
      { id: "topology", label: "Topology", render: () => <TopologyCanvas /> },
      // Paths — how traffic actually traverses the network.
      { id: "flowtrace", label: "Flow Trace", group: "Paths", render: (c) => <NetworkPath rangeMinutes={c.rangeMinutes} /> },
      { id: "tunnels", label: "Tunnels", group: "Paths", render: () => <Tunnels /> },
      { id: "wan-paths", label: "WAN Paths", group: "Paths", render: () => <WanCircuits /> },
      { id: "troubleshooting", label: "Troubleshooting", render: (c) => <Troubleshooting rangeMinutes={c.rangeMinutes} /> },
    ],
  },
  // ── Infrastructure — what do I own / what is observed ───────────────────────
  {
    id: "infrastructure",
    label: "Infrastructure",
    icon: "infrastructure",
    children: [
      { id: "devices", label: "Devices", render: () => <Devices /> },
      // Port Intelligence workbench (#94) — fleet interfaces/ports/optics/DDM.
      { id: "interfaces", label: "Interfaces & Optics", render: () => <PortsWorkbench /> },
      // Sites — the promoted sites surface; the Device Geomap is folded in as
      // its Map tab (deep links: #/infrastructure/sites/{map|sites|locations}).
      { id: "sites", label: "Sites", render: () => <Sites />, subItems: [
        { id: "map", label: "Map" },
        { id: "sites", label: "Manage Sites" },
        { id: "locations", label: "Set Locations" },
      ] },
      // Wireless canonical inventory (#128): controllers, APs + radios, WLANs.
      // Wired + wireless are ONE LAN domain (owner ruling) — this is the
      // wireless VIEW of it, filled by controller connectors (Catalyst 9800).
      { id: "wireless", label: "Wireless", render: () => <Wireless /> },
      // Discovery & NMS — subnet discovery (platform-operated) + the NMS vendor-
      // controller integrations (#95, dormant unless FEATURE_NMS_INTEGRATIONS).
      { id: "discovery", label: "Discovery & NMS", render: () => <Discovery />, subItems: [
        { id: "discovery", label: "Subnet Discovery" },
        { id: "nms", label: "NMS Integrations" },
      ] },
      { id: "sot", label: "Source of Truth", platformOnly: true, render: () => <SourceOfTruth /> },
    ],
  },
  // ── Explore — the raw telemetry planes ──────────────────────────────────────
  {
    id: "explore",
    label: "Explore",
    icon: "datasets",
    children: [
      { id: "metrics", label: "Metrics", render: (c) => <MetricsExplorer rangeMinutes={c.rangeMinutes} /> },
      // Log Search + Cloud Logs in one leaf; #/explore/logs/cloud deep-links the
      // cloud plane (see pages/LogsExplore.tsx).
      { id: "logs", label: "Logs", render: (c) => <LogsExplore initialQuery={c.query} rangeMinutes={c.rangeMinutes} />, subItems: [
        { id: "cloud", label: "Cloud Logs" },
      ] },
      { id: "flows", label: "Flows", render: (c) => <Flows sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "events", label: "Events", render: (c) => <Events sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "saved", label: "Saved Searches", render: () => <SavedSearches /> },
    ],
  },
  // ── Security — the CTEM section (P3-T8) ─────────────────────────────────────
  // Scope → Discover → Prioritize → Validate → Mobilize, rendered as product.
  // The three pre-existing leaves keep their ids (legacy deep links resolve
  // unchanged): "threat" and "compliance" now open the EVOLVED views that carry
  // the old boards as a sub-view, and "vuln" is untouched.
  {
    id: "security",
    label: "Security",
    icon: "shield",
    children: [
      { id: "overview", label: "Security Overview", render: () => <SecurityOverview /> },
      { id: "exposures", label: "Exposures", render: () => <SecurityExposures /> },
      { id: "stories", label: "Exposure Stories", render: () => <SecurityExposureStories /> },
      { id: "vuln", label: "Vulnerabilities", render: () => <VulnerabilityManagement /> },
      {
        id: "threat", label: "Threat Detection",
        render: (c) => <SecurityThreatDetection sinceSeconds={c.rangeMinutes * 60} />,
        subItems: [
          { id: "detections", label: "Detections" },
          { id: "behavior", label: "Network Behavior" },
        ],
      },
      {
        id: "compliance", label: "Compliance", render: () => <SecurityCompliance />,
        subItems: [
          { id: "controls", label: "Control set" },
          { id: "drift", label: "Drift & baselines" },
        ],
      },
      { id: "rules", label: "Detection Rules", group: "Configuration", render: () => <SecurityRules /> },
      { id: "views", label: "Saved Views", group: "Configuration", render: () => <SecuritySavedViews /> },
    ],
  },
  // ── Analytics — boards, reports and management trend views ──────────────────
  {
    id: "analytics",
    label: "Analytics",
    icon: "analytics",
    children: [
      {
        id: "dashboards",
        label: "Dashboard List",
        group: "Dashboards",
        render: () => <DashboardList />,
        subItems: [
          { id: "device-metric", label: "Device Metrics", route: "analytics/device-monitoring" },
          { id: "interface-metric", label: "Interface Metrics", route: "analytics/interface-performance" },
          { id: "bgp-metric", label: "BGP Metrics", route: "analytics/protocols" },
          { id: "bandwidth", label: "Bandwidth Utilization", route: "analytics/device-monitoring" },
          { id: "wan-circuit", label: "WAN Interface Metrics", route: "investigate/wan-paths" },
        ],
      },
      // Marketing demo board: same live panel registry, flashier chrome. Style
      // over depth, on purpose — kept as a sales surface.
      { id: "demo", label: "Demo Showcase", group: "Dashboards", render: () => <DemoShowcase /> },
      // The device-monitoring board suite (docs/design/device-monitoring-dashboards.md).
      { id: "device-monitoring", label: "Device Monitoring", group: "Metric Dashboards", render: (c) => <DeviceMonitoring rangeMinutes={c.rangeMinutes} /> },
      { id: "interface-performance", label: "Interface Performance", group: "Metric Dashboards", render: (c) => <InterfacePerformance rangeMinutes={c.rangeMinutes} /> },
      { id: "protocols", label: "Protocol Monitoring", group: "Metric Dashboards", render: (c) => <BgpOspf rangeMinutes={c.rangeMinutes} /> },
      // Item 10 (2026-08-25): the consolidated BGP outage screen — routing
      // status, RPKI, AS-paths, churn, RDAP ownership in one place.
      { id: "bgp-ops", label: "BGP Operations", group: "Metric Dashboards", render: () => <BgpOps /> },
      { id: "reports", label: "Reports", render: () => <Reports /> },
      // #113: the management library — ONLY promoted real outages + documents.
      { id: "rca-reports", label: "RCA Reports", render: () => <RcaReports /> },
      { id: "scorecard", label: "Recovery Scorecard", render: () => <ReliabilityScorecard /> },
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
      // Incident Response plumbing — configuration, not operations (the old
      // Incident Response rail section dissolved into here).
      { id: "integrations", label: "Integrations", group: "Incident Response", render: () => <IntegrationsAdmin /> },
      { id: "notifications", label: "Notifications", group: "Incident Response", render: () => <NotificationsAdmin /> },
      { id: "ticketing", label: "Ticketing & Automation", group: "Incident Response", render: () => <IncidentPoliciesAdmin /> },
      // Data Collection — the sources + the poller plumbing that feed telemetry.
      // Data Collection order (owner, 2026-08-25): discovery pair first
      // (SNMP profiles beside the Sensors/subnet-discovery controls), then the
      // shaping/handling pair (Processors beside Sensitive Data Access).
      { id: "datasources", label: "Data Sources", group: "Data Collection", render: () => <DataSources /> },
      { id: "snmp", label: "SNMP Profiles", group: "Data Collection", render: () => <SnmpProfileManager /> },
      // The collector/poller controls ("Sensors" in the owner tree) — platform
      // plumbing; its subnet-discovery card also surfaces under
      // Infrastructure → Discovery & NMS for the same platform principals.
      { id: "sensors", label: "Sensors", group: "Data Collection", platformOnly: true, render: () => <Collectors /> },
      // Item 121: per-tenant processor editor (redact/drop/set shaping compiled
      // into the ingest router). Admin-gated server-side.
      { id: "processors", label: "Processors", group: "Data Collection", render: () => <ProcessorsAdmin /> },
      // Sealed Fields (#129): who revealed protected data, when, and why.
      // Server-gated on sensitive_data:admin.
      { id: "sensitive-data-access", label: "Sensitive Data Access", group: "Data Collection", render: () => <SensitiveDataAccess /> },
      // Identity & Access — consolidates Users · Roles · Security Settings.
      // Sub-items deep-link its internal views via the #/admin/identity/<sub>
      // suffix (read by IdentityAccess, same mechanism as admin/api).
      { id: "identity", label: "Identity & Access", render: () => <IdentityAccess /> },
      // Platform Security — authentication providers, access reasoning, live
      // sessions, the audit trail and the TLS posture inventory.
      // Authentication providers (OIDC/LDAP/TACACS) are platform-GLOBAL config:
      // every endpoint behind this page is requirePlatformAdmin-gated, so for a
      // tenant admin the leaf is only dead "Loading…" tiles and 403'd saves.
      { id: "auth", label: "Authentication", group: "Platform Security", platformOnly: true, render: () => <AuthenticationAdmin /> },
      { id: "access", label: "Access Explorer", group: "Platform Security", render: () => <AccessExplorer /> },
      { id: "sessions", label: "Sessions", group: "Platform Security", platformOnly: true, render: () => <SessionsAdmin /> },
      { id: "audit", label: "Audit Log", group: "Platform Security", render: () => <AuditLog /> },
      // SEC-021.1: read-only TLS posture inventory. NOT platformOnly — tenant
      // admins get their scoped device-lane view; the backend enforces scope.
      { id: "transport", label: "Transport Security", group: "Platform Security", render: () => <TransportSecurity /> },
      // Platform — the platform's OWN infra plumbing + raw-backend tools.
      // Platform-owner only, leaf-stamped; the backend enforces it independently
      // (/api/stack/health 403, nginx auth_request on /search, etc.).
      { id: "regions", label: "Regions", group: "Platform", platformOnly: true, render: () => <RegionsAdmin /> },
      { id: "health", label: "Stack Health", group: "Platform", platformOnly: true, render: () => <StackHealth /> },
      { id: "grafana", label: "Self-Monitoring", group: "Platform", platformOnly: true, requiresGrafana: true, render: () => <GrafanaTab /> },
      { id: "opensearch", label: "OpenSearch", group: "Platform", platformOnly: true, render: () => <SearchDashboardsTab /> },
      { id: "graphql", label: "GraphQL Explorer", group: "Platform", platformOnly: true, render: () => <GraphQLExplorer /> },
      {
        id: "api", label: "API Access", render: () => <ApiAccessAdmin />,
        subItems: [
          { id: "keys", label: "Generate API key" },
          { id: "token", label: "Token Policy" },
          { id: "rest", label: "REST API Reference" },
        ],
      },
      { id: "settings", label: "Settings", render: () => <Settings /> },
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

// ── Legacy route aliases (2026-08 nav redesign) ──────────────────────────────
// The pre-redesign IA (Dashboards · Monitoring · Incident Response · Automation
// · Metrics/Flows/Logs · the admin collector pages) was re-mapped onto the
// owner's 2026-08 tree. EVERY old hash — bookmarks, saved landings, panel
// drills, the panels.tsx ghost routes, and the 2026-07-10 Explain/Stack
// legacies — must keep resolving to the moved page instead of silently falling
// back to Home. Two tables, applied by aliasSegs in this order:
//
//  1. LEGACY_ROUTE_ALIAS, exact "section/leaf" key (also bare-section /
//     one-segment ghost keys) → the new route, which may carry its own
//     sub-item suffix (e.g. logs/cloud → explore/logs/cloud). Any further
//     original segments are appended, so in-page suffixes survive
//     (monitoring/appobs/investigations → operations/services/investigations).
//  2. LEGACY_SECTION_ALIAS, leaf-preserving section renames for leaves not in
//     table 1 (stack/graphql → admin/graphql; leaf ids were preserved there).
const LEGACY_ROUTE_ALIAS: Record<string, string> = {
  // Dashboards section → Overview / Analytics
  "dashboards": "overview/home",
  "dashboards/home": "overview/home",
  "dashboards/operations": "overview/operations",
  "dashboards/board": "overview/board",
  "dashboards/demo": "analytics/demo",
  "dashboards/list": "analytics/dashboards",
  "dashboards/reports": "analytics/reports",
  // Monitoring section → Operations / Investigate / Explore / Analytics
  "monitoring/monitors": "operations/rules",
  "monitoring/new": "operations/new",
  "monitoring/triggered": "operations/alerts",
  "monitoring/maintenance": "operations/maintenance",
  "monitoring/quality": "operations/network-health",
  "monitoring/events": "explore/events",
  "monitoring/incidents": "operations/incidents",
  "monitoring/anomalies": "investigate/findings",
  "monitoring/correlations": "investigate/rca",
  "monitoring/rca-reports": "analytics/rca-reports",
  "monitoring/appobs": "operations/services",
  "monitoring/reliability": "analytics/scorecard",
  // Incident Response section → Overview / Administration
  "incident": "overview/home",
  "incident/overview": "overview/home",
  "incident/notifications": "admin/notifications",
  "incident/integrations": "admin/integrations",
  "incident/rca-ticketing": "admin/ticketing",
  // Automation section (one leaf) → Infrastructure
  "automation": "infrastructure/sot",
  "automation/sot": "infrastructure/sot",
  // Infrastructure leaves that moved out or were renamed
  "infrastructure/ports": "infrastructure/interfaces",
  "infrastructure/nms": "infrastructure/discovery/nms",
  "infrastructure/monitoring": "analytics/device-monitoring",
  "infrastructure/ifperf": "analytics/interface-performance",
  "infrastructure/bgpospf": "analytics/protocols",
  "infrastructure/troubleshooting": "investigate/troubleshooting",
  "infrastructure/topology-canvas": "investigate/topology",
  // Topology's pre-move home (also an old FrontPage drill target). Without the
  // alias it silently resolved to Infrastructure's first leaf — Devices.
  "infrastructure/topology": "investigate/topology",
  "infrastructure/geomap": "infrastructure/sites/map",
  "infrastructure/flowtrace": "investigate/flowtrace",
  "infrastructure/wan-circuits": "investigate/wan-paths",
  "infrastructure/tunnels": "investigate/tunnels",
  // The old top-level data-plane sections → Explore
  "metrics": "explore/metrics",
  "flows": "explore/flows",
  "logs": "explore/logs",
  "logs/logs": "explore/logs",
  "logs/cloud": "explore/logs/cloud",
  "logs/saved": "explore/saved",
  // Admin renames (collectors → sensors; everything else kept its id)
  "admin/collectors": "admin/sensors",
  // Explain + Stack rail sections dissolved into Administration (2026-07-10);
  // bare hashes land on their old first page.
  "explain": "admin/access",
  "stack": "admin/health",
  // panels.tsx ghost drill routes (never existed as sections — they silently
  // fell back to Home before the redesign; now they land where they meant to)
  "alerts/active": "operations/alerts",
  "alerts/incidents": "operations/incidents",
  "topology/map": "infrastructure/sites/map",
  "topology/tunnels": "investigate/tunnels",
  "topology-canvas": "investigate/topology",
};
// Leaf-preserving section renames (leaf ids kept in the move). Applied only
// when table 1 has no exact entry.
const LEGACY_SECTION_ALIAS: Record<string, string> = {
  explain: "admin",
  stack: "admin",
  dashboards: "overview",
  monitoring: "operations",
  incident: "overview",
  automation: "infrastructure",
  logs: "explore",
  alerts: "operations",
  topology: "investigate",
};

// aliasSegs maps a legacy path (split on "/") to its canonical segments, or
// null when the path is already canonical (or unknown — resolveRoute then
// applies its usual first-section/first-leaf fallback).
function aliasSegs(segs: string[]): string[] | null {
  const key = segs.length >= 2 ? `${segs[0]}/${segs[1]}` : segs[0];
  const exact = LEGACY_ROUTE_ALIAS[key];
  if (exact) return [...exact.split("/"), ...segs.slice(2)];
  const section = LEGACY_SECTION_ALIAS[segs[0]];
  if (section) return [section, ...segs.slice(1)];
  const bare = LEGACY_ROUTE_ALIAS[segs[0]];
  if (bare) return [...bare.split("/"), ...segs.slice(1)];
  return null;
}

// canonicalHash rewrites a legacy hash to its canonical form, PRESERVING any
// sub-item suffix and ?query (deep-link params). Returns null when the hash is
// already canonical. App.tsx applies this via history.replaceState so pages
// that read their tab from the third hash segment always see canonical routes.
// #/resource/... is a first-class route and is never rewritten.
export function canonicalHash(hash: string): string | null {
  const raw = hash.replace(/^#\/?/, "");
  const qi = raw.indexOf("?");
  const path = qi >= 0 ? raw.slice(0, qi) : raw;
  const query = qi >= 0 ? raw.slice(qi) : "";
  if (!path || path.split("/")[0] === "resource") return null;
  const next = aliasSegs(path.split("/"));
  if (!next) return null;
  return `#/${next.join("/")}${query}`;
}

// Parse "#/section/leaf" into the section + active leaf, with fallbacks. The nav
// defaults to the full tree; pass a filtered tree to keep hidden routes
// unreachable via the hash (they fall back to the first visible entry).
function canonicalPath(hash: string): [string, string | undefined] {
  const path = hash.replace(/^#\/?/, "").split("?")[0]; // drop ?query (deep-link params)
  const segs = path.split("/");
  const aliased = aliasSegs(segs) ?? segs;
  return [aliased[0], aliased[1]];
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
  // Compare against the CANONICAL path so a landing saved before the redesign
  // keeps validating (it resolves to the moved leaf).
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
