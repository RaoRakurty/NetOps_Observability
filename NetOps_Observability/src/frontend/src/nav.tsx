import { SectionCtx } from "./context/shell";

// Pages / tabs (existing components, reparented into product sections).
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Reports from "./pages/Reports";
import SavedDashboards from "./pages/SavedDashboards";
import Topology from "./tabs/Topology";
import Collectors from "./tabs/Collectors";
import Alerts from "./tabs/Alerts";
import Rules from "./tabs/Rules";
import Findings from "./tabs/Findings";
import Logs from "./tabs/Logs";
import Flows from "./tabs/Flows";
import PrometheusTab from "./tabs/Prometheus";
import GrafanaTab from "./tabs/Grafana";
import SearchDashboardsTab from "./tabs/SearchDashboards";
import Settings from "./tabs/Settings";

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

// The information architecture. Order here is the sidebar order.
export const NAV: NavSection[] = [
  {
    id: "overview",
    label: "Overview",
    icon: "overview",
    render: () => <Dashboard />,
  },
  {
    id: "search",
    label: "Search",
    icon: "search",
    children: [
      { id: "logs", label: "Search", render: (c) => <Logs initialQuery={c.query} rangeMinutes={c.rangeMinutes} /> },
      { id: "advanced", label: "Advanced (OSD)", render: () => <SearchDashboardsTab /> },
    ],
  },
  {
    id: "analytics",
    label: "Analytics",
    icon: "analytics",
    children: [
      { id: "flows", label: "Flows", render: (c) => <Flows sinceSeconds={c.rangeMinutes * 60} /> },
      { id: "metrics", label: "Metrics", render: () => <PrometheusTab /> },
    ],
  },
  {
    id: "datasets",
    label: "Datasets",
    icon: "datasets",
    children: [
      { id: "devices", label: "Devices", render: () => <Devices /> },
      { id: "collectors", label: "Collectors", render: () => <Collectors /> },
    ],
  },
  {
    id: "dashboards",
    label: "Dashboards",
    icon: "dashboards",
    children: [
      { id: "saved", label: "Saved", render: () => <SavedDashboards /> },
      { id: "grafana", label: "Grafana", render: () => <GrafanaTab /> },
    ],
  },
  {
    id: "alerts",
    label: "Alerts",
    icon: "alerts",
    children: [
      { id: "triggered", label: "Triggered", render: () => <Alerts /> },
      { id: "rules", label: "Rules", render: () => <Rules /> },
      { id: "incidents", label: "Incidents", render: () => <Findings /> },
    ],
  },
  {
    id: "reports",
    label: "Reports",
    icon: "reports",
    render: () => <Reports />,
  },
  {
    id: "topology",
    label: "Topology",
    icon: "topology",
    render: () => <Topology />,
  },
  {
    id: "copilot",
    label: "Copilot",
    icon: "copilot",
    action: "copilot",
    footer: true,
  },
  {
    id: "settings",
    label: "Settings",
    icon: "settings",
    render: () => <Settings />,
    footer: true,
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
