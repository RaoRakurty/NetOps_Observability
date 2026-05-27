import { useEffect, useState } from "react";
import { api, Health } from "./services/api";
import { useAuth } from "./hooks/useAuth";
import Header from "./components/Header";
import TabNavigation, { Tab } from "./components/TabNavigation";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
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
import Copilot from "./tabs/Copilot";
import Settings from "./tabs/Settings";

const TABS: Tab[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "devices", label: "Devices" },
  { id: "topology", label: "Topology" },
  { id: "collectors", label: "Collectors" },
  { id: "alerts", label: "Alerts" },
  { id: "rules", label: "Rules" },
  { id: "findings", label: "Findings" },
  { id: "logs", label: "Logs" },
  { id: "flows", label: "Flows" },
  { id: "copilot", label: "Copilot" },
  { id: "prometheus", label: "Prometheus" },
  { id: "grafana", label: "Grafana" },
  { id: "search", label: "OS Dashboards" },
  { id: "settings", label: "Settings" },
];

export default function App() {
  const { user, loading, refresh, logout } = useAuth();
  const [tab, setTab] = useState<string>(() => location.hash.replace("#", "") || "dashboard");
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    const onHash = () => setTab(location.hash.replace("#", "") || "dashboard");
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!user) return;
    let alive = true;
    const tick = async () => {
      try {
        const h = await api.health();
        if (alive) setHealth(h);
      } catch {
        if (alive) setHealth(null);
      }
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [user]);

  const select = (id: string) => {
    location.hash = id;
    setTab(id);
  };

  if (loading) {
    return <div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>;
  }
  if (!user) {
    return <Login onLoggedIn={refresh} />;
  }

  return (
    <div className="app">
      <Header health={health} user={user} onLogout={logout} />
      <TabNavigation tabs={TABS} active={tab} onSelect={select} />
      <div className="content">
        {tab === "dashboard" && <Dashboard />}
        {tab === "devices" && <Devices />}
        {tab === "topology" && <Topology />}
        {tab === "collectors" && <Collectors />}
        {tab === "alerts" && <Alerts />}
        {tab === "rules" && <Rules />}
        {tab === "findings" && <Findings />}
        {tab === "logs" && <Logs />}
        {tab === "flows" && <Flows />}
        {tab === "copilot" && <Copilot />}
        {tab === "prometheus" && <PrometheusTab />}
        {tab === "grafana" && <GrafanaTab />}
        {tab === "search" && <SearchDashboardsTab />}
        {tab === "settings" && <Settings />}
      </div>
    </div>
  );
}
