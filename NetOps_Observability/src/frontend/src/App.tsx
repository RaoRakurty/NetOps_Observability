import { useEffect, useMemo, useState } from "react";
import { api, Health } from "./services/api";
import { useAuth } from "./hooks/useAuth";
import { ShellContext, ShellState, TimeRange, TIME_RANGES, SectionCtx } from "./context/shell";
import { resolveRoute } from "./nav";
import TopBar from "./components/TopBar";
import Sidebar from "./components/Sidebar";
import SubNav from "./components/SubNav";
import CopilotDrawer from "./components/CopilotDrawer";
import Login from "./pages/Login";

export default function App() {
  const { user, loading, refresh, logout } = useAuth();
  const [health, setHealth] = useState<Health | null>(null);

  // Shell state — the single source of truth that unifies the sections.
  const [hash, setHash] = useState<string>(() => location.hash || "#/overview");
  const [range, setRange] = useState<TimeRange>(TIME_RANGES[1]); // Last 1 hour
  const [query, setQuery] = useState<string>("*");
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const onHash = () => setHash(location.hash || "#/overview");
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Poll backend health for the top-bar indicator.
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

  const navigate = (route: string) => {
    location.hash = `#/${route.replace(/^#?\/?/, "")}`;
  };

  const shell: ShellState = useMemo(
    () => ({ range, setRange, query, setQuery, copilotOpen, setCopilotOpen, navigate }),
    [range, query, copilotOpen],
  );

  if (loading) {
    return <div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>;
  }
  if (!user) {
    return <Login onLoggedIn={refresh} />;
  }

  const { section, leaf } = resolveRoute(hash);
  const ctx: SectionCtx = { rangeMinutes: range.minutes, query };
  const view = leaf ? leaf.render(ctx) : section.render ? section.render(ctx) : null;

  return (
    <ShellContext.Provider value={shell}>
      <div className={`shell${collapsed ? " collapsed" : ""}`}>
        <TopBar health={health} user={user} onLogout={logout} />
        <Sidebar
          activeSection={section.id}
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
        />
        <main className="main">
          <div className="main-head">
            <div className="crumbs">
              <span className="crumb-section">{section.label}</span>
              {leaf && <span className="crumb-sep">/</span>}
              {leaf && <span className="crumb-leaf">{leaf.label}</span>}
            </div>
            <SubNav section={section} activeLeaf={leaf?.id} />
          </div>
          <div className="page">{view}</div>
        </main>
        <CopilotDrawer />
      </div>
    </ShellContext.Provider>
  );
}
