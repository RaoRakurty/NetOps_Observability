import { useEffect, useMemo, useRef, useState } from "react";
import { api, Health } from "./services/api";
import { useAuth } from "./hooks/useAuth";
import { ShellContext, ShellState, TimeRange, SectionCtx } from "./context/shell";
import { rangeForSection, rememberSectionRange } from "./theme/timeprefs";
import { resolveRoute, filteredNav } from "./nav";
import TopBar from "./components/TopBar";
import Sidebar from "./components/Sidebar";
import SubNav from "./components/SubNav";
import CopilotDrawer from "./components/CopilotDrawer";
import CommandPalette from "./components/CommandPalette";
import Login from "./pages/Login";

export default function App() {
  const { user, loading, refresh, logout } = useAuth();
  const [health, setHealth] = useState<Health | null>(null);

  // The nav tree is gated to the principal: tenant-scoped users don't see the
  // platform's own infra-stack monitoring (Stack Health + raw backends). The
  // backend enforces the same boundary independently.
  const platformAdmin = !!user?.platform_admin;
  const nav = useMemo(() => filteredNav(platformAdmin), [platformAdmin]);

  // Shell state — the single source of truth that unifies the sections.
  const [hash, setHash] = useState<string>(() => location.hash || "#/overview");
  // Per-section time-range memory: each section restores the range it was last
  // viewed with (theme/timeprefs.ts). setRange persists under the active section.
  const sectionId = useMemo(() => resolveRoute(hash, nav).section.id, [hash, nav]);
  const sectionRef = useRef(sectionId);
  const [range, setRangeState] = useState<TimeRange>(() => rangeForSection(sectionId));
  const setRange = (r: TimeRange) => {
    rememberSectionRange(sectionRef.current, r.minutes);
    setRangeState(r);
  };
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

  // When the active section changes, restore that section's remembered range.
  useEffect(() => {
    if (sectionRef.current !== sectionId) {
      sectionRef.current = sectionId;
      setRangeState(rangeForSection(sectionId));
    }
  }, [sectionId]);

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

  const { section, leaf } = resolveRoute(hash, nav);
  const ctx: SectionCtx = { rangeMinutes: range.minutes, query };
  const view = leaf ? leaf.render(ctx) : section.render ? section.render(ctx) : null;

  return (
    <ShellContext.Provider value={shell}>
      <div className={`shell${collapsed ? " collapsed" : ""}`}>
        <TopBar health={health} user={user} onLogout={logout} />
        <Sidebar
          nav={nav}
          activeSection={section.id}
          activeLeaf={leaf?.id}
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
        />
        <main className="main">
          <div className="main-head">
            <div className="crumbs">
              <span className="crumb-section">{section.label}</span>
              {leaf && leaf.label !== section.label && <span className="crumb-sep">/</span>}
              {leaf && leaf.label !== section.label && <span className="crumb-leaf">{leaf.label}</span>}
            </div>
            <SubNav section={section} activeLeaf={leaf?.id} />
          </div>
          <div className="page">{view}</div>
        </main>
        <CopilotDrawer />
        <CommandPalette nav={nav} />
      </div>
    </ShellContext.Provider>
  );
}
