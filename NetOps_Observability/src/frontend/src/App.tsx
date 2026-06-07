import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api, Health } from "./services/api";
import { useAuth } from "./hooks/useAuth";
import { ShellContext, ShellState, TimeRange, SectionCtx } from "./context/shell";
import { rangeForSection, rememberSectionRange } from "./theme/timeprefs";
import { resolveRoute, filteredNav } from "./nav";
import TopBar from "./components/TopBar";
import Sidebar from "./components/Sidebar";
import IconRail from "./components/IconRail";
import SubNav from "./components/SubNav";
import CopilotDrawer from "./components/CopilotDrawer";
import CommandPalette from "./components/CommandPalette";
import Inspector from "./components/Inspector";
import BottomDrawer from "./components/BottomDrawer";
import { WorkspaceProvider, useWorkspace } from "./context/workspace";
import Login from "./pages/Login";
import { Modal } from "./components/ui";
import ChangePasswordCard from "./components/ChangePasswordCard";

// ShellGridSizing mirrors the live pane sizes into the shell grid's track vars
// (--ins-w / --drawer-h) so the docked Inspector/BottomDrawer reflow the center
// workspace instead of overlaying it. Runs inside the provider; 0px collapses
// the track when a pane is closed. useLayoutEffect = applied before paint.
function ShellGridSizing() {
  const ws = useWorkspace();
  useLayoutEffect(() => {
    const el = document.querySelector(".shell.shell-v2") as HTMLElement | null;
    if (!el) return;
    el.style.setProperty("--ins-w", ws.inspector ? `${ws.inspectorWidth}px` : "0px");
    el.style.setProperty("--drawer-h", ws.drawer ? `${ws.drawerHeight}px` : "0px");
  }, [ws.inspector, ws.inspectorWidth, ws.drawer, ws.drawerHeight]);
  return null;
}

export default function App() {
  const { user, loading, refresh, logout } = useAuth();
  const [health, setHealth] = useState<Health | null>(null);
  // Self-service change-password modal, reachable from either account menu while
  // signed in (TopBar in v1, IconRail foot in v2) — local accounts only; federated
  // users change it at their IdP. Works for global and tenant-scoped users alike.
  const [pwOpen, setPwOpen] = useState(false);
  const localAccount = !user?.auth_source || user.auth_source === "local";
  const onChangePassword = localAccount ? () => setPwOpen(true) : undefined;

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

  // Shell-v2 (#24): the new slim icon-rail + hover-flyout nav, behind a flag so
  // the current shell stays the default. `?shell=v2` enables it and is sticky;
  // `?shell=v1` turns it back off — the runtime rollback.
  const shellV2 = useMemo(() => {
    try {
      const q = new URLSearchParams(location.search).get("shell");
      if (q === "v2") {
        localStorage.setItem("shellV2", "1");
        return true;
      }
      if (q === "v1") {
        localStorage.removeItem("shellV2");
        return false;
      }
      return localStorage.getItem("shellV2") === "1";
    } catch {
      return false;
    }
  }, []);

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
     <WorkspaceProvider enabled={shellV2}>
      <div className={`shell${collapsed ? " collapsed" : ""}${shellV2 ? " shell-v2" : ""}`}>
        <ShellGridSizing />
        <TopBar health={health} user={user} onLogout={logout} onChangePassword={onChangePassword} hideUserMenu={shellV2} />
        {shellV2 ? (
          <IconRail nav={nav} activeSection={section.id} activeLeaf={leaf?.id} user={user} onLogout={logout} onChangePassword={onChangePassword} />
        ) : (
          <Sidebar
            nav={nav}
            activeSection={section.id}
            activeLeaf={leaf?.id}
            collapsed={collapsed}
            onToggle={() => setCollapsed((c) => !c)}
          />
        )}
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
        <Inspector />
        <BottomDrawer />
        {pwOpen && (
          <Modal title="Change password" subtitle={user.username} onClose={() => setPwOpen(false)}>
            <ChangePasswordCard fixedUsername={user.username} onDone={() => setPwOpen(false)} />
          </Modal>
        )}
      </div>
     </WorkspaceProvider>
    </ShellContext.Provider>
  );
}
