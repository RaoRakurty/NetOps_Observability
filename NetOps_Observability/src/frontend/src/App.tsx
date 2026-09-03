import { ReactNode, Suspense, startTransition, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api, Health, LANDING_PENDING_KEY } from "./services/api";
import { useAuth } from "./hooks/useAuth";
import { ShellContext, ShellState, TimeRange, SectionCtx } from "./context/shell";
import { rangeForSection, rememberSectionRange } from "./theme/timeprefs";
import { useTzMode, setTzMode } from "./lib/time";
import { lazy } from "react";
import { resolveRoute, resolveResourceRoute, filteredNav, landingResolves, routeFor, canonicalHash, ROUTE_CHUNKS } from "./nav";
// Route-level page like the nav leaves (#/resource/{kind}/{id}) — lazy for the
// same reason: it pulls the appobs metric panels (ECharts) into its own chunk.
// It renders inside the same <Suspense> boundary as the nav pages below.
const ResourceDetail = lazy(() => import("./pages/ResourceDetail"));
import TopBar from "./components/TopBar";
import Sidebar from "./components/Sidebar";
import IconRail from "./components/IconRail";
import SubNav from "./components/SubNav";
import ScopeBadge from "./components/ScopeBadge";
import OpsisDrawer from "./components/OpsisDrawer";
import HelpDrawer from "./components/HelpDrawer";
import CommandPalette from "./components/CommandPalette";
import Inspector from "./components/Inspector";
import BottomDrawer from "./components/BottomDrawer";
import { WorkspaceProvider, useWorkspace } from "./context/workspace";
import Login from "./pages/Login";
import { Modal } from "./components/ui";
import ChangePasswordCard from "./components/ChangePasswordCard";
import TenantGate from "./components/TenantGate";
import ErrorBoundary from "./components/ErrorBoundary";

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

// RouteView renders the active route by calling the nav leaf's render thunk
// from INSIDE the shell error boundary. Module scope (not a closure in App) so
// its identity is stable and the page below it is never remounted by a shell
// re-render.
function RouteView({ build }: { build: () => ReactNode }) {
  return <>{build()}</>;
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
  const grafanaEnabled = user?.grafana_enabled !== false; // absent (old api) = show
  const nav = useMemo(() => filteredNav(platformAdmin, grafanaEnabled), [platformAdmin, grafanaEnabled]);
  // The brand/Home button goes to the configured landing (if it resolves for this
  // principal), else the first nav section — so Home matches "where I start".
  const homeRoute = useMemo(() => {
    const want = user?.default_landing;
    return want && landingResolves(want, nav) ? want : routeFor(nav[0]);
  }, [user, nav]);

  // Shell state — the single source of truth that unifies the sections.
  // Legacy hashes (pre-2026-08 IA + the Explain/Stack legacies) are rewritten
  // to their canonical route BEFORE first paint via history.replaceState (no
  // hashchange fires), so pages that read their tab from the third hash
  // segment only ever see canonical routes — and the address bar shows the
  // route worth bookmarking.
  const [hash, setHash] = useState<string>(() => {
    const h = location.hash || "#/overview/home";
    const canon = canonicalHash(h);
    if (canon) {
      try {
        history.replaceState(null, "", canon);
      } catch {
        /* sandboxed history: resolveRoute still aliases the legacy hash */
      }
      return canon;
    }
    return h;
  });
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
  const [helpOpen, setHelpOpen] = useState(false);
  const [helpPath, setHelpPath] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  // Global time-display mode (Local/UTC — a per-TENANT setting under
  // Administration → Settings). Keying the page on it remounts the active view
  // so every rendered timestamp — including plain (non-hook) render helpers —
  // switches zone immediately.
  const tz = useTzMode();
  // The tenant preference is server-truth: apply it on sign-in (localStorage
  // is only the pre-fetch paint). A failed read keeps the cached mode.
  useEffect(() => {
    if (!user) return;
    api.getDisplaySettings().then((r) => setTzMode(r.time_display === "utc" ? "utc" : "local"), () => {});
  }, [user]);

  // Shell-v2 (#24): the slim icon-rail + hover-flyout nav, navy header band, and
  // compact cockpit type — now the DEFAULT. `?shell=v1` is a sticky opt-OUT
  // (the runtime rollback); `?shell=v2` re-opts-in. Absent any choice, v2.
  const shellV2 = useMemo(() => {
    try {
      const q = new URLSearchParams(location.search).get("shell");
      if (q === "v2") {
        localStorage.setItem("shellV2", "1");
        return true;
      }
      if (q === "v1") {
        localStorage.setItem("shellV2", "0"); // sticky opt-out, survives reloads
        return false;
      }
      return localStorage.getItem("shellV2") !== "0"; // default ON unless opted out
    } catch {
      return true;
    }
  }, []);

  useEffect(() => {
    const onHash = () => {
      const h = location.hash || "#/overview/home";
      const canon = canonicalHash(h);
      if (canon) {
        try {
          history.replaceState(null, "", canon);
        } catch {
          /* resolveRoute still aliases the legacy hash */
        }
      }
      // Perf wave 2026-08-25: route switches are React TRANSITIONS. The
      // outgoing page stays on screen while the incoming lazy chunk loads,
      // so navigation never blanks to the Suspense fallback mid-click —
      // the fallback is reserved for cold first paint.
      startTransition(() => setHash(canon ?? h));
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Administratively-configured default landing (Increment 2). Applied ONCE per load,
  // when the session is a FRESH LOGIN or the app was entered at the root/home — NOT
  // when reloading or deep-linking a specific page (those keep their page). Only
  // applied if the configured route resolves to a real leaf in THIS principal's nav;
  // a stale/forbidden route is ignored (keeps the built-in home).
  const initialHash = useRef(location.hash);
  const appliedLanding = useRef(false);
  useEffect(() => {
    if (appliedLanding.current || loading || !user) return;
    appliedLanding.current = true;
    const want = user.default_landing;
    if (!want || !landingResolves(want, nav)) {
      sessionStorage.removeItem(LANDING_PENDING_KEY);
      return;
    }
    const freshLogin = sessionStorage.getItem(LANDING_PENDING_KEY) === "1";
    const h = initialHash.current;
    // "#/dashboards/home" was the pre-redesign default route — old bookmarks of
    // it still count as "entered at home".
    const enteredAtHome = h === "" || h === "#/" || h === "#/overview/home" || h === "#/dashboards/home";
    if ((freshLogin || enteredAtHome) && want !== location.hash) {
      location.hash = want; // fires hashchange → setHash
    }
    sessionStorage.removeItem(LANDING_PENDING_KEY);
  }, [user, loading, nav]);

  // Idle warm-up of every route chunk (perf wave 2026-08-25). This is an
  // on-prem NOC console on a LAN: after first paint settles, fetching the
  // remaining page chunks one at a time makes every later click render from
  // cache — the "slick even at high EPS" requirement is mostly this. One
  // chunk in flight at a time (never competes with real traffic bursts),
  // starts 3.5s after mount, honors Save-Data, and any failure is silently
  // skipped (the route still lazy-loads on demand exactly as before).
  useEffect(() => {
    type NetInfo = { saveData?: boolean };
    const conn = (navigator as unknown as { connection?: NetInfo }).connection;
    if (conn?.saveData) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      const thunks = Object.values(ROUTE_CHUNKS);
      let i = 0;
      const next = () => {
        if (cancelled || i >= thunks.length) return;
        thunks[i++]().catch(() => undefined).then(() => {
          if (cancelled) return;
          const ric = (window as unknown as { requestIdleCallback?: (cb: () => void) => number }).requestIdleCallback;
          if (ric) ric(next); else setTimeout(next, 250);
        });
      };
      next();
    }, 3500);
    return () => { cancelled = true; clearTimeout(timer); };
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

  // Open the Help drawer, optionally deep-linked at a docs page ("" = home).
  const openHelp = (path?: string) => {
    setHelpPath(path || "");
    setHelpOpen(true);
  };

  const shell: ShellState = useMemo(
    () => ({ range, setRange, query, setQuery, copilotOpen, setCopilotOpen, helpOpen, setHelpOpen, helpPath, openHelp, navigate }),
    [range, query, copilotOpen, helpOpen, helpPath],
  );

  if (loading) {
    return <div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>;
  }
  if (!user) {
    return <Login onLoggedIn={refresh} />;
  }

  const { section, leaf } = resolveRoute(hash, nav);
  const ctx: SectionCtx = { rangeMinutes: range.minutes, query };
  // Permanent resource URLs (#/resource/{kind}/{id}, Wave 6 #20) live OUTSIDE
  // the section/leaf nav tree — matched first, rendered as a full page in the
  // same shell. The id stays canonical/opaque; the page itself answers 404.
  const resourceRoute = resolveResourceRoute(hash);
  // Full-bleed canvas page (Investigate → Topology): the map claims the whole
  // viewport (owner: "topology canvas should be 100"), so under shell-v2 the
  // breadcrumb/tab strip is CSS-hidden for this leaf only (.main-bleed) — its
  // ~44px would shrink the canvas and zoom the fitted network out. Section
  // siblings stay reachable via the rail flyout there.
  const pageBleed = !resourceRoute && section.id === "investigate" && leaf?.id === "topology";
  // The two facts the shell's error boundary needs to name a failure honestly:
  // what the operator calls this view, and the route it lives at. `routeKey` is
  // also the boundary's reset key — navigating away from a view that threw
  // clears the fallback with no operator action (see components/ErrorBoundary).
  const viewLabel = resourceRoute ? "This resource" : leaf?.label ?? section.label;
  const routeKey = resourceRoute
    ? `resource:${resourceRoute.kind}:${resourceRoute.id}`
    : `${section.id}/${leaf?.id ?? ""}`;
  // The leaf's render thunk is EVALUATED INSIDE the boundary (see RouteView),
  // not here: a thunk that throws while building its element would otherwise
  // throw in App's own render, above the boundary, and blank the console —
  // exactly the failure the boundary exists to stop.
  const buildView = (): ReactNode =>
    resourceRoute ? (
      <ResourceDetail key={`${resourceRoute.kind}:${resourceRoute.id}`} kind={resourceRoute.kind} id={resourceRoute.id} />
    ) : leaf ? (
      leaf.render(ctx)
    ) : section.render ? (
      section.render(ctx)
    ) : null;

  return (
    <ShellContext.Provider value={shell}>
     <WorkspaceProvider enabled={shellV2}>
      <div className={`shell${collapsed ? " collapsed" : ""}${shellV2 ? " shell-v2" : ""}`}>
        {/* Skip link (WCAG 2.4.1). Routing owns location.hash, so an href jump
            would navigate — focus the main region programmatically instead. */}
        <a
          className="skip-link"
          href="#main-content"
          onClick={(e) => {
            e.preventDefault();
            document.getElementById("main-content")?.focus();
          }}
        >
          Skip to main content
        </a>
        <ShellGridSizing />
        <TopBar health={health} user={user} onLogout={logout} onChangePassword={onChangePassword} hideUserMenu={shellV2} />
        {shellV2 ? (
          <IconRail nav={nav} activeSection={resourceRoute ? "" : section.id} activeLeaf={resourceRoute ? undefined : leaf?.id} user={user} onLogout={logout} onChangePassword={onChangePassword} homeRoute={homeRoute} />
        ) : (
          <Sidebar
            nav={nav}
            activeSection={resourceRoute ? "" : section.id}
            activeLeaf={resourceRoute ? undefined : leaf?.id}
            collapsed={collapsed}
            onToggle={() => setCollapsed((c) => !c)}
            homeRoute={homeRoute}
          />
        )}
        <main className={`main${pageBleed ? " main-bleed" : ""}`} id="main-content" tabIndex={-1}>
          <div className="main-head">
            <div className="crumbs">
              {resourceRoute ? (
                <>
                  <span className="crumb-section">Resource</span>
                  <span className="crumb-sep">/</span>
                  <span className="crumb-leaf">{resourceRoute.id}</span>
                </>
              ) : (
                <>
                  <span className="crumb-section">{section.label}</span>
                  {leaf && leaf.label !== section.label && <span className="crumb-sep">/</span>}
                  {leaf && leaf.label !== section.label && <span className="crumb-leaf">{leaf.label}</span>}
                </>
              )}
            </div>
            {/* Administration hides the horizontal leaf strip (owner, 2026-08-25):
                its 20+ leaves made the strip a second, noisier nav; the hover
                flyout's grouped list is the one Administration menu. */}
            {!resourceRoute && section.id !== "admin" && <SubNav section={section} activeLeaf={leaf?.id} />}
          </div>
          {/* Topology is a CANVAS, not a document: it gets the whole viewport
              rather than the reading-width page box. Without this the map sits
              inside a 1640px cap with side gutters on a wide monitor — the
              "limited to the borders" the owner reported. Opt-in per leaf so
              every other page keeps its comfortable measure. */}
          <div className={`page${pageBleed ? " page-bleed" : ""}`} key={tz}>
            {/* Administration acts on config — always state the acting scope
                (rendered in-page: shell-v2 hides the main-head strip). */}
            {section.id === "admin" && (
              <div className="admin-scope-strip">
                <ScopeBadge user={user} />
              </div>
            )}
            {/* Cross-tenant reach is not cross-tenant display (owner 2026-07-21):
                a platform admin opens ONE tenant at a time rather than reading
                ten tenants' telemetry merged into one table. Tenant users and
                already-scoped admins pass straight through. */}
            <TenantGate sectionId={resourceRoute ? "resource" : section.id} sectionLabel={resourceRoute ? "this resource" : section.label}>
              {/* Single Suspense boundary for the route-level code-split pages
                  (nav.tsx wraps every leaf in React.lazy). Same affordance as
                  the app-boot loading state above. */}
              <Suspense fallback={<div className="page-skeleton" aria-busy="true" />}>
                {/* A render exception in ANY route stops here: the rail, top bar
                    and drawers keep rendering and only the view is replaced by
                    a named, recoverable panel. Before this, one bad field
                    access white-screened the whole console. */}
                <ErrorBoundary label={viewLabel} route={hash} resetKey={routeKey}>
                  <RouteView build={buildView} />
                </ErrorBoundary>
              </Suspense>
            </TenantGate>
          </div>
        </main>
        <OpsisDrawer />
        <HelpDrawer />
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
