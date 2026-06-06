import { useCallback, useEffect, useRef, useState } from "react";
import { NavSection, routeFor } from "../nav";
import { useShell } from "../context/shell";
import { usePrefs, CHROME_PRESETS } from "../theme/prefs";
import { AuthUser } from "../services/api";
import { BRAND } from "../brand";
import Icon from "./Icon";
import NavFlyout from "./NavFlyout";

// Per-module accent hue (design spec §9.1 taxonomy), keyed by section id. This
// only tints the active indicator + the flyout header; severity colours stay
// separate and sacred. Falls back to periwinkle for any unmapped section.
const MOD_HUE: Record<string, string> = {
  overview: "#2D6BE0", // Pulse — cobalt
  explore: "#22B8CF", // Explore/Metrics — cyan
  alerts: "#EC4899", // Monitors/Alerts — pink
  infrastructure: "#14B8A6", // Fleet — teal
  topology: "#3B9EFF", // Network — azure
  reports: "#818CF8", // Reports — periwinkle
  stack: "#06B6D4", // Stack — bright cyan
  copilot: "#8B5CF6", // Copilot — violet
  admin: "#64748B", // Admin — slate
};
const hueFor = (id: string) => MOD_HUE[id] ?? "#818CF8";

// Segregated nav groups (presentation only — the nav data in nav.tsx is shared
// with the v1 sidebar and stays untouched). Sections render under their group's
// label with a thin divider between groups. Any section not listed falls into a
// trailing "More" group so nothing is ever dropped.
const GROUPS: { label: string; ids: string[] }[] = [
  { label: "Monitoring", ids: ["overview", "copilot", "alerts", "topology", "reports"] },
  { label: "Infrastructure & Logs", ids: ["infrastructure", "explore"] },
];
// Admin zone anchored at the foot (Datadog-style): Stack + Administration kept
// together in one zone, above a thin-line-separated Support/Help zone, then the
// account. Excluded from the top groups.
const FOOT_ADMIN_IDS = ["stack", "admin"];

type Props = {
  nav: NavSection[];
  activeSection: string;
  activeLeaf?: string;
  user: AuthUser;
  onLogout: () => void;
};

type OpenState = { id: string; top: number } | null;

// IconRail — the persistent labeled rail (icon before name, small font). Hovering
// or focusing a section opens a flyout of its children to the right; the rail
// never collapses and never reflows (the flyout is a fixed overlay). Click
// navigates. All sections render in order (Administration is no longer pinned to
// the very bottom), and a utility cluster (Account · Support · Help) sits at the
// foot — replacing the top-right user menu.
export default function IconRail({ nav, activeSection, activeLeaf, user, onLogout }: Props) {
  const { navigate, setCopilotOpen, copilotOpen } = useShell();
  const { theme, setTheme, density, setDensity, chrome, setChrome } = usePrefs();
  const [open, setOpen] = useState<OpenState>(null);
  const [acctOpen, setAcctOpen] = useState(false);
  const openTimer = useRef<number | undefined>(undefined);
  const closeTimer = useRef<number | undefined>(undefined);
  const acctCloseTimer = useRef<number | undefined>(undefined);
  const acctRef = useRef<HTMLDivElement | null>(null);

  // Account/preferences opens on hover-intent like the rail items (flyout to the
  // right), with a close grace so the diagonal path into it doesn't dismiss.
  const openAcct = useCallback(() => {
    window.clearTimeout(acctCloseTimer.current);
    setOpen(null); // don't overlap with a nav flyout
    setAcctOpen(true);
  }, []);
  const closeAcct = useCallback(() => {
    acctCloseTimer.current = window.setTimeout(() => setAcctOpen(false), 200);
  }, []);

  // Hover-intent: open after 80ms, close after a 200ms grace so a diagonal
  // cursor path into the flyout doesn't dismiss it ("safe triangle").
  const scheduleOpen = useCallback((id: string, el: HTMLElement) => {
    window.clearTimeout(closeTimer.current);
    window.clearTimeout(openTimer.current);
    const top = el.getBoundingClientRect().top;
    openTimer.current = window.setTimeout(() => setOpen({ id, top }), 80);
  }, []);
  const scheduleClose = useCallback(() => {
    window.clearTimeout(openTimer.current);
    closeTimer.current = window.setTimeout(() => setOpen(null), 200);
  }, []);
  const cancelClose = useCallback(() => window.clearTimeout(closeTimer.current), []);

  // Close the account menu on outside click.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (acctRef.current && !acctRef.current.contains(e.target as Node)) setAcctOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const railItem = (s: NavSection) => {
    const isCopilot = s.action === "copilot";
    const active = isCopilot ? copilotOpen : s.id === activeSection;
    const onActivate = () => (isCopilot ? setCopilotOpen(!copilotOpen) : navigate(routeFor(s)));
    return (
      <button
        key={s.id}
        type="button"
        className={`rail-item${active ? " active" : ""}`}
        style={{ ["--mod" as string]: hueFor(s.id) } as React.CSSProperties}
        aria-current={active ? "page" : undefined}
        onClick={onActivate}
        onMouseEnter={(e) => !isCopilot && scheduleOpen(s.id, e.currentTarget)}
        onFocus={(e) => !isCopilot && scheduleOpen(s.id, e.currentTarget)}
        onMouseLeave={scheduleClose}
        onBlur={scheduleClose}
      >
        <span className="rail-icon">
          <Icon name={s.icon} size={16} />
        </span>
        <span className="rail-label">{s.label}</span>
      </button>
    );
  };

  // Resolve groups against the (already permission-filtered) nav, preserving
  // group order; collect any unlisted sections into a trailing group.
  const byId = new Map(nav.map((s) => [s.id, s]));
  const claimed = new Set<string>();
  const groups = GROUPS.map((g) => {
    const sections = g.ids.map((id) => byId.get(id)).filter(Boolean) as NavSection[];
    sections.forEach((s) => claimed.add(s.id));
    return { label: g.label, sections };
  }).filter((g) => g.sections.length > 0);
  const adminZone = FOOT_ADMIN_IDS.map((id) => byId.get(id)).filter(Boolean) as NavSection[];
  adminZone.forEach((s) => claimed.add(s.id));
  const leftover = nav.filter((s) => !claimed.has(s.id));
  if (leftover.length) groups.push({ label: "More", sections: leftover });

  const openSection = open ? nav.find((s) => s.id === open.id) ?? null : null;

  return (
    <aside className="rail">
      <button
        className="rail-brand"
        onClick={() => navigate(routeFor(nav[0]))}
        title={BRAND}
        aria-label={BRAND}
      >
        <span className="rail-brand-mark">
          <Icon name="logo" size={22} />
        </span>
        <span className="rail-brand-name">{BRAND}</span>
      </button>

      {/* Segregated groups with thin dividers (Monitoring · Infra & Logs · Admin). */}
      <nav className="rail-main" aria-label="Primary">
        {groups.map((g) => (
          <div className="rail-group" key={g.label}>
            <div className="rail-group-label">{g.label}</div>
            {g.sections.map(railItem)}
          </div>
        ))}
      </nav>

      {/* Foot cluster (Datadog-style), thin-line separated zones:
          (5) admin zone = Stack + Administration · (6) Support/Help · account. */}
      <div className="rail-util">
        <div className="rail-foot-zone">{adminZone.map(railItem)}</div>

        <div className="rail-foot-zone">
          <div className="rail-util-row">
            <button className="rail-util-icon" type="button" title="Support" aria-label="Support">
              <Icon name="support" size={16} />
              <span>Support</span>
            </button>
            <button className="rail-util-icon" type="button" title="Help" aria-label="Help">
              <Icon name="help" size={16} />
              <span>Help</span>
            </button>
          </div>
        </div>

        <div
          className="rail-foot-zone rail-account"
          ref={acctRef}
          onMouseEnter={openAcct}
          onMouseLeave={closeAcct}
        >
          <button
            className="rail-util-item rail-account-btn"
            type="button"
            onClick={() => setAcctOpen((o) => !o)}
            aria-haspopup="menu"
            aria-expanded={acctOpen}
          >
            <span className="avatar">{user.username.slice(0, 1).toUpperCase()}</span>
            <span className="rail-account-id">
              <span className="rail-account-name">{user.username}</span>
              <span className="rail-account-role">{user.role}</span>
            </span>
          </button>
          {acctOpen && (
            <div className="menu-pop rail-account-pop" role="menu">
              <div className="menu-head">
                {user.username}
                <span style={{ color: "var(--muted)" }}> · {user.role}</span>
              </div>
              <div className="pref-row">
                <span className="pref-label">Theme</span>
                <span className="pref-seg">
                  <button className={theme === "light" ? "on" : ""} onClick={() => setTheme("light")}>Light</button>
                  <button className={theme === "dark" ? "on" : ""} onClick={() => setTheme("dark")}>Dark</button>
                  <button className={theme === "oled" ? "on" : ""} onClick={() => setTheme("oled")}>OLED</button>
                </span>
              </div>
              <div className="pref-row">
                <span className="pref-label">Accent</span>
                <span className="chrome-seg">
                  {CHROME_PRESETS.map((c) => (
                    <button
                      key={c.id}
                      className={`chrome-dot${chrome === c.id ? " on" : ""}`}
                      style={{ ["--dot" as any]: c.swatch }}
                      title={c.label}
                      aria-label={`${c.label} accent`}
                      aria-pressed={chrome === c.id}
                      onClick={() => setChrome(c.id)}
                    />
                  ))}
                </span>
              </div>
              <div className="pref-row">
                <span className="pref-label">Density</span>
                <span className="pref-seg">
                  <button className={density === "comfortable" ? "on" : ""} onClick={() => setDensity("comfortable")}>Cozy</button>
                  <button className={density === "compact" ? "on" : ""} onClick={() => setDensity("compact")}>Compact</button>
                </span>
              </div>
              <button onClick={() => { setAcctOpen(false); navigate("admin/settings"); }}>Settings</button>
              <button onClick={onLogout}>Sign out</button>
            </div>
          )}
        </div>
      </div>

      {openSection && open && (
        <NavFlyout
          section={openSection}
          top={open.top}
          hue={hueFor(openSection.id)}
          activeSection={activeSection}
          activeLeaf={activeLeaf}
          onEnter={cancelClose}
          onLeave={scheduleClose}
          onNavigate={navigate}
          onClose={() => setOpen(null)}
        />
      )}
    </aside>
  );
}
