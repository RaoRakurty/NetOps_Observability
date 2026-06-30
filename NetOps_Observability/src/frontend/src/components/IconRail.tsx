import { useCallback, useEffect, useRef, useState } from "react";
import { NavSection, routeFor } from "../nav";
import { useShell } from "../context/shell";
import { AuthUser } from "../services/api";
import { BRAND } from "../brand";
import Icon from "./Icon";
import NavFlyout from "./NavFlyout";
import { Modal } from "./ui";
import MfaCard from "./MfaCard";
import AppearanceControls from "./AppearanceControls";

// Per-module accent hue (design spec §9.1 taxonomy), keyed by section id. This
// only tints the active indicator + the flyout header; severity colours stay
// separate and sacred. Falls back to periwinkle for any unmapped section.
// Per-section hue — vivid, saturated tones at Alert-pink intensity so hovering
// any item gives a clear contrast colour (the mild set read too flat on the
// dark rail). Alerts (pink) and Copilot/ChatGPT (violet) are kept; the rest are
// spread across the wheel: blue · cyan · green · teal · orange · amber · slate.
const MOD_HUE: Record<string, string> = {
  dashboards: "#3B82F6", // Dashboards — vivid blue
  monitoring: "#EC4899", // Monitoring — pink (kept from Alerts)
  incident: "#F97316", // Incident Response — vivid orange
  automation: "#A855F7", // Automation — vivid purple
  infrastructure: "#22C55E", // Fleet — vivid leafy green
  security: "#EF4444", // Security — vivid red
  metrics: "#0EA5E9", // Metrics — vivid sky
  flows: "#14B8A6", // Flows — vivid teal
  logs: "#EAB308", // Logs — vivid amber/gold
  explain: "#D946EF", // Explain (access reasoning) — vivid fuchsia
  stack: "#64748B", // Stack — slate (utility)
  copilot: "#8B5CF6", // Correlix AI — violet (kept)
  admin: "#94A3B8", // Admin — slate (utility)
};
const hueFor = (id: string) => MOD_HUE[id] ?? "#818CF8";

// Segregated nav groups (presentation only — the nav data in nav.tsx is shared
// with the v1 sidebar and stays untouched). Sections render under their group's
// label with a thin divider between groups. Any section not listed falls into a
// trailing "More" group so nothing is ever dropped.
// Three layers (the hybrid IA): Operations (monitor/operate) · Explain (access
// reasoning) · and — anchored at the foot — Governance (Administration + Stack).
const GROUPS: { label: string; ids: string[] }[] = [
  { label: "Monitor", ids: ["dashboards", "monitoring", "incident", "automation"] },
  { label: "Infrastructure", ids: ["infrastructure", "security"] },
  { label: "Data", ids: ["metrics", "flows", "logs"] },
];
// Governance/admin zone anchored at the foot: Explain + Stack +
// Administration kept together, above a thin-line-separated Support/Help zone,
// then the account. Excluded from the top groups.
const FOOT_ADMIN_IDS = ["explain", "stack", "admin"];

type Props = {
  nav: NavSection[];
  activeSection: string;
  activeLeaf?: string;
  user: AuthUser;
  onLogout: () => void;
  // Opens the self-service change-password modal; undefined for federated
  // accounts (they change it at the IdP) so the item is hidden.
  onChangePassword?: () => void;
  // Where the brand/Home button goes (the configured landing, else first section).
  homeRoute?: string;
};

type OpenState = { id: string; top: number } | null;

// IconRail — the persistent labeled rail (icon before name, small font). Hovering
// or focusing a section opens a flyout of its children to the right; the rail
// never collapses and never reflows (the flyout is a fixed overlay). Click
// navigates. All sections render in order (Administration is no longer pinned to
// the very bottom), and a utility cluster (Account · Support · Help) sits at the
// foot — replacing the top-right user menu.
export default function IconRail({ nav, activeSection, activeLeaf, user, onLogout, onChangePassword, homeRoute }: Props) {
  const { navigate, setCopilotOpen, copilotOpen } = useShell();
  const [open, setOpen] = useState<OpenState>(null);
  const [acctOpen, setAcctOpen] = useState(false);
  const [mfaOpen, setMfaOpen] = useState(false);
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
        title={s.label}
        onClick={onActivate}
        onMouseEnter={(e) => !isCopilot && scheduleOpen(s.id, e.currentTarget)}
        onFocus={(e) => !isCopilot && scheduleOpen(s.id, e.currentTarget)}
        onMouseLeave={scheduleClose}
        onBlur={scheduleClose}
      >
        <span className="rail-icon">
          <Icon name={s.icon} size={19} />
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
        onClick={() => navigate(homeRoute ?? routeFor(nav[0]))}
        title={BRAND}
        aria-label={BRAND}
      >
        {/* Eye brand mark (placeholder for the final logo): a flat almond eye —
            eyelids (the outline), an iris ring and a pupil. The "Correlix"
            wordmark lives in the top bar (UI-16); the rail carries just this mark. */}
        <span className="brand-eye" aria-hidden="true">
          <svg viewBox="0 0 28 28" width="26" height="26" fill="none">
            {/* Eyelids — symmetric almond/lens */}
            <path d="M2 14 C 7 6.5, 21 6.5, 26 14 C 21 21.5, 7 21.5, 2 14 Z"
              stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
            {/* Iris ring */}
            <circle cx="14" cy="14" r="4.2" stroke="currentColor" strokeWidth="1.8" />
            {/* Pupil */}
            <circle cx="14" cy="14" r="1.7" fill="currentColor" />
          </svg>
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

      {/* Foot cluster, thin-line separated zones:
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
              <AppearanceControls />
              <button onClick={() => { setAcctOpen(false); navigate("admin/settings"); }}>Settings</button>
              <button onClick={() => { setAcctOpen(false); setMfaOpen(true); }}>Two-factor authentication</button>
              {onChangePassword && (
                <button onClick={() => { setAcctOpen(false); onChangePassword(); }}>Change password</button>
              )}
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
      {mfaOpen && (
        <Modal title="Two-factor authentication" subtitle={user.username} onClose={() => setMfaOpen(false)}>
          <MfaCard />
        </Modal>
      )}
    </aside>
  );
}
