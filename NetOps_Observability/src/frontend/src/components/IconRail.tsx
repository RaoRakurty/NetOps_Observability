import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { NavSection, routeFor } from "../nav";
import { useShell } from "../context/shell";
import { AuthUser } from "../services/api";
import Icon from "./Icon";
import NavFlyout from "./NavFlyout";
import { Modal } from "./ui";
import AppearanceControls from "./AppearanceControls";
import ScopeBadge from "./ScopeBadge";

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
  copilot: "#8B5CF6", // Iris AI — violet (kept)
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
// Governance zone anchored at the foot: Administration alone (Explain + Stack
// dissolved into it, 2026-07-10), above a thin-line-separated Support/Help
// zone, then the account. Excluded from the top groups.
const FOOT_ADMIN_IDS = ["admin"];

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

type OpenState = { id: string; top: number; focus?: boolean } | null;

// IconRail — the persistent labeled rail (icon before name, small font). Hovering
// or focusing a section opens a flyout of its children to the right; the rail
// never collapses and never reflows (the flyout is a fixed overlay). Click
// navigates. All sections render in order (Administration is no longer pinned to
// the very bottom), and a utility cluster (Account · Support · Help) sits at the
// foot — replacing the top-right user menu.
export default function IconRail({ nav, activeSection, activeLeaf, user, onLogout, onChangePassword }: Props) {
  const { navigate, setCopilotOpen, copilotOpen, setHelpOpen } = useShell();
  const [open, setOpen] = useState<OpenState>(null);
  const [acctOpen, setAcctOpen] = useState(false);
  const [supportOpen, setSupportOpen] = useState(false);
  const openTimer = useRef<number | undefined>(undefined);
  const closeTimer = useRef<number | undefined>(undefined);
  const acctCloseTimer = useRef<number | undefined>(undefined);
  const acctRef = useRef<HTMLDivElement | null>(null);
  // The rail item that opened the current flyout — focus returns here on Escape.
  const flyoutTrigger = useRef<HTMLElement | null>(null);

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
    flyoutTrigger.current = el;
    const top = el.getBoundingClientRect().top;
    openTimer.current = window.setTimeout(() => setOpen({ id, top }), 80);
  }, []);
  // Keyboard path (2.1.1): ArrowRight on a rail item opens its flyout at once
  // and moves focus onto the first menu item.
  const keyboardOpen = useCallback((id: string, el: HTMLElement) => {
    window.clearTimeout(closeTimer.current);
    window.clearTimeout(openTimer.current);
    flyoutTrigger.current = el;
    setOpen({ id, top: el.getBoundingClientRect().top, focus: true });
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
        aria-haspopup={!isCopilot ? "menu" : undefined}
        aria-expanded={!isCopilot ? open?.id === s.id : undefined}
        title={s.label}
        onClick={onActivate}
        onKeyDown={(e) => {
          if (!isCopilot && e.key === "ArrowRight") {
            e.preventDefault();
            keyboardOpen(s.id, e.currentTarget);
          }
        }}
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
      {/* No brand head (owner 2026-07-21): the rail's standalone eye is
          retired — the BLOGO5 wordmark in the topbar is the shell's one and
          only brand mark. The nav groups start at the top of the pane. */}

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
            <button className="rail-util-icon" type="button" title="Support" aria-label="Support" onClick={() => setSupportOpen(true)}>
              <Icon name="support" size={16} />
              <span>Support</span>
            </button>
            <button className="rail-util-icon" type="button" title="Documentation" aria-label="Documentation" onClick={() => setHelpOpen(true)}>
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
          onKeyDown={(e) => {
            if (e.key === "Escape" && acctOpen) {
              setAcctOpen(false);
              (acctRef.current?.querySelector(".rail-account-btn") as HTMLElement | null)?.focus();
            }
          }}
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
                <ScopeBadge user={user} />
              </div>
              <AppearanceControls />
              <button onClick={() => { setAcctOpen(false); navigate("admin/settings"); }}>Settings</button>
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
          autoFocus={open.focus}
          onEnter={cancelClose}
          onLeave={scheduleClose}
          onNavigate={navigate}
          onClose={(restoreFocus) => {
            setOpen(null);
            if (restoreFocus) flyoutTrigger.current?.focus();
          }}
        />
      )}
      {/* PORTALED to <body>: the rail's backdrop-filter makes it the containing
          block for fixed descendants, so an inline modal's full-screen scrim
          would be squeezed into the 52px rail column (the same trap the docs
          navbar hamburger fell into — see styles.css .rail comment). */}
      {supportOpen &&
        createPortal(
          <Modal title="Support" onClose={() => setSupportOpen(false)}>
            {/* Placeholder — the support portal isn't live yet. Keep it honest
                and give the operator somewhere useful to go meanwhile. */}
            <div className="support-placeholder">
              <p><strong>The support portal is coming soon.</strong></p>
              <p>
                Until it opens, the documentation covers setup, operations and
                troubleshooting for every part of the platform.
              </p>
              <button
                className="dash-btn"
                type="button"
                onClick={() => { setSupportOpen(false); setHelpOpen(true); }}
              >
                Open documentation
              </button>
            </div>
          </Modal>,
          document.body,
        )}
    </aside>
  );
}
