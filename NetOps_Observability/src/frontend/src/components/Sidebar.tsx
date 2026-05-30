import { useState } from "react";
import { NAV, NavLeaf, NavSection, routeFor } from "../nav";
import { useShell } from "../context/shell";
import { BRAND } from "../brand";
import Icon from "./Icon";

type Props = {
  activeSection: string;
  activeLeaf?: string;
  collapsed: boolean;
  onToggle: () => void;
};

export default function Sidebar({ activeSection, activeLeaf, collapsed, onToggle }: Props) {
  const { navigate, setCopilotOpen, copilotOpen } = useShell();

  // Which grouped sections are expanded in the sidebar. A section defaults to
  // expanded when it's the active one, so the current leaf is always visible.
  const [overrides, setOverrides] = useState<Record<string, boolean>>({});
  const isOpen = (id: string) => overrides[id] ?? id === activeSection;
  const toggle = (id: string) => setOverrides((m) => ({ ...m, [id]: !isOpen(id) }));

  const main = NAV.filter((s) => !s.footer);
  const footer = NAV.filter((s) => s.footer);

  const leafItem = (s: NavSection, leaf: NavLeaf) => {
    const active = s.id === activeSection && leaf.id === activeLeaf;
    return (
      <button
        key={leaf.id}
        className={`nav-sub${active ? " active" : ""}`}
        onClick={() => navigate(`${s.id}/${leaf.id}`)}
      >
        <span className="nav-label">{leaf.label}</span>
      </button>
    );
  };

  const item = (s: NavSection) => {
    const isCopilot = s.action === "copilot";
    const active = isCopilot ? copilotOpen : s.id === activeSection;
    // Children only nest in the sidebar when it's expanded; collapsed (icons
    // only) mode falls back to the in-content SubNav for leaf switching.
    const grouped = !!s.children && !collapsed;
    const open = grouped && isOpen(s.id);

    const onClick = () => {
      if (isCopilot) return setCopilotOpen(!copilotOpen);
      // Navigate into the section (active or first leaf) and reveal its
      // children. The caret handles pure collapse without leaving the page.
      navigate(routeFor(s));
      if (grouped) setOverrides((m) => ({ ...m, [s.id]: true }));
    };

    return (
      <div key={s.id} className="nav-group">
        <button
          className={`nav-item${active ? " active" : ""}`}
          title={collapsed ? s.label : undefined}
          onClick={onClick}
        >
          <span className="nav-icon"><Icon name={s.icon} size={18} /></span>
          {!collapsed && <span className="nav-label">{s.label}</span>}
          {grouped && (
            <span
              className="nav-caret"
              role="button"
              aria-label={open ? "Collapse" : "Expand"}
              onClick={(e) => { e.stopPropagation(); toggle(s.id); }}
            >
              <Icon name={open ? "chevron-down" : "chevron-right"} size={14} />
            </span>
          )}
        </button>
        {open && <div className="nav-children">{s.children!.map((leaf) => leafItem(s, leaf))}</div>}
      </div>
    );
  };

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
      <button className="rail-brand" onClick={() => navigate(routeFor(main[0]))} title={BRAND}>
        <span className="rail-brand-mark"><Icon name="logo" size={20} /></span>
        {!collapsed && <span className="rail-brand-name">{BRAND}</span>}
      </button>
      <nav className="nav-main">{main.map(item)}</nav>
      <div className="nav-footer">
        {footer.map(item)}
        <button className="nav-item nav-collapse" onClick={onToggle} title="Collapse sidebar">
          <span className="nav-icon">
            <Icon name={collapsed ? "chevron-right" : "chevron-left"} size={18} />
          </span>
          {!collapsed && <span className="nav-label">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
