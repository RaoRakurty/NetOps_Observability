import { NAV, NavSection, routeFor } from "../nav";
import { useShell } from "../context/shell";

type Props = {
  activeSection: string;
  collapsed: boolean;
  onToggle: () => void;
};

export default function Sidebar({ activeSection, collapsed, onToggle }: Props) {
  const { navigate, setCopilotOpen, copilotOpen } = useShell();

  const main = NAV.filter((s) => !s.footer);
  const footer = NAV.filter((s) => s.footer);

  const item = (s: NavSection) => {
    const isCopilot = s.action === "copilot";
    const active = isCopilot ? copilotOpen : s.id === activeSection;
    return (
      <button
        key={s.id}
        className={`nav-item${active ? " active" : ""}`}
        title={collapsed ? s.label : undefined}
        onClick={() => (isCopilot ? setCopilotOpen(!copilotOpen) : navigate(routeFor(s)))}
      >
        <span className="nav-icon">{s.icon}</span>
        {!collapsed && <span className="nav-label">{s.label}</span>}
      </button>
    );
  };

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
      <nav className="nav-main">{main.map(item)}</nav>
      <div className="nav-footer">
        {footer.map(item)}
        <button className="nav-item nav-collapse" onClick={onToggle} title="Collapse sidebar">
          <span className="nav-icon">{collapsed ? "»" : "«"}</span>
          {!collapsed && <span className="nav-label">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
