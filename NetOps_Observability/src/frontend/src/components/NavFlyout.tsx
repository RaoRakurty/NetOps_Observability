import { useEffect } from "react";
import { NavSection, routeFor } from "../nav";

type Props = {
  section: NavSection;
  top: number;
  hue: string;
  activeSection: string;
  activeLeaf?: string;
  onEnter: () => void;
  onLeave: () => void;
  onNavigate: (route: string) => void;
  onClose: () => void;
};

// NavFlyout — the hover panel that lists a section's children to the right of
// the rail. Fixed-position overlay (never reflows the page), top-aligned to the
// hovered rail item. Closes on Escape; staying hovered keeps it open.
export default function NavFlyout({
  section,
  top,
  hue,
  activeSection,
  activeLeaf,
  onEnter,
  onLeave,
  onNavigate,
  onClose,
}: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const children = section.children ?? [];

  return (
    <div
      className="nav-flyout"
      role="menu"
      aria-label={section.label}
      style={{ top, ["--mod" as string]: hue } as React.CSSProperties}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
    >
      <div className="nav-flyout-head">{section.label}</div>
      <div className="nav-flyout-body">
        {children.length === 0 ? (
          <button
            type="button"
            role="menuitem"
            className="nav-flyout-item active"
            onClick={() => onNavigate(routeFor(section))}
          >
            Open {section.label}
          </button>
        ) : (
          children.map((leaf) => {
            const active = section.id === activeSection && leaf.id === activeLeaf;
            return (
              <button
                key={leaf.id}
                type="button"
                role="menuitem"
                className={`nav-flyout-item${active ? " active" : ""}`}
                onClick={() => onNavigate(`${section.id}/${leaf.id}`)}
              >
                {leaf.label}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
