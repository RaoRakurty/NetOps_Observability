import { useEffect, useLayoutEffect, useRef, useState } from "react";
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
  const ref = useRef<HTMLDivElement | null>(null);
  // Keep the panel inside the viewport: anchor at the hovered item's top, but if
  // it would overflow the bottom (e.g. Administration in the foot), shift it up
  // so every child stays visible.
  const [topPx, setTopPx] = useState(top);
  useLayoutEffect(() => {
    const h = ref.current?.offsetHeight ?? 0;
    const max = window.innerHeight - h - 8;
    setTopPx(Math.max(8, Math.min(top, max)));
  }, [top, section.id]);

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
      ref={ref}
      className="nav-flyout"
      role="menu"
      aria-label={section.label}
      style={{ top: topPx, ["--mod" as string]: hue } as React.CSSProperties}
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
