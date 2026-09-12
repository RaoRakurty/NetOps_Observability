// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { Fragment, useEffect, useLayoutEffect, useRef, useState } from "react";
import { NavSection, routeFor } from "../nav";

type Props = {
  section: NavSection;
  top: number;
  hue: string;
  activeSection: string;
  activeLeaf?: string;
  /** Opened via keyboard (ArrowRight on the rail item): focus the first item. */
  autoFocus?: boolean;
  onEnter: () => void;
  onLeave: () => void;
  onNavigate: (route: string) => void;
  /** restoreFocus=true when closed via keyboard — caller refocuses the trigger. */
  onClose: (restoreFocus?: boolean) => void;
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
  autoFocus,
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
      if (e.key === "Escape") onClose(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Keyboard-opened (rail ArrowRight): move focus onto the first menu item.
  useEffect(() => {
    if (autoFocus) {
      ref.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    }
  }, [autoFocus, section.id]);

  // Menu keyboard pattern: ArrowUp/Down move between items, Home/End jump.
  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
    const items = Array.from(ref.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);
    if (items.length === 0) return;
    e.preventDefault();
    const cur = items.indexOf(document.activeElement as HTMLElement);
    const next =
      e.key === "Home" ? 0 :
      e.key === "End" ? items.length - 1 :
      e.key === "ArrowDown" ? (cur + 1) % items.length :
      cur <= 0 ? items.length - 1 : cur - 1;
    items[next]?.focus();
  };

  // Current route path (sans leading #/ and ?query), tracked so the active
  // sub-item highlights — and updates if a sub-item is clicked while open.
  const [curPath, setCurPath] = useState(() => location.hash.replace(/^#\/?/, "").split("?")[0]);
  useEffect(() => {
    const onHash = () => setCurPath(location.hash.replace(/^#\/?/, "").split("?")[0]);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

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
      onKeyDown={onMenuKeyDown}
      // Focus moving from the rail item into the flyout fires the rail item's
      // blur-close timer — cancel it while focus lives here; resume when focus
      // leaves the flyout entirely (2.1.1: no keyboard-unreachable menu).
      onFocus={onEnter}
      onBlur={(e) => {
        if (!ref.current?.contains(e.relatedTarget as Node)) onLeave();
      }}
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
          (() => {
            let lastGroup: string | undefined;
            return children.map((leaf) => {
              const active = section.id === activeSection && leaf.id === activeLeaf;
              const header = leaf.group && leaf.group !== lastGroup ? leaf.group : null;
              lastGroup = leaf.group;
              return (
                <Fragment key={leaf.id}>
                  {header && <div className="nav-flyout-group" role="presentation">{header}</div>}
                  <button
                    type="button"
                    role="menuitem"
                    className={`nav-flyout-item${active ? " active" : ""}${leaf.subItems ? " has-sub" : ""}`}
                    onClick={() => onNavigate(`${section.id}/${leaf.id}`)}
                  >
                    {leaf.label}
                  </button>
                  {(leaf.subItems ?? []).map((sub) => {
                    const target = sub.route ?? `${section.id}/${leaf.id}/${sub.id}`;
                    const subActive = curPath === target;
                    return (
                      <button
                        key={sub.id}
                        type="button"
                        role="menuitem"
                        aria-current={subActive ? "true" : undefined}
                        className={`nav-flyout-subitem${subActive ? " active" : ""}`}
                        onClick={() => onNavigate(target)}
                      >
                        {sub.label}
                      </button>
                    );
                  })}
                </Fragment>
              );
            });
          })()
        )}
      </div>
    </div>
  );
}
