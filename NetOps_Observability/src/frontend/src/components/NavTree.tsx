// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { Fragment, useCallback, useEffect, useState } from "react";
import type { NavLeaf, NavSection } from "../nav";
import Icon from "./Icon";

// NavTree — the expanded navigation (visual language, owner 2026-11-24; the
// approved mockup is docs/design/visual-language.md §Menu). It replaces the
// expanded rail's section list with the full menu, laid out the way the owner
// asked for:
//
//   · Home / Overview / My dashboards and Iris at the top, flat;
//   · then the work sections in zones (Operations · Investigate + Explore ·
//     Infrastructure + Security · Analytics), each zone after a thin divider;
//   · Administration and Platform at the foot, after a divider;
//   · every section is a header with a LEFT chevron that folds its pages away;
//   · every page carries a grey line icon; only the page you are on is tinted
//     with the one accent colour.
//
// Presentation only: the sections arrive permission-filtered (filteredNav), and
// every route is the same `section/leaf` the flyout and the router use.

export type NavTreeProps = {
  nav: NavSection[];
  activeSection: string;
  activeLeaf?: string;
  copilotOpen: boolean;
  onToggleCopilot: () => void;
  onNavigate: (route: string) => void;
};

// Zones of work sections, in the order the operator reaches for them. Sections
// not listed (and not top/foot) are appended as one more zone, so nothing a
// future nav entry adds is ever dropped.
const ZONES: string[][] = [["operations"], ["investigate", "explore"], ["infrastructure", "security"], ["analytics"]];
const TOP_ID = "overview";
const FOOT_IDS = ["admin", "platform"];

// Which sections are folded open is remembered per browser — a convenience,
// never required: a private window or blocked storage just starts fresh.
export const NAV_TREE_OPEN_KEY = "netops.navTree.open";
function readOpen(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(NAV_TREE_OPEN_KEY);
    const v = raw ? JSON.parse(raw) : {};
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}
function writeOpen(v: Record<string, boolean>) {
  try {
    localStorage.setItem(NAV_TREE_OPEN_KEY, JSON.stringify(v));
  } catch {
    /* the fold state just won't persist */
  }
}

function currentPath(): string {
  return location.hash.replace(/^#\/?/, "").split("?")[0];
}

export default function NavTree({ nav, activeSection, activeLeaf, copilotOpen, onToggleCopilot, onNavigate }: NavTreeProps) {
  const [open, setOpen] = useState<Record<string, boolean>>(readOpen);
  const [curPath, setCurPath] = useState(currentPath);
  // Collapsible leaves (NavLeaf.collapsible) toggled by the operator.
  const [leafOpen, setLeafOpen] = useState<Record<string, boolean>>({});
  useEffect(() => {
    const on = () => setCurPath(currentPath());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  // The section you are in is always shown open, whatever was stored: the page
  // you are on is never hidden behind a fold.
  const isOpen = (id: string) => id === activeSection || (open[id] ?? false);
  const toggle = useCallback((id: string, now: boolean) => {
    setOpen((o) => {
      const next = { ...o, [id]: !now };
      writeOpen(next);
      return next;
    });
  }, []);

  const byId = new Map(nav.map((s) => [s.id, s]));
  const claimed = new Set<string>([TOP_ID, ...FOOT_IDS]);
  const zones = ZONES.map((ids) => {
    ids.forEach((id) => claimed.add(id));
    return ids.map((id) => byId.get(id)).filter(Boolean) as NavSection[];
  }).filter((z) => z.length > 0);
  const copilot = nav.find((s) => s.action === "copilot");
  if (copilot) claimed.add(copilot.id);
  const leftover = nav.filter((s) => !claimed.has(s.id));
  if (leftover.length) zones.push(leftover);
  const top = byId.get(TOP_ID);
  const foot = FOOT_IDS.map((id) => byId.get(id)).filter(Boolean) as NavSection[];

  const leafRow = (s: NavSection, leaf: NavLeaf, indent: boolean) => {
    const active = s.id === activeSection && leaf.id === activeLeaf;
    const subs = leaf.subItems ?? [];
    const collapsible = !!leaf.collapsible && subs.length > 0;
    const inside =
      curPath === `${s.id}/${leaf.id}` ||
      curPath.startsWith(`${s.id}/${leaf.id}/`) ||
      subs.some((x) => x.route !== undefined && curPath === x.route);
    const subsOpen = collapsible ? leafOpen[`${s.id}/${leaf.id}`] ?? inside : active;
    return (
      <Fragment key={`${s.id}/${leaf.id}`}>
        <button
          type="button"
          className={`nt-item${indent ? " nt-indent" : ""}${active ? " active" : ""}`}
          aria-current={active ? "page" : undefined}
          aria-expanded={collapsible ? subsOpen : undefined}
          data-testid={`nt-leaf-${s.id}-${leaf.id}`}
          onClick={() =>
            collapsible
              ? setLeafOpen((m) => ({ ...m, [`${s.id}/${leaf.id}`]: !subsOpen }))
              : onNavigate(`${s.id}/${leaf.id}`)
          }
        >
          <Icon name={leaf.icon} size={16} className="nt-icon" />
          <span className="nt-label">{leaf.label}</span>
          {collapsible && <Icon name={subsOpen ? "chevron-down" : "chevron-right"} size={14} className="nt-subchev" />}
        </button>
        {/* In-page sub-items show under the page you are on (or under an
            opened collapsible leaf) — the rest of the tree stays one line per
            page, as in the approved mockup. */}
        {subsOpen &&
          subs.map((sub) => {
            const target = sub.route ?? `${s.id}/${leaf.id}/${sub.id}`;
            const subActive = curPath === target;
            return (
              <button
                key={sub.id}
                type="button"
                className={`nt-subitem${subActive ? " active" : ""}`}
                aria-current={subActive ? "true" : undefined}
                onClick={() => onNavigate(target)}
              >
                {sub.label}
              </button>
            );
          })}
      </Fragment>
    );
  };

  const leaves = (s: NavSection, indent: boolean) => {
    let lastGroup: string | undefined;
    return (s.children ?? []).map((leaf) => {
      const header = leaf.group && leaf.group !== lastGroup ? leaf.group : null;
      lastGroup = leaf.group;
      return (
        <Fragment key={`${s.id}/${leaf.id}/g`}>
          {header && (
            <div className="nt-group" role="presentation">
              {header}
            </div>
          )}
          {leafRow(s, leaf, indent)}
        </Fragment>
      );
    });
  };

  const section = (s: NavSection) => {
    const o = isOpen(s.id);
    return (
      <div className="nt-section" key={s.id} data-testid={`nt-section-${s.id}`}>
        <button
          type="button"
          className={`nt-head${s.id === activeSection ? " in" : ""}`}
          aria-expanded={o}
          onClick={() => toggle(s.id, o)}
        >
          <Icon name={o ? "chevron-down" : "chevron-right"} size={14} className="nt-chev" />
          <span className="nt-label">{s.label}</span>
        </button>
        {o && <div className="nt-leaves">{leaves(s, true)}</div>}
      </div>
    );
  };

  return (
    <nav className="nav-tree" aria-label="Primary">
      {(top || copilot) && (
        <div className="nt-zone nt-top">
          {top && leaves(top, false)}
          {copilot && (
            <button
              type="button"
              className={`nt-item${copilotOpen ? " active" : ""}`}
              aria-pressed={copilotOpen}
              data-testid="nav-iris"
              title={copilot.label}
              onClick={onToggleCopilot}
            >
              <Icon name={copilot.icon} size={16} className="nt-icon" />
              <span className="nt-label">{copilot.label}</span>
            </button>
          )}
        </div>
      )}
      {zones.map((z, i) => (
        <div className="nt-zone" key={i}>
          {z.map(section)}
        </div>
      ))}
      {foot.length > 0 && <div className="nt-zone nt-foot">{foot.map(section)}</div>}
    </nav>
  );
}
