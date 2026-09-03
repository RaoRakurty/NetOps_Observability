// Section — the one-page BGP outage view's structural primitive.
//
// The BGP page used to be three tabs of cards; during an outage that meant an
// operator clicking between views to assemble one story. Owner instruction
// (2026-09-03): "put all the data into one page so that a NOC admin gets a
// single view during an outage without clicking so much." So every panel is now
// a SECTION on one screen, and this is the shell they all share.
//
// What the shell guarantees, so no panel has to re-invent it:
//
//   * an accessible landmark per section (`role="region"` with the title as its
//     name) plus a stable `data-section` id — that pair is what the layout test
//     asserts the ORDER of, and it is what a keyboard user navigates by;
//   * a "last updated" stamp in the header. A NOC screen that shows a number
//     without saying when it was measured invites an operator to act on stale
//     data, which during an outage is the expensive mistake;
//   * a uniform way to keep a long list short (`useCap` + `ShowAll`). Sections
//     render on load — no tab, no accordion hiding evidence — but a 500-row
//     feed is capped to the first N with an explicit control to see the rest.
//     The cap is what keeps the page's DOM budget flat (perf/budgets.json).
//
// Density is deliberate: the type scale, the header pitch and the right-aligned
// numeric column all live in the `.bgp-*` CSS block, not in inline styles, so
// the whole page reads as one instrument rather than a stack of cards.

import { useCallback, useMemo, useState, type ReactNode } from "react";

/** Formats a fetch timestamp as the section's "last updated" stamp. */
export function stamp(at: string | number | null | undefined): string {
  if (at == null || at === "") return "";
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString();
}

export function Section({
  id, title, updatedAt, note, actions, children,
}: {
  /** Stable machine id — the layout contract the ordering test reads. */
  id: string;
  title: string;
  /** When this section's data was last read. Omitted when it holds no fetch. */
  updatedAt?: string | number | null;
  /** One short qualifier beside the title (a source, a scope). */
  note?: ReactNode;
  /** Controls that belong to the section header rather than its body. */
  actions?: ReactNode;
  children: ReactNode;
}) {
  const s = stamp(updatedAt);
  return (
    <section className="bgp-sec" data-section={id} aria-label={title}>
      <div className="bgp-sec-hd">
        <h2>{title}</h2>
        {note && <span className="bgp-sec-note">{note}</span>}
        <span className="bgp-sec-sp" />
        {actions}
        {s && <span className="bgp-sec-stamp" title="When this section last read its data">upd {s}</span>}
      </div>
      <div className="bgp-sec-bd">{children}</div>
    </section>
  );
}

/** A titled block INSIDE a section — two related tables under one heading. */
export function SubBlock({ title, updatedAt, children }: {
  title: string; updatedAt?: string | number | null; children: ReactNode;
}) {
  const s = stamp(updatedAt);
  return (
    <div className="bgp-sub">
      <div className="bgp-sub-hd">
        <h3>{title}</h3>
        <span className="bgp-sec-sp" />
        {s && <span className="bgp-sec-stamp" title="When this block last read its data">upd {s}</span>}
      </div>
      {children}
    </div>
  );
}

export interface Capped<T> {
  /** The rows to render right now. */
  rows: T[];
  /** How many are held back. 0 when everything is on screen. */
  hidden: number;
  expanded: boolean;
  toggle: () => void;
}

/**
 * Keeps a long list to its first `n` rows until the operator asks for the rest.
 * Every section renders on load — this bounds WHAT it renders, never WHETHER.
 */
export function useCap<T>(items: T[], n: number): Capped<T> {
  const [expanded, setExpanded] = useState(false);
  const toggle = useCallback(() => setExpanded((v) => !v), []);
  const rows = useMemo(() => (expanded ? items : items.slice(0, n)), [items, n, expanded]);
  return { rows, hidden: Math.max(0, items.length - rows.length), expanded, toggle };
}

/** The control that pairs with `useCap`. Renders nothing when nothing is held back. */
export function ShowAll<T>({ cap, noun }: { cap: Capped<T>; noun: string }) {
  if (cap.hidden === 0 && !cap.expanded) return null;
  return (
    <button type="button" className="bgp-more" onClick={cap.toggle}>
      {cap.expanded ? `Show fewer ${noun}` : `Show all ${cap.hidden + cap.rows.length} ${noun}`}
    </button>
  );
}

export default Section;
