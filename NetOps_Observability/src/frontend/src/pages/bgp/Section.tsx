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
// Type is for READING (owner, 2026-09-06: "fonts are too small looks hard on
// eye … make watchable font, elegant and crisp"). The scale, the header pitch
// and the right-aligned numeric column all live in the `.bgp-*` CSS block, not
// in inline styles, so the whole page reads as one instrument rather than a
// stack of cards — and so raising the scale is one edit, not forty.
//
// The shell also owns the two things that keep this page plain-language:
//   * `sub` — the technical name for what the plain heading asks (RPKI, ASPA,
//     bogon, BMP). Demoted one size, never deleted.
//   * `Details` — the disclosure secondary detail moved behind instead of into
//     the bin.

import { useCallback, useMemo, useState, type ReactNode } from "react";

/** Formats a fetch timestamp as the section's "last updated" stamp. */
export function stamp(at: string | number | null | undefined): string {
  if (at == null || at === "") return "";
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString();
}

export function Section({
  id, title, sub, updatedAt, note, actions, wide, children,
}: {
  /** Stable machine id — the layout contract the ordering test reads. */
  id: string;
  /** The PLAIN-LANGUAGE question this section answers. No jargon here. */
  title: string;
  /**
   * The technical name for what the heading asks, one size down and muted.
   * This is where "RPKI", "ASPA", "bogon" and "BMP" live now: an engineer can
   * still map the section onto the protocol word, and a NOC admin reading the
   * heading never has to.
   */
  sub?: string;
  /** When this section's data was last read. Omitted when it holds no fetch. */
  updatedAt?: string | number | null;
  /** One short qualifier beside the title (a source, a scope). */
  note?: ReactNode;
  /** Controls that belong to the section header rather than its body. */
  actions?: ReactNode;
  /** Spans BOTH grid columns. Rows are whole: a card is half-width only when
   *  it is paired with another, so the grid never ends on an orphan. */
  wide?: boolean;
  children: ReactNode;
}) {
  const s = stamp(updatedAt);
  return (
    <section className={`bgp-sec${wide ? " bgp-wide" : ""}`} data-section={id} aria-label={title}>
      <div className="bgp-sec-hd">
        <div className="bgp-sec-ttl">
          <h2>{title}</h2>
          {sub && <span className="bgp-sec-sub">{sub}</span>}
        </div>
        {note && <span className="bgp-sec-note">{note}</span>}
        <span className="bgp-sec-sp" />
        {actions}
        {s && <span className="bgp-sec-stamp" title="When this section last read its data">upd {s}</span>}
      </div>
      <div className="bgp-sec-bd">{children}</div>
    </section>
  );
}

/**
 * Details — the disclosure that secondary detail moved BEHIND rather than into
 * the bin (owner, 2026-09-06: "each section should just show what NOC admin
 * wants to see"). Nothing is deleted: provenance, protocol caveats, per-row
 * evidence and long captions all still render, one click away, and stay in the
 * DOM so they remain searchable and keyboard-reachable.
 */
export function Details({ summary, children }: { summary: string; children: ReactNode }) {
  return (
    <details className="bgp-details">
      <summary>{summary}</summary>
      <div className="bgp-details-bd">{children}</div>
    </details>
  );
}

/** One KPI tile: a number a NOC admin reads from across the room, its plain
 *  label, and (optionally) what the number means for them right now. */
export function Kpi({ n, label, interp, tone, title }: {
  n: ReactNode; label: string; interp?: string; tone?: string; title?: string;
}) {
  return (
    <div className="bgp-kpi" title={title}>
      <div className="bgp-kpi-n" style={tone ? { color: tone } : undefined}>{n}</div>
      <div className="bgp-kpi-l">{label}</div>
      {interp && <div className="bgp-kpi-i">{interp}</div>}
    </div>
  );
}

/** The KPI row. Three or four tiles; below 720px it folds to two columns. */
export function Kpis({ cols = 4, children }: { cols?: 3 | 4; children: ReactNode }) {
  return <div className={`bgp-kpis${cols === 3 ? " bgp-kpis-3" : ""}`}>{children}</div>;
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
