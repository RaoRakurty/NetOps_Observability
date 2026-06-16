// DataTable — the #45 phase-2 telemetry table primitive (spec §20.2).
//
// A dense, virtualized, keyboard-navigable table built on the semantic token
// layer (--row-h / --surface / severity ramp) in plain CSS — NO TanStack/Tailwind
// dependency, matching how the rest of shell-v2 is built (hand-rolled on tokens).
// It realizes the spec's BEHAVIOUR: 28px rows, frozen header, inline-filterable,
// sortable columns, conditional severity tint, row keyboard nav, hover actions,
// and windowed rendering so a 100k-row fleet stays at 60fps.
//
// Generic over the row type T; the consumer supplies column defs and a stable
// rowKey. Filtering/sorting are computed here from the column `text`/`sortValue`
// accessors so every consumer gets the same dense interaction model for free.

import {
  ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export type Sev = "ok" | "warn" | "crit" | "info" | "ack";
export type Align = "left" | "right" | "center";

export interface Column<T> {
  key: string;
  header: ReactNode;
  /** px number, a CSS grid track ("20%", "1fr"), or undefined → minmax(0,1fr). */
  width?: number | string;
  align?: Align;
  sortable?: boolean;
  /** Value used to sort this column; defaults to the `text` accessor. */
  sortValue?: (row: T) => string | number;
  /** Plain text contributed to the global filter (defaults to ""). */
  text?: (row: T) => string;
  /** Optional per-cell severity tint (sacred ok/warn/crit ramp). */
  sev?: (row: T) => Sev | undefined;
  render: (row: T) => ReactNode;
}

export interface DataTableProps<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  /** Scroll-viewport height (the table windows within this). Default 480. */
  height?: number | string;
  /** Row height in px; pass 24 for the compact density toggle. Default 28. */
  rowHeight?: number;
  /** Controlled global filter text (matched against column `text` accessors). */
  filter?: string;
  initialSort?: { key: string; dir: "asc" | "desc" };
  onRowClick?: (row: T) => void;
  /** Optional left-accent bar color per row (e.g. log severity). */
  rowAccent?: (row: T) => string | undefined;
  /** Optional extra class per row (e.g. a selected/master-detail highlight). */
  rowClassName?: (row: T) => string;
  /** Hover/active-revealed, right-docked per-row actions. */
  rowActions?: (row: T) => ReactNode;
  empty?: ReactNode;
  ariaLabel?: string;
  /** Allow the user to drag column borders to widen/narrow them. */
  resizable?: boolean;
}

const OVERSCAN = 12;

export default function DataTable<T>({
  rows,
  columns,
  rowKey,
  height = 480,
  rowHeight = 28,
  filter = "",
  initialSort,
  onRowClick,
  rowAccent,
  rowClassName,
  rowActions,
  empty,
  ariaLabel,
  resizable = false,
}: DataTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(typeof height === "number" ? height : 480);
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" } | null>(initialSort ?? null);
  const [active, setActive] = useState(0);
  // User-overridden column widths (px), keyed by column key, when resizable.
  const [colW, setColW] = useState<Record<string, number>>({});

  // Drag a column border: capture the header cell's current width, then track the
  // pointer and clamp to a sane minimum. Stops propagation so it never sorts.
  const startResize = (e: React.MouseEvent, key: string) => {
    e.preventDefault();
    e.stopPropagation();
    const th = (e.currentTarget as HTMLElement).parentElement;
    const startW = th ? th.getBoundingClientRect().width : 120;
    const startX = e.clientX;
    const onMove = (me: MouseEvent) => setColW((p) => ({ ...p, [key]: Math.max(60, Math.round(startW + (me.clientX - startX))) }));
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // The grid track template — shared verbatim by the header and every body row so
  // columns stay pixel-aligned. An extra zero-width track is NOT needed; row
  // actions overlay absolutely on the right.
  const template = useMemo(
    () =>
      columns
        .map((c) =>
          colW[c.key] != null
            ? `${colW[c.key]}px`
            : c.width === undefined
              ? "minmax(0,1fr)"
              : typeof c.width === "number"
                ? `${c.width}px`
                : c.width,
        )
        .join(" "),
    [columns, colW],
  );

  // Global filter, then sort. Both derive from column accessors so the consumer
  // declares behaviour once in the column defs.
  const view = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    let out = rows;
    if (needle) {
      out = rows.filter((r) =>
        columns.some((c) => (c.text?.(r) ?? "").toLowerCase().includes(needle)),
      );
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        const val = (r: T) => col.sortValue?.(r) ?? col.text?.(r) ?? "";
        const dir = sort.dir === "asc" ? 1 : -1;
        out = [...out].sort((a, b) => {
          const va = val(a);
          const vb = val(b);
          if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
          return String(va).localeCompare(String(vb)) * dir;
        });
      }
    }
    return out;
  }, [rows, columns, filter, sort]);

  // Keep the active row in range as the view shrinks/grows.
  useEffect(() => {
    if (active > view.length - 1) setActive(Math.max(0, view.length - 1));
  }, [view.length, active]);

  // Measure the scroll viewport so the window size tracks resizes/density.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => setViewport(el.clientHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const total = view.length * rowHeight;
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const last = Math.min(view.length, Math.ceil((scrollTop + viewport) / rowHeight) + OVERSCAN);
  const windowed = view.slice(first, last);

  const toggleSort = useCallback((key: string) => {
    setSort((s) =>
      s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );
  }, []);

  // Scroll a row index into view (used by keyboard nav).
  const reveal = useCallback(
    (i: number) => {
      const el = scrollRef.current;
      if (!el) return;
      const top = i * rowHeight;
      const bottom = top + rowHeight;
      if (top < el.scrollTop) el.scrollTop = top;
      else if (bottom > el.scrollTop + el.clientHeight) el.scrollTop = bottom - el.clientHeight;
    },
    [rowHeight],
  );

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!view.length) return;
    let next = active;
    switch (e.key) {
      case "ArrowDown": next = Math.min(view.length - 1, active + 1); break;
      case "ArrowUp": next = Math.max(0, active - 1); break;
      case "Home": next = 0; break;
      case "End": next = view.length - 1; break;
      case "Enter": onRowClick?.(view[active]); return;
      default: return;
    }
    e.preventDefault();
    setActive(next);
    reveal(next);
  };

  return (
    <div
      ref={scrollRef}
      className="dtv"
      role="grid"
      aria-label={ariaLabel}
      aria-rowcount={view.length}
      tabIndex={0}
      style={{ height, ["--dtv-row" as string]: `${rowHeight}px` }}
      onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      onKeyDown={onKeyDown}
    >
      <div className="dtv-head" role="row" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => {
          const sorted = sort?.key === c.key;
          return (
            <div
              key={c.key}
              role="columnheader"
              aria-sort={sorted ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
              className={`dtv-th${c.sortable ? " sortable" : ""}${sorted ? " sorted" : ""}`}
              style={{ textAlign: c.align ?? "left", position: resizable ? "relative" : undefined }}
              onClick={c.sortable ? () => toggleSort(c.key) : undefined}
            >
              {c.header}
              {c.sortable && (
                <span className="dtv-arrow">{sorted ? (sort!.dir === "asc" ? "▲" : "▼") : "↕"}</span>
              )}
              {resizable && (
                <span
                  role="separator"
                  aria-label="Resize column"
                  title="Drag to resize"
                  onMouseDown={(e) => startResize(e, c.key)}
                  onClick={(e) => e.stopPropagation()}
                  style={{ position: "absolute", top: 0, right: 0, width: 7, height: "100%", cursor: "col-resize" }}
                />
              )}
            </div>
          );
        })}
      </div>

      {view.length === 0 ? (
        <div className="dtv-empty">{empty ?? "No rows."}</div>
      ) : (
        <div className="dtv-body" style={{ height: total }}>
          {windowed.map((row, i) => {
            const idx = first + i;
            const accent = rowAccent?.(row);
            return (
              <div
                key={rowKey(row)}
                role="row"
                aria-rowindex={idx + 1}
                className={`dtv-row${idx === active ? " active" : ""}${onRowClick ? " clickable" : ""}${rowClassName ? " " + rowClassName(row) : ""}`}
                style={{
                  gridTemplateColumns: template,
                  transform: `translateY(${idx * rowHeight}px)`,
                  ...(accent ? { boxShadow: `inset 3px 0 0 ${accent}` } : null),
                }}
                onMouseEnter={() => setActive(idx)}
                onClick={() => onRowClick?.(row)}
              >
                {columns.map((c) => (
                  <div
                    key={c.key}
                    role="gridcell"
                    className="dtv-cell"
                    data-sev={c.sev?.(row)}
                    style={{ justifyContent: align(c.align) }}
                  >
                    {c.render(row)}
                  </div>
                ))}
                {rowActions && (
                  <div className="dtv-actions" onClick={(e) => e.stopPropagation()}>
                    {rowActions(row)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function align(a?: Align): string {
  return a === "right" ? "flex-end" : a === "center" ? "center" : "flex-start";
}
