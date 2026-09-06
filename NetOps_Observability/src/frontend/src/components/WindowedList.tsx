// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// WindowedList — the list counterpart to components/DataTable's windowing.
//
// DataTable already keeps big TABLES flat by rendering only the rows in view.
// Plain lists beside the canvas (the topology device inventory, and any list
// like it) had no such primitive, so they rendered a DOM node per row for the
// whole fleet: a 1,000-device view built ~15,000 elements before the operator
// could interact with anything.
//
// This is that primitive, hand-rolled on the same technique for the same reason
// the table was (no virtualization dependency in package.json, and §6 says
// stdlib/first-party unless a library is foundational — windowing a list is 60
// lines, not a library):
//
//   - the scroller holds one spacer of the FULL height, so the scrollbar is
//     honest about how much list there is;
//   - only the slice intersecting the viewport (plus overscan) is rendered,
//     each absolutely positioned at index * rowHeight;
//   - the viewport is measured with a ResizeObserver, so a resized or collapsed
//     panel windows correctly rather than over- or under-rendering.
//
// Rows must be a FIXED height (`rowHeight`) — that is what makes the mapping
// from scroll offset to index exact, and it is what the callers' rows already
// are. A variable-height list is deliberately out of scope.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";

export interface WindowedListProps<T> {
  items: T[];
  /** Fixed row pitch in px (row height including its own margin). */
  rowHeight: number;
  /** Stable identity per item — used as the React key. */
  itemKey: (item: T, index: number) => string;
  /** Renders one row. It MUST occupy exactly `rowHeight` px. */
  renderItem: (item: T, index: number) => ReactNode;
  /** Class on the scrolling viewport. */
  className?: string;
  /** Rows rendered beyond each edge of the viewport. */
  overscan?: number;
  /** Shown in place of the list when `items` is empty. */
  empty?: ReactNode;
  role?: string;
  ariaLabel?: string;
}

export default function WindowedList<T>({
  items,
  rowHeight,
  itemKey,
  renderItem,
  className,
  overscan = 8,
  empty,
  role,
  ariaLabel,
}: WindowedListProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(0);

  // Measure the scroll viewport so the window tracks panel resizes. Until the
  // first measurement lands, `viewport` is 0 and only the overscan renders —
  // which is correct for one frame and settles immediately.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => setViewport(el.clientHeight);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // A shorter list must not leave the scroller parked past its own end (which
  // would render an empty window after a filter narrows the list).
  const total = items.length * rowHeight;
  useEffect(() => {
    const el = scrollRef.current;
    if (el && el.scrollTop > total) {
      el.scrollTop = 0;
      setScrollTop(0);
    }
  }, [total]);

  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const last = Math.min(items.length, Math.ceil((scrollTop + viewport) / rowHeight) + overscan);
  const windowed = useMemo(() => items.slice(first, last), [items, first, last]);

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop((e.target as HTMLDivElement).scrollTop);
  }, []);

  if (items.length === 0 && empty !== undefined) {
    return <div className={className} role={role} aria-label={ariaLabel}>{empty}</div>;
  }

  return (
    <div
      ref={scrollRef}
      className={className}
      role={role}
      aria-label={ariaLabel}
      onScroll={onScroll}
      style={{ overflowY: "auto", position: "relative" }}
    >
      {/* Full-height spacer: the scrollbar reflects the whole list, not the window. */}
      <div style={{ height: total, position: "relative" }}>
        {windowed.map((item, i) => {
          const idx = first + i;
          return (
            <div
              key={itemKey(item, idx)}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: rowHeight,
                transform: `translateY(${idx * rowHeight}px)`,
              }}
            >
              {renderItem(item, idx)}
            </div>
          );
        })}
      </div>
    </div>
  );
}
