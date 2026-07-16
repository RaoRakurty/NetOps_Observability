// FeedBar — the honesty header for a live cloud signal feed (owner review #2).
//
// Answers, in one strip, the three questions every cloud table used to leave
// unanswered: WHAT WINDOW am I looking at (and can I change it), HOW MUCH am I
// seeing of what exists, and IS THIS LIVE / how fresh is it.
//
// Built on the existing design system: the shared `Segmented` control from
// components/ui (same control as the App Detail view switcher), the ao-* panel
// classes and var(--*) tokens, so it themes light/dark for free.

import { useEffect, useState } from "react";
import { Segmented } from "../../components/ui";
import { CLOUD_RANGES, freshnessText, FeedCount } from "./range";

// A ticking clock for the freshness label. Without it "updated 8s ago" freezes at
// its first paint and becomes a lie the moment the user stops interacting.
export function useNow(everyMs = 5_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(t);
  }, [everyMs]);
  return now;
}

export function FeedBar({ minutes, onRange, count, loadedAt, onRefresh, busy, label }: {
  minutes: number;
  onRange: (minutes: number) => void;
  /** shown/total for the current window — rendered verbatim (see range.feedCount). */
  count: FeedCount;
  /** epoch ms of the last successful fetch — the freshness anchor. */
  loadedAt: number;
  onRefresh: () => void;
  busy?: boolean;
  /** accessible name for the range control, e.g. "Alerts time range". */
  label: string;
}) {
  const now = useNow();
  return (
    <div className="ao-feedbar">
      <Segmented
        value={String(minutes)}
        onChange={(v) => onRange(Number(v))}
        ariaLabel={label}
        options={CLOUD_RANGES.map((r) => ({ value: String(r.minutes), label: r.label }))}
      />
      {/* role=status: the count changes as the range changes, and a screen-reader
          user must hear the new "showing N of M" without chasing the table. */}
      <span className="ao-feedbar-count" role="status">{count.text}</span>
      <span className="ao-feedbar-live">
        <span className="ao-live-dot" aria-hidden="true" />
        <span className="ao-live-l">live · {freshnessText(loadedAt, now)}</span>
      </span>
      <button className="ao-btn ao-btn--sm" onClick={onRefresh} disabled={busy}
        aria-label="Refresh this feed now">
        {busy ? "Refreshing…" : "Refresh"}
      </button>
    </div>
  );
}
