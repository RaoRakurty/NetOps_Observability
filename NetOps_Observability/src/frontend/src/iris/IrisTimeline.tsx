// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisTimeline — the chronological "what happened when" list for Iris answers
// (tracker 337 N-E3, design Part 2 §27).
//
// Generalised from the RCA workspace's EventTimeline (components/rca/
// RcaWorkspace.tsx): same ordered-list semantics, same <time dateTime>, same
// "show the date only when the day changes" rule, same native <details> collapse.
// What it adds:
//   · RESTRAINED ACCENTS — only root cause, incident start, recovery, critical
//     change and high-confidence evidence get colour, and each accent also
//     carries a WORD ("Root cause") so meaning is never colour-only (WCAG 1.4.1).
//     Every other event is neutral.
//   · Drill-down — an event can be selected (opens its detail) or link to its
//     entity through the safe link map. No dead ends.
//   · Honest gaps — events without a real timestamp are not placed on the line;
//     the list says how many were left off instead of inventing a time.
//
// Every label/detail is untrusted text rendered as an escaped React text node.

import { useMemo } from "react";
import { fmtDate, fmtDateTime, fmtTime, parseTs } from "../lib/time";
import type { HighlightKind } from "./presentation";
import { SafeLink } from "./links";

export type TimelineAccent = "cause" | "start" | "recovery" | "critical" | "evidence";

export interface TimelineEvent {
  id: string;
  ts: string | number;
  label: string;
  detail?: string;
  accent?: TimelineAccent;
  /** An entity to open — rendered through the safe link map. */
  link?: { kind: string; id: string };
}

const ACCENT_WORD: Record<TimelineAccent, string> = {
  cause: "Root cause",
  start: "Incident start",
  recovery: "Recovery",
  critical: "Critical change",
  evidence: "Strong evidence",
};

export function accentForHighlight(k: HighlightKind | undefined): TimelineAccent | undefined {
  switch (k) {
    case "root_cause":
      return "cause";
    case "incident_start":
      return "start";
    case "recovery":
      return "recovery";
    case "critical_change":
      return "critical";
    case "high_confidence":
      return "evidence";
    default:
      return undefined;
  }
}

export default function IrisTimeline({
  events,
  onSelect,
  ariaLabel = "Timeline",
}: {
  events: TimelineEvent[];
  onSelect?: (e: TimelineEvent) => void;
  ariaLabel?: string;
}) {
  const { placed, undated } = useMemo(() => {
    const withTime: { e: TimelineEvent; d: Date }[] = [];
    let missing = 0;
    for (const e of events) {
      const d = parseTs(e.ts);
      if (d) withTime.push({ e, d });
      else missing++;
    }
    withTime.sort((a, b) => a.d.getTime() - b.d.getTime());
    return { placed: withTime, undated: missing };
  }, [events]);

  if (placed.length === 0) {
    return (
      <p className="iris-empty" role="status">
        {undated > 0
          ? `No event in this answer has a recorded time, so none can be placed on a timeline (${undated} left off).`
          : "No events in this window."}
      </p>
    );
  }

  const firstDay = fmtDate(placed[0].d);
  return (
    <details className="iris-tl" open>
      <summary className="iris-tl-summary">
        {placed.length} event{placed.length === 1 ? "" : "s"} · oldest first
      </summary>
      <ol className="iris-tl-list" aria-label={ariaLabel}>
        {placed.map(({ e, d }, i) => {
          const sameDay = fmtDate(d) === firstDay;
          const body = (
            <>
              <span className="iris-tl-label">{e.label}</span>
              {e.detail && <span className="iris-tl-detail"> · {e.detail}</span>}
            </>
          );
          return (
            <li key={`${e.id}-${i}`} className={`iris-tl-item${e.accent ? ` accent-${e.accent}` : ""}`}>
              <time className="iris-tl-time" dateTime={d.toISOString()} title={fmtDateTime(d)}>
                {sameDay ? fmtTime(d) : fmtDateTime(d)}
              </time>
              <span className="iris-tl-dot" aria-hidden="true" />
              <span className="iris-tl-text">
                {e.accent && <span className="iris-tl-tag">{ACCENT_WORD[e.accent]}</span>}
                {onSelect ? (
                  <button type="button" className="iris-tl-open" onClick={() => onSelect(e)}>
                    {body}
                  </button>
                ) : e.link ? (
                  <SafeLink kind={e.link.kind} id={e.link.id}>
                    {body}
                  </SafeLink>
                ) : (
                  body
                )}
              </span>
            </li>
          );
        })}
      </ol>
      {undated > 0 && (
        <p className="iris-note">
          {undated} event{undated === 1 ? " has" : "s have"} no recorded time and {undated === 1 ? "is" : "are"} not placed on the timeline.
        </p>
      )}
    </details>
  );
}
