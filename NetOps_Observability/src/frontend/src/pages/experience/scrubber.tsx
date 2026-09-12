// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// scrubber.tsx — the incident timeline scrubber.
//
// One axis carries every entry the server put on the incident's timeline plus
// the ranked changes, and a scrub control walks a cursor along it. The list
// under the axis shows only what had happened by the cursor, which is how an
// operator answers "what did we know at 14:12" without re-reading the whole
// story.
//
// TWO HONESTY RULES ARE BUILT INTO THE DRAWING.
//   1. An INFERRED entry is drawn as a hollow, dashed marker and rendered with
//      an italic dashed rule in the list. An inferred entry on a timeline that
//      looks measured is exactly how a story becomes a fact.
//   2. The axis spans the incident's own window. It is never stretched to the
//      first and last entry: a timeline that starts at the first evidence hides
//      how much of the window produced nothing.

import { useMemo, useState } from "react";

import { fmtDateTime } from "../../lib/time";
import type { DemChangeRelevance, DemTimelineEntry } from "../../services/api";
import { ProvenanceChip } from "./honest";
import AskIris from "../../components/AskIris";

export interface ScrubEntry {
  at: number;
  kind: string;
  summary: string;
  observation: string;
  source?: string;
  ref?: string;
}

const KIND_LABEL: Record<string, string> = {
  detected: "Detected",
  impact: "Impact",
  change: "Change",
  evidence: "Evidence",
  action: "Action",
  recovery: "Recovery",
};

/** Timeline entries + ranked changes on ONE axis, oldest first. A change that
 *  happened AFTER first impact is kept (an operator wants to see what was done
 *  during the incident) — the list says so rather than dropping it. */
export function buildEntries(
  timeline: DemTimelineEntry[] | undefined,
  changes: DemChangeRelevance[] | undefined,
): ScrubEntry[] {
  const out: ScrubEntry[] = [];
  for (const t of timeline ?? []) {
    const at = Date.parse(t.at);
    if (Number.isNaN(at)) continue;
    out.push({ at, kind: t.kind, summary: t.summary, observation: t.observation, source: t.source, ref: t.ref });
  }
  for (const c of changes ?? []) {
    const at = Date.parse(c.change.provenance?.event_at ?? "");
    if (Number.isNaN(at)) continue;
    out.push({
      at, kind: "change",
      summary: c.precedes_impact
        ? c.change.summary
        : `${c.change.summary} — recorded after the first impact, so it cannot have caused it`,
      observation: c.change.provenance?.observation ?? "unknown",
      source: c.change.provenance?.source,
      ref: c.change.id,
    });
  }
  return out.sort((a, b) => a.at - b.at);
}

export function TimelineScrubber({ entries, start, end, label }: {
  entries: ScrubEntry[];
  /** The incident window. Empty strings fall back to the entry extent, and the
   *  caption says so — a silently rescaled axis is a misleading axis. */
  start?: string;
  end?: string;
  label?: string;
}) {
  const bounds = useMemo(() => {
    const s = Date.parse(start ?? "");
    const e = Date.parse(end ?? "");
    const ats = entries.map((x) => x.at);
    const lo = Number.isNaN(s) ? Math.min(...ats, Date.now()) : s;
    const hi = Number.isNaN(e) ? Math.max(...ats, lo + 1) : e;
    return { lo, hi: hi > lo ? hi : lo + 1, declared: !Number.isNaN(s) && !Number.isNaN(e) };
  }, [entries, start, end]);

  const [cursor, setCursor] = useState(100);
  const cutoff = bounds.lo + ((bounds.hi - bounds.lo) * cursor) / 100;
  const shown = entries.filter((x) => x.at <= cutoff);

  if (entries.length === 0) {
    return (
      <p className="dx-note">
        No entry on this timeline.<AskIris topic="dem.absence-not-health" label="an empty timeline" />
      </p>
    );
  }

  const W = 1000, H = 64, PAD = 8;
  const x = (t: number) => PAD + ((t - bounds.lo) / (bounds.hi - bounds.lo)) * (W - PAD * 2);

  return (
    <div className="dx-scrub" role="group" aria-label={label ?? "Incident timeline"}>
      <svg className="dx-scrub-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"
        role="img"
        aria-label={`Timeline from ${fmtDateTime(new Date(bounds.lo))} to ${fmtDateTime(new Date(bounds.hi))}, ${entries.length} entries`}>
        <rect className="dx-scrub-window" x={PAD} y={16} width={W - PAD * 2} height={20} />
        <line className="dx-scrub-axis" x1={PAD} y1={26} x2={W - PAD} y2={26} />
        <line className="dx-scrub-axis" x1={x(cutoff)} y1={8} x2={x(cutoff)} y2={44} />
        {entries.map((e, i) => {
          const cx = x(e.at);
          const cls = `dx-scrub-mark--${e.observation === "observed" ? "observed"
            : e.observation === "inferred" ? "inferred"
              : e.observation === "simulated" ? "simulated" : "unknown"}`;
          return e.observation === "observed"
            ? <circle key={i} className={cls} cx={cx} cy={26} r={5} />
            : <rect key={i} className={cls} x={cx - 4} y={22} width={8} height={8} transform={`rotate(45 ${cx} 26)`} />;
        })}
        <text className="dx-scrub-tick" x={PAD} y={58}>{fmtDateTime(new Date(bounds.lo))}</text>
        <text className="dx-scrub-tick" x={W - PAD} y={58} textAnchor="end">{fmtDateTime(new Date(bounds.hi))}</text>
      </svg>

      <div className="dx-scrub-controls">
        <label htmlFor="dx-scrub-range">Scrub to</label>
        <input id="dx-scrub-range" type="range" min={0} max={100} value={cursor}
          onChange={(ev) => setCursor(Number(ev.target.value))}
          aria-label="Scrub the incident timeline" />
        <span className="dx-mono dx-subtle">{fmtDateTime(new Date(cutoff))}</span>
        <span className="dx-cap">{shown.length} of {entries.length}</span>
      </div>

      {!bounds.declared && (
        <p className="dx-cap">
          Axis spans the entries<AskIris topic="dem.timeline-window" label="the timeline axis" />
        </p>
      )}

      <ul className="dx-events">
        {shown.map((e, i) => (
          <li key={i} className={`dx-event${e.observation === "observed" ? "" : " dx-event--inferred"}`}>
            <span className="dx-event-at">
              {fmtDateTime(new Date(e.at))} · {KIND_LABEL[e.kind] ?? e.kind}
              {e.source ? ` · ${e.source}` : ""}
            </span>
            <span className="dx-event-summary">{e.summary}</span>
            <span><ProvenanceChip observation={e.observation} /></span>
          </li>
        ))}
      </ul>
    </div>
  );
}
