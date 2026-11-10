// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ViewNotices.tsx — the topology view's "what this map could not show" control.
//
// Owner 2026-11-10: a note on the map must never pop a paragraph. The view's
// conditions (tracker 290 unread evidence, a stale SD-WAN overlay, edges whose
// tunnels cannot be drawn) used to render as red role="alert" sentences beside
// the toolbar. They are now ONE compact chip that is always visible while a
// condition holds (so the map is never mistaken for complete, which is what 290
// requires) and says only a short headline. The why, the devices and the one
// action that fixes it open on click, in a popover the operator controls.

import { useEffect, useId, useRef, useState } from "react";
import type { TopologyNotice } from "../api/topologyTypes";

export type ViewNoticesProps = {
  notices?: TopologyNotice[];
  /** Headlines the producer could not structure; shown as headline-only notices. */
  degraded?: string[];
};

const RANK: Record<TopologyNotice["severity"], number> = { critical: 3, warning: 2, info: 1 };

/** Merge structured notices with any bare degraded headline they do not cover. */
export function mergeNotices(notices: TopologyNotice[] = [], degraded: string[] = []): TopologyNotice[] {
  const covered = new Set(notices.map((n) => n.headline));
  const bare: TopologyNotice[] = degraded
    .filter((d) => d && !covered.has(d))
    .map((d, i) => ({ id: `degraded.${i}`, severity: "warning", headline: d }));
  return [...notices, ...bare].sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}

export default function ViewNotices({ notices, degraded }: ViewNoticesProps) {
  const all = mergeNotices(notices, degraded);
  const [open, setOpen] = useState(false);
  const popId = useId();
  const wrapRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open]);

  if (all.length === 0) return null;
  const worst = all[0].severity;
  const label = all.length === 1 ? all[0].headline : `${all.length} map notices`;

  return (
    <span className="topo-notices" ref={wrapRef} role="status" data-testid="topo-view-notices">
      <button
        type="button"
        className={`topo-notices-chip sev-${worst}`}
        aria-expanded={open}
        aria-controls={popId}
        onClick={() => setOpen((v) => !v)}
        title="What this map could not show"
      >
        <span className="topo-notices-icon" aria-hidden="true">{worst === "info" ? "i" : "!"}</span>
        <span className="topo-notices-label">{label}</span>
      </button>
      {open && (
        <div id={popId} className="topo-notices-pop" role="dialog" aria-label="Map notices">
          <ul>
            {all.map((n) => (
              <li key={n.id} className={`sev-${n.severity}`} data-testid="topo-notice">
                <div className="topo-notice-head">{n.headline}</div>
                {n.detail && <p className="topo-notice-detail">{n.detail}</p>}
                {n.devices && n.devices.length > 0 && (
                  <div className="topo-notice-devices" aria-label="Devices">
                    {n.devices.map((d) => <span key={d} className="topo-notice-device">{d}</span>)}
                  </div>
                )}
                {n.action && (
                  <a className="topo-notice-action" href={n.action.path}>{n.action.label} →</a>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </span>
  );
}
