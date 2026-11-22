// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PathData — the "Path data" drawer of Investigate → Paths (Paths redesign P5),
// modelled on Explore → Flows' "About this data": which of the four sources
// behind the tabs are on, and the console page where each is turned on. Read
// once each time the drawer opens; a source that cannot be read says so and is
// never shown as off. Every number is the caller's own workspace's: the three
// reads are tenant-scoped on the server.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import AskIris from "../../components/AskIris";
import Icon from "../../components/Icon";
import { pathDataItems, type PathDataFacts, type SourceState } from "./pathsModel";

const EMPTY: PathDataFacts = {
  pathDiscovery: null, activeProbe: null, tracing: null, tunnels: null, wanInterfaces: null, wanMeasured: null,
};

const STATE_WORD: Record<SourceState, string> = { on: "On", off: "Off", unknown: "Unknown" };
const STATE_TONE: Record<SourceState, string> = { on: "good", off: "warn", unknown: "" };

export default function PathData({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [facts, setFacts] = useState<PathDataFacts>(EMPTY);
  const [reading, setReading] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    setReading(true);
    const next: PathDataFacts = { ...EMPTY };
    Promise.allSettled([
      api.probeTargetSuggestions().then((s) => {
        next.pathDiscovery = !!s.path_discovery;
        next.activeProbe = !!s.active_probe;
        next.tracing = s.tracing ?? 0;
      }),
      api.tunnels(1).then((t) => { next.tunnels = t.total ?? t.rows ?? 0; }),
      api.wanInterfaces().then((w) => {
        const rows = w.interfaces ?? [];
        next.wanInterfaces = rows.length;
        next.wanMeasured = rows.filter((r) => r.has_latency || r.has_loss).length;
      }),
    ]).then(() => {
      if (alive) { setFacts(next); setReading(false); }
    });
    return () => { alive = false; };
  }, [open]);

  const items = pathDataItems(facts);

  return (
    <>
      <div className={`help-scrim${open ? " open" : ""}`} onClick={onClose} aria-hidden="true" />
      <aside className={`help-panel paths-data${open ? " open" : ""}`} aria-hidden={!open} role="dialog"
        aria-modal="false" aria-label="Path data" data-testid="paths-data">
        <header className="help-head">
          <span className="help-title"><Icon name="info" size={16} />Path data</span>
          <div className="help-actions">
            <AskIris topic="paths.data" label="Path data" />
            <button className="help-close" type="button" onClick={onClose} aria-label="Close Path data" title="Close (Esc)">
              <Icon name="close" size={16} />
            </button>
          </div>
        </header>
        {open && (
          <div className="paths-data-body">
            {reading && <p className="paths-data-text">Reading…</p>}
            <ol className="paths-data-list">
              {items.map((it) => (
                <li key={it.id} data-testid={`paths-data-${it.id}`} data-state={it.state}>
                  <div className="paths-data-row">
                    <h3>{it.title}</h3>
                    <span className={`badge ${STATE_TONE[it.state]}`}>{STATE_WORD[it.state]}</span>
                  </div>
                  <p className="paths-data-text">{it.text}</p>
                  {it.state !== "on" && (
                    <p className="paths-data-text">Turn on: <a href={it.href}>{it.where}</a></p>
                  )}
                </li>
              ))}
            </ol>
          </div>
        )}
      </aside>
    </>
  );
}
