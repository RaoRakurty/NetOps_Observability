// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// MeasuredPaths — the measured path of a WAN circuit or tunnel row, where the
// row is (2026-11-22; until then a "Measured paths" tab of its own):
//
//   * PathCell   — the row's "Path" column: the worst path's state and hop count.
//   * PathPanel  — opened from a row: each of its paths hop by hop (the measured
//                  ribbon, first-loss hop marked, and the hop table), with the
//                  path's health against its own baseline and when it was traced.
//   * OtherPaths — the paths no row on this tab claims, collapsed, so nothing the
//                  prober measures is hidden.
//
// The rules (which path belongs to which row, what a path's state is) are in
// measuredFold.ts and unit-tested there.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { ProbePath } from "../../services/api";
import DataTable, { type Column } from "../../components/DataTable";
import AskIris from "../../components/AskIris";
import Icon from "../../components/Icon";
import { PathHealthCard } from "../../components/PathHealthList";
import NetworkPathView from "../../features/topology/components/NetworkPathView";
import { asOfText } from "../../tabs/tunnels.model";
import { probePathToView } from "./probePathView";
import { matchesSite } from "./pathsModel";
import {
  destText, hopsText, roleText, verdictText, type AttachedPath, type MeasuredPath,
} from "./measuredFold";

type Hop = ProbePath["hops"][number];

export function HopTable({ hops }: { hops: Hop[] }) {
  const cols: Column<Hop>[] = [
    { key: "ttl", header: "Hop", width: "56px", sortable: true, sortValue: (h) => h.ttl, render: (h) => `${h.ttl}` },
    { key: "ip", header: "Router", sortable: true, text: (h) => h.ip || "*", render: (h) => <span className="mono">{h.ip || "* (no reply)"}</span> },
    // A hop with no reply, or a prober that does not measure per-hop loss, has
    // no rtt_ms / loss_pct: guard them, never call toFixed on undefined.
    { key: "rtt", header: "RTT", align: "right", sortable: true, sortValue: (h) => h.rtt_ms ?? -1, render: (h) => (h.ip && h.rtt_ms != null ? `${h.rtt_ms.toFixed(1)} ms` : "—") },
    { key: "loss", header: "Loss", align: "right", sortable: true, sortValue: (h) => h.loss_pct ?? -1, render: (h) => (h.ip && h.loss_pct != null ? `${h.loss_pct.toFixed(0)}%` : "—") },
  ];
  return <DataTable<Hop> rows={hops} columns={cols} rowKey={(h) => `${h.ttl}-${h.ip}`} height={Math.min(420, 44 + hops.length * 28)} ariaLabel="Path hops" initialSort={{ key: "ttl", dir: "asc" }} />;
}

/** The chip for one path: its state, plus "route changed" when that is not already the state. */
function VerdictChip({ m }: { m: MeasuredPath }) {
  const v = verdictText(m);
  return <span className={`badge ${v.tone}`} data-testid="path-verdict">{v.text}</span>;
}

/** The row's "Path" cell: the worst of its paths, or a dash when none is measured. */
export function PathCell({ paths }: { paths: AttachedPath[] }) {
  if (paths.length === 0) return <span className="mini-meta" data-testid="path-cell">—</span>;
  const worst = paths[0].m;
  const more = paths.length - 1;
  return (
    <span className="mpath-cell" data-testid="path-cell" title={paths.map((p) => `${roleText(p)}: ${verdictText(p.m).text}`).join("\n")}>
      <VerdictChip m={worst} />
      <span className="mpath-hops">{hopsText(worst)}</span>
      {more > 0 && <span className="mpath-more">+{more}</span>}
    </span>
  );
}

/** One measured path, hop by hop, with its health and time. */
function PathDetail({ m, heading, now }: { m: MeasuredPath; heading: string; now: Date }) {
  const p = m.path;
  return (
    <section className="mpath-detail" data-testid="path-detail">
      <div className="mpath-detail-head">
        <h3>{heading}</h3>
        <VerdictChip m={m} />
        {p.changed && m.verdict !== "changed" && <span className="badge warn">Route changed</span>}
      </div>
      <p className="mpath-facts">
        {`From ${p.vantage_id ? `prober ${p.vantage_id}` : "the prober"} to ${destText(m)}`}
        {p.method ? ` · ${p.method.toUpperCase()}` : ""}
        {` · ${hopsText(m)}`}
        {asOfText(p.ts, now) ? ` · traced ${asOfText(p.ts, now)}` : ""}
      </p>
      <div className="paths-ribbon" data-testid="paths-ribbon">
        <NetworkPathView view={probePathToView(p)} rail={false} />
      </div>
      <HopTable hops={p.hops} />
      {m.health && <PathHealthCard p={m.health} />}
    </section>
  );
}

/** The side panel a row opens: every path that row claims, worst first. */
export function PathPanel({ title, paths, ends, onClose }: {
  title: string;
  paths: AttachedPath[] | null;
  /** A tunnel's two end devices, so "To End A" can name it. */
  ends?: { a?: string; b?: string };
  onClose: () => void;
}) {
  const open = !!paths && paths.length > 0;
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    if (!open) return;
    setNow(new Date());
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <>
      <div className={`help-scrim${open ? " open" : ""}`} onClick={onClose} aria-hidden="true" />
      <aside className={`help-panel paths-page mpath-panel${open ? " open" : ""}`} aria-hidden={!open} role="dialog"
        aria-modal="false" aria-label={`Measured path: ${title}`} data-testid="path-panel">
        <header className="help-head">
          <span className="help-title"><Icon name="info" size={16} />{title}</span>
          <div className="help-actions">
            <AskIris topic="path.traceroute" label="Measured path" />
            <button className="help-close" type="button" onClick={onClose} aria-label="Close measured path" title="Close (Esc)">
              <Icon name="close" size={16} />
            </button>
          </div>
        </header>
        {open && (
          <div className="mpath-body">
            {paths!.map((a) => <PathDetail key={a.m.key} m={a.m} heading={roleText(a, ends)} now={now} />)}
          </div>
        )}
      </aside>
    </>
  );
}

/**
 * The paths no row on this tab claims (a catalogue target that is not a WAN
 * target or a tunnel end), collapsed. The page's site filter applies by the
 * path's own site.
 */
export function OtherPaths({ paths, site, onOpen, children }: {
  paths: MeasuredPath[];
  site: string;
  onOpen: (m: MeasuredPath) => void;
  children?: ReactNode;
}) {
  const shown = useMemo(() => paths.filter((m) => matchesSite(site, m.path.site)), [paths, site]);
  const now = new Date();
  if (shown.length === 0) return null;
  return (
    <details className="mpath-other" data-testid="paths-other">
      <summary>Measured paths to other targets ({shown.length})</summary>
      {children}
      <table className="dp-tbl">
        <thead>
          <tr><th>Target</th><th>Site</th><th>Path</th><th>Traced</th></tr>
        </thead>
        <tbody>
          {shown.map((m) => (
            <tr key={m.key}>
              <th scope="row">
                <button type="button" className="mpath-open" onClick={() => onOpen(m)} data-testid="paths-other-open">
                  {destText(m)}
                </button>
              </th>
              <td>{m.path.site || "—"}</td>
              <td><span className="mpath-cell"><VerdictChip m={m} /><span className="mpath-hops">{hopsText(m)}</span></span></td>
              <td>{asOfText(m.path.ts, now) || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

/** One line when the paths read failed: the rows stay, their paths are unknown. */
export function PathsReadNote({ error }: { error: string | null }) {
  if (!error) return null;
  return <p className="proto-key" role="alert" data-testid="paths-read-error">{error} The Path column shows a dash.</p>;
}
