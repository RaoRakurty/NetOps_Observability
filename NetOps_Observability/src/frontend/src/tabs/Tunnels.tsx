// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useState } from "react";
import { matchesSite } from "../pages/paths/pathsModel";
import { api, Tunnel, TunnelEnd, TunnelsResponse } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { Group } from "../components/board/panels";
import {
  asOfText, caseHref, cellFilter, CellFilter, endText, matrixGrid, oldestQualityAsOf, rowInCell,
  rowState, searchText, stateLabel, stateOrder, stateTone,
} from "./tunnels.model";

// Heat severity — lower is better for latency/jitter/loss, higher for QoE.
// Maps onto the sacred ok/warn/crit ramp the DataTable tints cells with.
// Exported (with coerce/fmtTunnelUptime) for the Device Monitoring tunnel section.
export const latSev = (ms: number): Sev => (ms < 50 ? "ok" : ms < 150 ? "warn" : "crit");
const jitSev = (ms: number): Sev => (ms < 30 ? "ok" : ms < 60 ? "warn" : "crit");
export const lossSev = (pct: number): Sev => (pct < 1 ? "ok" : pct < 3 ? "warn" : "crit");
const qoeSev = (q: number): Sev => (q >= 8 ? "ok" : q >= 5 ? "warn" : "crit");

// ClickHouse JSON returns UInt64 (uptime) as a string and Float32 as a number;
// coerce every numeric field so arithmetic and formatting are safe.
export function coerce(t: Tunnel): Tunnel {
  return {
    ...t,
    latency_ms: Number(t.latency_ms) || 0,
    jitter_ms: Number(t.jitter_ms) || 0,
    loss_pct: Number(t.loss_pct) || 0,
    qoe: Number(t.qoe) || 0,
    uptime_s: Number(t.uptime_s) || 0,
  };
}

export function fmtTunnelUptime(s: number): string {
  if (s <= 0) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export interface TunnelKpis {
  up: number;
  down: number;
  /** Folded SD-WAN tunnels whose two ends report different states. */
  disagree: number;
  /** Rows whose quality (latency/loss) is actually measured. */
  measured: number;
  /** Averages over MEASURED rows only; null when none is measured. */
  avgLatency: number | null;
  avgLoss: number | null;
}

// The summary tiles. Latency and loss average only the rows whose quality is
// measured: an SD-WAN row with no controller reading carries measured:false and
// zeros, and dividing by every row read a fleet of unmeasured tunnels as a
// healthy 0 ms / 0 % (Paths redesign P0, 2026-11-20). Up/down/disagree count
// every row, by the folded state when the server sent one (Paths P4).
export function tunnelKpis(rows: Tunnel[]): TunnelKpis {
  const m = rows.filter((t) => t.measured !== false);
  const avg = (f: (t: Tunnel) => number) => (m.length ? m.reduce((n, t) => n + f(t), 0) / m.length : null);
  return {
    up: rows.filter((t) => rowState(t) === "up").length,
    down: rows.filter((t) => rowState(t) === "down").length,
    disagree: rows.filter((t) => rowState(t) === "disagree").length,
    measured: m.length,
    avgLatency: avg((t) => t.latency_ms),
    avgLoss: avg((t) => t.loss_pct),
  };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** One end of a tunnel: device prominent, colour a mono suffix, site underneath. */
function EndCell({ end, device, addr }: { end?: TunnelEnd; device: string; addr: string }) {
  const who = end ? end.device || end.system_ip || device : device;
  const colour = end ? end.color : addr;
  const site = end?.site?.label;
  return (
    <span className="tun-end" title={[who, colour, site].filter(Boolean).join(" · ")}>
      <span className="tun-end-who">
        {who || "—"}
        {colour && <span className="mono tun-end-colour">{colour}</span>}
      </span>
      {site && <span className="tun-end-site">{site}</span>}
    </span>
  );
}

function SiteMatrix({ res, selected, onSelect }: {
  res: TunnelsResponse | null;
  selected: CellFilter | null;
  onSelect: (f: CellFilter | null) => void;
}) {
  const m = res?.matrix;
  const grid = useMemo(() => matrixGrid(m), [m]);
  if (!m || grid.sites.length === 0) {
    return <div className="empty" data-testid="tunnels-matrix-empty">No tunnel ends are placed at sites yet.</div>;
  }
  const isSel = (a: string, b: string) =>
    !!selected && ((selected.a === a && selected.b === b) || (selected.a === b && selected.b === a));
  return (
    <>
      <div className="tun-matrix-wrap">
        <table className="tun-matrix" data-testid="tunnels-matrix" aria-label="Tunnels by site pair">
          <thead>
            <tr>
              <th scope="col"><span className="sr-only">Site</span></th>
              {grid.sites.map((s) => <th key={s.key} scope="col">{s.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {grid.sites.map((row) => (
              <tr key={row.key}>
                <th scope="row">{row.label}</th>
                {grid.sites.map((col) => {
                  const c = grid.cellAt(row.key, col.key);
                  if (!c) return <td key={col.key} className="tun-cell-none" aria-label={`${row.label} to ${col.label}: no tunnels`}>·</td>;
                  const tone = stateTone(c.state);
                  const sel = isSel(row.label, col.label);
                  const parts = [plural(c.tunnels, "tunnel")];
                  if (c.down) parts.push(`${c.down} down`);
                  if (c.disagree) parts.push(`${c.disagree} with ends disagreeing`);
                  if (c.cases.length) parts.push(plural(c.cases.length, "open case"));
                  const label = `${row.label} to ${col.label}: ${parts.join(", ")}`;
                  return (
                    <td key={col.key}>
                      <button
                        type="button"
                        className={`tun-cell t-${tone}${sel ? " is-selected" : ""}`}
                        data-testid="tunnels-matrix-cell"
                        data-state={c.state}
                        aria-pressed={sel}
                        aria-label={label}
                        title={label}
                        onClick={() => onSelect(sel ? null : cellFilter(m, c))}
                      >
                        <span className="tun-cell-n">{c.tunnels}</span>
                        {c.down > 0 && <span className="tun-cell-bad">· {c.down} down</span>}
                        {c.disagree > 0 && <span className="tun-cell-bad">· {c.disagree} disagree</span>}
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(m.unplaced_tunnels > 0 || m.truncated) && (
        <p className="proto-key" data-testid="tunnels-matrix-foot">
          {m.unplaced_tunnels > 0 && `${plural(m.unplaced_tunnels, "tunnel")} with an end at no site. `}
          {m.truncated && `The ${grid.sites.length} worst of ${m.sites_total} sites.`}
        </p>
      )}
    </>
  );
}

export default function Tunnels({ site = "", onSites }: {
  /** The Paths page's site filter (a siteKey): a tunnel with EITHER end there. "" is All sites. */
  site?: string;
  /** Reports the sites the tunnel ends name, for the Paths page's site list. */
  onSites?: (labels: string[]) => void;
} = {}) {
  const [res, setRes] = useState<TunnelsResponse | null>(null);
  const [rows, setRows] = useState<Tunnel[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [cell, setCell] = useState<CellFilter | null>(null);
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.tunnels(500, undefined, { matrix: true });
        if (alive) {
          setRes(r ?? null);
          setRows((r?.data ?? []).map(coerce));
          setNow(new Date());
          setErr(null);
        }
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    onSites?.(rows.flatMap((t) => [t.a?.site?.label ?? "", t.b?.site?.label ?? ""]));
  }, [rows, onSites]);
  // The page's site filter scopes the tiles AND the table; the matrix keeps the
  // whole picture so a site's neighbours stay visible.
  const scoped = useMemo(
    () => rows.filter((t) => matchesSite(site, t.a?.site?.label, t.b?.site?.label)),
    [rows, site],
  );
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return scoped.filter((t) => (!cell || rowInCell(t, cell)) && (!needle || searchText(t).includes(needle)));
  }, [scoped, q, cell]);

  const columns = useMemo<Column<Tunnel>[]>(() => [
    { key: "type", header: "Type", width: 84, text: (t) => t.type ?? "",
      render: (t) => <span className="badge">{t.type || "—"}</span> },
    { key: "a", header: "End A", width: "17%", sortable: true,
      text: (t) => endText(t.a, t.local_device), sortValue: (t) => t.a?.device || t.local_device || "",
      render: (t) => <EndCell end={t.a} device={t.local_device} addr={t.local_addr} /> },
    { key: "b", header: "End B", width: "17%", sortable: true,
      text: (t) => endText(t.b, t.remote_device), sortValue: (t) => t.b?.device || t.remote_device || "",
      render: (t) => <EndCell end={t.b} device={t.remote_device} addr={t.remote_addr} /> },
    { key: "state", header: "State", width: 128, sortable: true,
      text: (t) => stateLabel(rowState(t)), sortValue: (t) => stateOrder(rowState(t)),
      render: (t) => (
        <span className="tun-state">
          <span className={`badge ${stateTone(rowState(t))}`} data-testid="tunnel-state">{stateLabel(rowState(t))}</span>
          {t.ends_reported === 1 && <span className="tun-one-end">one end reporting</span>}
        </span>
      ) },
    { key: "latency", header: "Latency", width: 112, align: "right", sortable: true,
      sortValue: (t) => t.latency_ms, sev: (t) => (t.measured === false ? undefined : latSev(t.latency_ms)),
      render: (t) => (t.measured === false ? "—" : `${t.latency_ms.toFixed(1)} ms`) },
    { key: "jitter", header: "Jitter", width: 100, align: "right", sortable: true,
      sortValue: (t) => t.jitter_ms, sev: (t) => (t.measured === false ? undefined : jitSev(t.jitter_ms)),
      render: (t) => (t.measured === false ? "—" : `${t.jitter_ms.toFixed(1)} ms`) },
    { key: "loss", header: "Loss", width: 92, align: "right", sortable: true,
      sortValue: (t) => t.loss_pct, sev: (t) => (t.measured === false ? undefined : lossSev(t.loss_pct)),
      render: (t) => (t.measured === false ? "—" : `${t.loss_pct.toFixed(2)} %`) },
    { key: "qoe", header: "QoE", width: 84, align: "right", sortable: true,
      sortValue: (t) => t.qoe, sev: (t) => (t.measured === false ? undefined : qoeSev(t.qoe)),
      render: (t) => (t.measured === false ? "—" : t.qoe.toFixed(1)) },
    { key: "asof", header: "Quality as of", width: 176, sortable: true,
      sortValue: (t) => t.quality?.as_of ?? "",
      render: (t) => <span data-testid="tunnel-asof">{(t.measured !== false && asOfText(t.quality?.as_of, now)) || "—"}</span> },
    { key: "case", header: "Case", width: 128,
      text: (t) => t.case?.id ?? "",
      render: (t) => (t.case ? (
        <a className="badge warn" data-testid="tunnel-case" href={caseHref(t.case.id)} title="Open the case in RCA">
          {t.case.tier ? `${t.case.tier} case` : "open case"}
        </a>
      ) : "—") },
  ], [now]);

  const { up, down, disagree, measured, avgLatency: avgLat, avgLoss } = tunnelKpis(scoped);
  const asOf = asOfText(oldestQualityAsOf(scoped.filter((t) => t.measured !== false)), now);
  const measuredFoot = measured ? `across ${plural(measured, "measured tunnel")}` : "quality not measured";
  const total = site ? scoped.length : res?.total ?? rows.length;
  const notes: string[] = [];
  if (res?.quality?.status === "unavailable") notes.push("Path quality could not be read, so quality shows a dash.");
  if (res?.cases?.status === "unavailable") notes.push("Open cases could not be read.");
  if (res?.truncated) notes.push(`Showing ${rows.length} of ${total} tunnels.`);

  return (
    <div className="dm-board paths-page tunnels-page">
      <h2>Tunnels</h2>
      {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

      <div className="stat-grid">
        <div className={`stat ${up ? "s-good" : "s-muted"}`}>
          <span className="stat-label">Tunnels up</span>
          <span className="stat-value">{up}</span>
          <span className="stat-foot">of {total}</span>
        </div>
        <div className={`stat ${down ? "s-bad" : disagree ? "s-warn" : "s-muted"}`} data-testid="tunnels-down">
          <span className="stat-label">Tunnels down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-foot">{disagree ? `${plural(disagree, "tunnel")} with ends disagreeing` : rows.length ? `${down} impaired` : "none reported"}</span>
        </div>
        <div className={`stat ${avgLat != null ? (avgLat < 150 ? "s-good" : "s-warn") : "s-muted"}`} data-testid="tunnels-avg-latency">
          <span className="stat-label">Avg latency</span>
          <span className="stat-value">
            {avgLat != null ? avgLat.toFixed(0) : "—"}
            {avgLat != null ? <span className="stat-unit"> ms</span> : null}
          </span>
          <span className="stat-foot">{measuredFoot}</span>
        </div>
        <div className={`stat ${avgLoss != null ? (avgLoss < 1 ? "s-good" : "s-warn") : "s-muted"}`} data-testid="tunnels-avg-loss">
          <span className="stat-label">Avg loss</span>
          <span className="stat-value">
            {avgLoss != null ? avgLoss.toFixed(2) : "—"}
            {avgLoss != null ? <span className="stat-unit"> %</span> : null}
          </span>
          <span className="stat-foot">{asOf || measuredFoot}</span>
        </div>
      </div>

      {notes.length > 0 && (
        <p className="proto-key" data-testid="tunnels-notes">{notes.join(" ")}</p>
      )}

      <Group title="Site matrix" hue="var(--mod-network)">
        <SiteMatrix res={res} selected={cell} onSelect={setCell} />
      </Group>

      <Group title="Tunnels" hue="var(--mod-metrics)">
        <div className="dt-toolbar">
          <label className="dt-search">
            <span className="omni-icon">⌕</span>
            <input
              placeholder="Search tunnels, devices, sites…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </label>
          {cell && (
            <button type="button" className="btn-ghost tun-filter" data-testid="tunnels-cell-filter" onClick={() => setCell(null)}>
              {cell.a === cell.b ? `Within ${cell.a}` : `${cell.a} ↔ ${cell.b}`} ✕
            </button>
          )}
          <span className="dt-count">
            {filtered.length} of {scoped.length} tunnels
          </span>
        </div>

        {rows.length === 0 ? (
          <div className="empty" data-testid="tunnels-empty">
            No tunnels reported yet. SD-WAN tunnels come from{" "}
            <a href="#/infrastructure/nms">Infrastructure › NMS Integrations</a>.
          </div>
        ) : (
          <DataTable<Tunnel>
            rows={filtered}
            columns={columns}
            rowKey={(t) => t.id}
            rowHeight={50}
            height="60vh"
            ariaLabel="Tunnels"
            initialSort={{ key: "state", dir: "asc" }}
            empty="No tunnels match this filter."
          />
        )}
      </Group>
    </div>
  );
}
