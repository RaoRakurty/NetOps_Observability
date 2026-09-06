import { useEffect, useMemo, useState } from "react";
import { api, Tunnel } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";

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

export default function Tunnels() {
  const [rows, setRows] = useState<Tunnel[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const res = await api.tunnels(500);
        if (alive) {
          setRows((res?.data ?? []).map(coerce));
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

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((t) =>
      [t.id, t.type, t.local_device, t.local_addr, t.remote_device, t.remote_addr, t.status]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [rows, q]);

  // Endpoint cell: device prominent, address a dimmed mono suffix on one line.
  const endpoint = (device: string, addr: string) => (
    <span title={`${device || "—"}${addr ? ` · ${addr}` : ""}`}>
      {device || "—"}
      {addr && <span className="mini-meta" style={{ marginLeft: 6, fontFamily: "var(--font-mono, monospace)" }}>{addr}</span>}
    </span>
  );

  const columns = useMemo<Column<Tunnel>[]>(() => [
    { key: "type", header: "Type", width: 92, text: (t) => t.type ?? "",
      render: (t) => <span className="badge">{t.type || "—"}</span> },
    { key: "local", header: "Local", width: "18%", sortable: true,
      text: (t) => `${t.local_device} ${t.local_addr}`, sortValue: (t) => t.local_device || "",
      render: (t) => endpoint(t.local_device, t.local_addr) },
    { key: "remote", header: "Remote", width: "18%", sortable: true,
      text: (t) => `${t.remote_device} ${t.remote_addr}`, sortValue: (t) => t.remote_device || "",
      render: (t) => endpoint(t.remote_device, t.remote_addr) },
    { key: "latency", header: "Latency", width: 96, align: "right", sortable: true,
      sortValue: (t) => t.latency_ms, sev: (t) => latSev(t.latency_ms),
      render: (t) => `${t.latency_ms.toFixed(1)} ms` },
    { key: "jitter", header: "Jitter", width: 90, align: "right", sortable: true,
      sortValue: (t) => t.jitter_ms, sev: (t) => jitSev(t.jitter_ms),
      render: (t) => `${t.jitter_ms.toFixed(1)} ms` },
    { key: "loss", header: "Loss", width: 84, align: "right", sortable: true,
      sortValue: (t) => t.loss_pct, sev: (t) => lossSev(t.loss_pct),
      render: (t) => `${t.loss_pct.toFixed(2)} %` },
    { key: "qoe", header: "QoE", width: 70, align: "right", sortable: true,
      sortValue: (t) => t.qoe, sev: (t) => qoeSev(t.qoe),
      render: (t) => t.qoe.toFixed(1) },
    { key: "uptime", header: "Uptime", width: 92, align: "right", sortable: true,
      sortValue: (t) => t.uptime_s, render: (t) => fmtTunnelUptime(t.uptime_s) },
    { key: "status", header: "Status", width: 86, sortable: true,
      text: (t) => t.status ?? "", sortValue: (t) => t.status ?? "",
      render: (t) => <span className={`badge ${t.status === "up" ? "good" : "bad"}`}>{t.status || "?"}</span> },
  ], []);

  const up = rows.filter((t) => t.status === "up").length;
  const down = rows.filter((t) => t.status === "down").length;
  const avgLat = rows.length
    ? rows.reduce((n, t) => n + t.latency_ms, 0) / rows.length
    : 0;
  const avgLoss = rows.length
    ? rows.reduce((n, t) => n + t.loss_pct, 0) / rows.length
    : 0;

  return (
    <div className="card">
      <h2>Tunnels</h2>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className={`stat ${up ? "s-good" : "s-muted"}`}>
          <span className="stat-label">Tunnels up</span>
          <span className="stat-value">{up}</span>
          <span className="stat-foot">of {rows.length}</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Tunnels down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-foot">{rows.length ? `${down} impaired` : "none reported"}</span>
        </div>
        <div className={`stat ${rows.length ? (avgLat < 150 ? "s-good" : "s-warn") : "s-muted"}`}>
          <span className="stat-label">Avg latency</span>
          <span className="stat-value">
            {rows.length ? avgLat.toFixed(0) : "—"}
            {rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> ms</span> : null}
          </span>
          <span className="stat-foot">across tunnels</span>
        </div>
        <div className={`stat ${rows.length ? (avgLoss < 1 ? "s-good" : "s-warn") : "s-muted"}`}>
          <span className="stat-label">Avg loss</span>
          <span className="stat-value">
            {rows.length ? avgLoss.toFixed(2) : "—"}
            {rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> %</span> : null}
          </span>
          <span className="stat-foot">packet loss</span>
        </div>
      </div>

      <div className="dt-toolbar">
        <label className="dt-search">
          <span className="omni-icon">⌕</span>
          <input
            placeholder="Search tunnels, devices, addresses…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <span className="dt-count">
          {filtered.length} of {rows.length} tunnels
        </span>
      </div>

      {rows.length === 0 ? (
        <div className="empty">
          No tunnels reported. IPsec / SD-WAN tunnel state appears here once a
          collector populates it from device telemetry.
        </div>
      ) : (
        <DataTable<Tunnel>
          rows={filtered}
          columns={columns}
          rowKey={(t) => t.id}
          height="60vh"
          ariaLabel="Tunnels"
          initialSort={{ key: "loss", dir: "desc" }}
          empty="No tunnels match this filter."
        />
      )}
    </div>
  );
}
