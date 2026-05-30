import { useEffect, useMemo, useState } from "react";
import { api, Tunnel } from "../services/api";

// Heat classes — lower is better for latency/jitter/loss, higher for QoE.
const latClass = (ms: number) =>
  ms < 50 ? "cell-ok" : ms < 150 ? "cell-warn" : "cell-bad";
const jitClass = (ms: number) =>
  ms < 30 ? "cell-ok" : ms < 60 ? "cell-warn" : "cell-bad";
const lossClass = (pct: number) =>
  pct < 1 ? "cell-ok" : pct < 3 ? "cell-warn" : "cell-bad";
const qoeClass = (q: number) =>
  q >= 8 ? "cell-ok" : q >= 5 ? "cell-warn" : "cell-bad";

// ClickHouse JSON returns UInt64 (uptime) as a string and Float32 as a number;
// coerce every numeric field so arithmetic and formatting are safe.
function coerce(t: Tunnel): Tunnel {
  return {
    ...t,
    latency_ms: Number(t.latency_ms) || 0,
    jitter_ms: Number(t.jitter_ms) || 0,
    loss_pct: Number(t.loss_pct) || 0,
    qoe: Number(t.qoe) || 0,
    uptime_s: Number(t.uptime_s) || 0,
  };
}

function fmtUptime(s: number): string {
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
          <span className="stat-sub">of {rows.length}</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Tunnels down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-sub">{rows.length ? `${down} impaired` : "none reported"}</span>
        </div>
        <div className={`stat ${rows.length ? (avgLat < 150 ? "s-good" : "s-warn") : "s-muted"}`}>
          <span className="stat-label">Avg latency</span>
          <span className="stat-value">
            {rows.length ? avgLat.toFixed(0) : "—"}
            {rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> ms</span> : null}
          </span>
          <span className="stat-sub">across tunnels</span>
        </div>
        <div className={`stat ${rows.length ? (avgLoss < 1 ? "s-good" : "s-warn") : "s-muted"}`}>
          <span className="stat-label">Avg loss</span>
          <span className="stat-value">
            {rows.length ? avgLoss.toFixed(2) : "—"}
            {rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> %</span> : null}
          </span>
          <span className="stat-sub">packet loss</span>
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
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Local</th>
              <th>Remote</th>
              <th className="num">Latency</th>
              <th className="num">Jitter</th>
              <th className="num">Loss</th>
              <th className="num">QoE</th>
              <th>Uptime</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((t) => (
              <tr key={t.id} className="dt-row">
                <td>
                  <span className="badge">{t.type || "—"}</span>
                </td>
                <td>
                  {t.local_device || "—"}
                  <div className="stat-sub">{t.local_addr}</div>
                </td>
                <td>
                  {t.remote_device || "—"}
                  <div className="stat-sub">{t.remote_addr}</div>
                </td>
                <td className={`num ${latClass(t.latency_ms)}`}>
                  {t.latency_ms.toFixed(1)} ms
                </td>
                <td className={`num ${jitClass(t.jitter_ms)}`}>
                  {t.jitter_ms.toFixed(1)} ms
                </td>
                <td className={`num ${lossClass(t.loss_pct)}`}>
                  {t.loss_pct.toFixed(2)} %
                </td>
                <td className={`num ${qoeClass(t.qoe)}`}>{t.qoe.toFixed(1)}</td>
                <td>{fmtUptime(t.uptime_s)}</td>
                <td>
                  <span className={`badge ${t.status === "up" ? "good" : "bad"}`}>
                    {t.status || "?"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
