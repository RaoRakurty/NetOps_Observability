import { useEffect, useState } from "react";
import { api, CollectorStatus } from "../services/api";

// Heat class for a poll-duration cell: fast=ok, sluggish=warn, slow=bad.
function pollClass(ms?: number): string {
  if (ms == null) return "";
  if (ms < 500) return "cell-ok";
  if (ms < 2000) return "cell-warn";
  return "cell-bad";
}

// Heat class for the reachable/targets cell.
function reachClass(c: CollectorStatus): string {
  if (c.targets === 0) return "";
  if ((c.reachable ?? 0) === 0) return "cell-bad";
  if ((c.reachable ?? 0) < c.targets) return "cell-warn";
  return "cell-ok";
}

export default function Collectors() {
  const [items, setItems] = useState<CollectorStatus[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const c = await api.collectors();
        // This tab is for transport/protocol collectors only. Feature
        // collectors (e.g. tunnel discovery, kind "discovery") have their own
        // views and are filtered out here.
        if (alive) setItems((c ?? []).filter((x) => (x.kind ?? "protocol") === "protocol"));
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const enabled = items.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.healthy).length;
  const totalTargets = items.reduce((n, c) => n + c.targets, 0);
  const totalReachable = items.reduce((n, c) => n + (c.reachable ?? 0), 0);
  const reachAccent =
    totalTargets === 0
      ? "s-muted"
      : totalReachable === 0
      ? "s-bad"
      : totalReachable < totalTargets
      ? "s-warn"
      : "s-good";

  return (
    <div className="card">
      <h2>Collectors</h2>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat s-accent">
          <span className="stat-label">Collectors</span>
          <span className="stat-value">{items.length}</span>
          <span className="stat-sub">registered</span>
        </div>
        <div className={`stat ${enabled.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">Enabled</span>
          <span className="stat-value">{enabled.length}</span>
          <span className="stat-sub">of {items.length}</span>
        </div>
        <div
          className={`stat ${
            enabled.length === 0
              ? "s-muted"
              : healthy === enabled.length
              ? "s-good"
              : "s-bad"
          }`}
        >
          <span className="stat-label">Healthy</span>
          <span className="stat-value">{healthy}</span>
          <span className="stat-sub">of {enabled.length} enabled</span>
        </div>
        <div className={`stat ${reachAccent}`}>
          <span className="stat-label">Targets reachable</span>
          <span className="stat-value">
            {totalReachable}
            <span style={{ fontSize: 20, color: "var(--muted)" }}>
              /{totalTargets}
            </span>
          </span>
          <span className="stat-sub">across all collectors</span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="empty">No collectors registered.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Enabled</th>
              <th>Healthy</th>
              <th className="num">Targets</th>
              <th className="num">Reachable</th>
              <th className="num">Last poll</th>
              <th>Last tick</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.name} className="dt-row">
                <td>{c.name}</td>
                <td>
                  <span className={`badge ${c.enabled ? "good" : "warn"}`}>
                    {c.enabled ? "on" : "off"}
                  </span>
                </td>
                <td>
                  <span className={`badge ${c.healthy ? "good" : "bad"}`}>
                    {c.healthy ? "ok" : "fail"}
                  </span>
                </td>
                <td className="num">{c.targets}</td>
                <td
                  className={`num ${reachClass(c)}`}
                  title={c.last_error || undefined}
                >
                  {c.targets > 0 ? `${c.reachable ?? 0}/${c.targets}` : "—"}
                </td>
                <td className={`num ${pollClass(c.last_poll_ms)}`}>
                  {c.last_poll_ms != null ? `${c.last_poll_ms} ms` : "—"}
                </td>
                <td>
                  {c.last_tick ? new Date(c.last_tick).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
