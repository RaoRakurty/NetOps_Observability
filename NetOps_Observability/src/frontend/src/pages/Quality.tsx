import { useEffect, useMemo, useState } from "react";
import { api, Tunnel } from "../services/api";
import { StatStrip, Stat } from "../components/ui";
import { Group, Panel, MetricTop, MetricStat } from "../components/board/panels";

// Quality — service- and link-quality scoring across the fleet. Distinct from the
// raw error/discard counts on Device Monitoring: this board is about RATES and
// RATIOS (errors/discards per 1k packets, saturation thresholds) and overlay QoE
// — the signals that say "is this link healthy", not just "how busy is it". All
// from telemetry we already collect (SNMP interface counters + tunnel metrics).

// Total packet rate (all classes, both directions) — the denominator for error
// and discard ratios. clamp_min(…,1) avoids divide-by-zero on idle interfaces.
const TOTAL_PKTS =
  "clamp_min(rate(device_if_in_ucast_pkts[5m]) + rate(device_if_in_mcast_pkts[5m]) + rate(device_if_in_bcast_pkts[5m]) " +
  "+ rate(device_if_out_ucast_pkts[5m]) + rate(device_if_out_mcast_pkts[5m]) + rate(device_if_out_bcast_pkts[5m]), 1)";

const errRate = `topk(10, (rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m])) / ${TOTAL_PKTS} * 1000)`;
const discRate = `topk(10, (rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m])) / ${TOTAL_PKTS} * 1000)`;

// Count of interfaces at/above a utilization threshold in either direction.
const utilCount = (thr: number) =>
  `count((rate(device_if_in_octets[5m]) * 8 * 100 / device_if_speed >= ${thr}) ` +
  `or (rate(device_if_out_octets[5m]) * 8 * 100 / device_if_speed >= ${thr})) or vector(0)`;

const num = (v: unknown) => Number(v) || 0;

// ── Overlay / tunnel quality (from /api/tunnels) ──────────────────────────────
function TunnelQuality() {
  const [rows, setRows] = useState<Tunnel[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try { const r = await api.tunnels(500); if (alive) { setRows((r?.data as Tunnel[]) ?? []); setErr(null); } }
      catch (e) { if (alive) setErr((e as Error).message); }
    };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const stats = useMemo(() => {
    const up = rows.filter((t) => String(t.status).toLowerCase() === "up").length;
    const qoes = rows.map((t) => num(t.qoe)).filter((q) => q > 0);
    const avgQoe = qoes.length ? qoes.reduce((a, b) => a + b, 0) / qoes.length : 0;
    const worstLoss = rows.reduce((m, t) => Math.max(m, num(t.loss_pct)), 0);
    return { total: rows.length, up, avgQoe, worstLoss };
  }, [rows]);

  const worst = useMemo(
    () => [...rows].filter((t) => num(t.qoe) > 0).sort((a, b) => num(a.qoe) - num(b.qoe)).slice(0, 8),
    [rows],
  );
  const qoeTone = (q: number) => (q >= 8 ? "good" : q >= 5 ? "warn" : "bad");

  return (
    <>
      <StatStrip>
        <Stat label="Tunnels" value={stats.total} />
        <Stat label="Up" value={stats.up} tone={stats.total > 0 && stats.up === stats.total ? "good" : stats.up < stats.total ? "warn" : ""} />
        <Stat label="Avg QoE" value={stats.total ? stats.avgQoe.toFixed(1) : "—"} tone={stats.total ? qoeTone(stats.avgQoe) : ""} />
        <Stat label="Worst loss" value={stats.total ? `${stats.worstLoss.toFixed(1)}%` : "—"} tone={stats.worstLoss >= 3 ? "bad" : stats.worstLoss >= 1 ? "warn" : "good"} />
      </StatStrip>
      <Panel title="Lowest-QoE overlay tunnels">
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : worst.length === 0 ? (
          <div className="empty">No overlay tunnel telemetry yet.</div>
        ) : (
          <ul className="dm-list">
            {worst.map((t) => (
              <li key={t.id}>
                <span>{t.local_device || t.id} → {t.remote_device || "—"} <em style={{ color: "var(--fg-subtle)" }}>({t.type})</em></span>
                <strong>
                  QoE {num(t.qoe).toFixed(1)} · {num(t.latency_ms).toFixed(0)}ms · loss {num(t.loss_pct).toFixed(1)}%
                </strong>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}

export default function Quality({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  return (
    <div className="dm-board">
      <Group title="Link error quality" hue="#22C55E">
        <StatStrip>
          <MetricStat label="Interfaces monitored" query="count(device_if_oper_status) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
          <MetricStat label="Operationally up" query="count(device_if_oper_status == 1) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={() => "good"} />
          <MetricStat label="With errors (5m)" query="count((rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m])) > 0) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
          <MetricStat label="With discards (5m)" query="count((rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m])) > 0) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "warn" : "good")} />
        </StatStrip>
        <div className="dm-grid">
          <MetricTop title="Worst error rate (errors / 1k packets)" query={errRate} minutes={m} fmtX={(n) => n.toFixed(2)} labelKeys={["device", "index"]} />
          <MetricTop title="Worst discard rate (discards / 1k packets)" query={discRate} minutes={m} fmtX={(n) => n.toFixed(2)} labelKeys={["device", "index"]} />
        </div>
        <p className="mini-meta" style={{ margin: 0 }}>
          Error/discard <em>rate</em> normalizes by traffic — a busy link with a few errors is healthier than a quiet link dropping a high fraction. Per 1,000 packets.
        </p>
      </Group>

      <Group title="Capacity quality (saturation)" hue="#14B8A6">
        <StatStrip>
          <MetricStat label="Interfaces ≥ 80% util" query={utilCount(80)} minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
          <MetricStat label="Interfaces ≥ 60% util" query={utilCount(60)} minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "warn" : "good")} />
        </StatStrip>
        <div className="dm-grid">
          <MetricTop title="Saturation risk — inbound peak (util %)" query="topk(10, rate(device_if_in_octets[5m]) * 8 * 100 / device_if_speed)" minutes={m} fmtX={(n) => `${n.toFixed(0)}%`} labelKeys={["device", "index"]} />
          <MetricTop title="Saturation risk — outbound peak (util %)" query="topk(10, rate(device_if_out_octets[5m]) * 8 * 100 / device_if_speed)" minutes={m} fmtX={(n) => `${n.toFixed(0)}%`} labelKeys={["device", "index"]} />
        </div>
      </Group>

      <Group title="Overlay quality (tunnels)" hue="#8B5CF6">
        <TunnelQuality />
      </Group>
    </div>
  );
}
