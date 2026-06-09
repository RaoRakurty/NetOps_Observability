import { ReactNode, useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Device, Alert, PromSeries } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor } from "../theme/charts";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";
import { Stub } from "./Placeholders";

// Device Monitoring — the network-device-fleet board (modeled on the reference
// "Network Device Monitoring" dashboard). Collapsible section groups; each panel
// is wired to data we actually collect (SNMP metrics in VictoriaMetrics:
// device_cpu_percent / device_mem_percent / device_if_*_octets / device_sysuptime,
// the device inventory, active alerts, and ClickHouse flows). Sections needing
// data we don't yet surface natively (synthetics, NetPath runners, IPsec SNMP
// OIDs, geo placement) render a "Planned" stub. Panel names are intentionally
// distinct from the Flows section to avoid duplicate labels across the app.

const fmtBps = (n: number) => {
  const x = Number(n) || 0;
  if (x < 1000) return `${x.toFixed(0)} bps`;
  const u = ["kbps", "Mbps", "Gbps", "Tbps"];
  let v = x / 1000;
  let i = 0;
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
};
const fmtPct = (n: number) => `${(Number(n) || 0).toFixed(0)}%`;

function fmtUptime(sec: number): string {
  const s = Number(sec) || 0;
  if (s <= 0) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

// Collapsible section group with a tinted header (reference dashboard style).
function Group({ title, hue, children, defaultOpen = true }: { title: string; hue: string; children: ReactNode; defaultOpen?: boolean }) {
  return (
    <details className="dm-group" open={defaultOpen}>
      <summary className="dm-group-head" style={{ ["--g" as string]: hue } as React.CSSProperties}>
        <Icon name="chevron" size={14} className="dm-group-chevron" />
        <span>{title}</span>
      </summary>
      <div className="dm-group-body">{children}</div>
    </details>
  );
}

function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3>{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

// Latest numeric value of a Prom series.
const latest = (s: PromSeries): number => (s.values.length ? Number(s.values[s.values.length - 1][1]) : 0);
// Human label for a series from preferred label keys (device, then index).
function seriesLabel(s: PromSeries): string {
  const m = s.metric || {};
  const dev = m.device || m.instance || m.host || "";
  const idx = m.index || m.ifName || m.ifname || "";
  if (dev && idx) return `${dev} · ${idx}`;
  return dev || idx || m.__name__ || "series";
}

// ── PromQL timeseries line panel ─────────────────────────────────────────────
function MetricLine({ title, query, minutes, fmtY, height = 240 }: { title: string; query: string; minutes: number; fmtY: (n: number) => string; height?: number }) {
  const [series, setSeries] = useState<PromSeries[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const end = Math.floor(Date.now() / 1000);
        const start = end - minutes * 60;
        const step = Math.max(30, Math.floor((minutes * 60) / 180));
        const r = await api.metricsQueryRange(query, start, end, step);
        if (!alive) return;
        if (r.status !== "success" || !r.data) throw new Error((r as any).error || "query failed");
        setSeries(r.data.result ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [query, minutes]);

  return (
    <Panel title={title}>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : series.length === 0 ? (
        <div className="empty">No data in this window.</div>
      ) : (
        <ReactECharts
          style={{ height }}
          option={{
            ...chartBase,
            tooltip: { ...chartBase.tooltip, trigger: "axis" },
            legend: series.length > 1 && series.length <= 8 ? { ...chartBase.legend, top: 0, type: "scroll" } : { show: false },
            grid: { left: 56, right: 24, top: series.length > 1 ? 30 : 12, bottom: 24 },
            xAxis: { type: "time", ...axisStyle },
            yAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtY(v) } },
            series: series.slice(0, 12).map((s, i) => ({
              name: seriesLabel(s),
              type: "line",
              showSymbol: false,
              smooth: true,
              lineStyle: { color: paletteColor(i), width: 2 },
              itemStyle: { color: paletteColor(i) },
              areaStyle: series.length === 1 ? { color: areaGradient(i) } : undefined,
              data: s.values.map(([t, v]) => [t * 1000, Number(v)]),
            })),
          }}
        />
      )}
    </Panel>
  );
}

// ── PromQL "top-N" horizontal-bar panel (latest value per series) ─────────────
function MetricTop({ title, query, minutes, fmtX, limit = 10 }: { title: string; query: string; minutes: number; fmtX: (n: number) => string; limit?: number }) {
  const [rows, setRows] = useState<{ label: string; value: number }[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const end = Math.floor(Date.now() / 1000);
        const start = end - minutes * 60;
        const step = Math.max(30, Math.floor((minutes * 60) / 60));
        const r = await api.metricsQueryRange(query, start, end, step);
        if (!alive) return;
        if (r.status !== "success" || !r.data) throw new Error((r as any).error || "query failed");
        const out = (r.data.result ?? [])
          .map((s) => ({ label: seriesLabel(s), value: latest(s) }))
          .filter((x) => Number.isFinite(x.value))
          .sort((a, b) => b.value - a.value)
          .slice(0, limit);
        setRows(out);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [query, minutes]);

  return (
    <Panel title={title}>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <div className="empty">No data in this window.</div>
      ) : (
        <ReactECharts
          style={{ height: Math.min(360, 36 + rows.length * 26) }}
          option={{
            ...chartBase,
            grid: { left: 8, right: 70, top: 6, bottom: 6, containLabel: true },
            tooltip: { ...chartBase.tooltip, trigger: "axis", axisPointer: { type: "shadow" }, formatter: (ps: any) => { const p = Array.isArray(ps) ? ps[0] : ps; return `${p.name}<br/><b>${fmtX(p.value)}</b>`; } },
            xAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtX(v) } },
            yAxis: { type: "category", inverse: true, data: rows.map((r) => r.label), ...axisStyle, splitLine: { show: false } },
            series: [{ type: "bar", data: rows.map((r) => r.value), itemStyle: { color: paletteColor(0), borderRadius: [0, 3, 3, 0] }, barMaxWidth: 16 }],
          }}
        />
      )}
    </Panel>
  );
}

// ── Fleet pulse: reachability tiles + alerts-by-severity, from inventory+alerts ─
const SEV_ORDER = ["critical", "error", "warning", "notice", "info"];
function FleetPulse() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [d, a] = await Promise.all([api.devices(), api.alerts()]);
        if (!alive) return;
        setDevices(d ?? []);
        setAlerts(a ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const { monitored, reachable, unreachable } = useMemo(() => {
    const now = Date.now();
    let r = 0;
    for (const d of devices) {
      const seen = Date.parse(d.last_seen || "");
      if (Number.isFinite(seen) && now - seen < 5 * 60_000) r++;
    }
    return { monitored: devices.length, reachable: r, unreachable: devices.length - r };
  }, [devices]);

  const bySev = useMemo(() => {
    const open = alerts.filter((a) => !a.resolved_at);
    const counts: Record<string, number> = {};
    for (const a of open) {
      const s = (a.severity || "info").toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return SEV_ORDER.filter((s) => counts[s]).map((s) => ({ sev: s, n: counts[s] }));
  }, [alerts]);

  const sevTone = (s: string) => (s === "critical" || s === "error" ? "bad" : s === "warning" ? "warn" : "");

  return (
    <>
      <StatStrip>
        <Stat label="Monitored devices" value={monitored} />
        <Stat label="Reachable" value={reachable} tone="good" />
        <Stat label="Unreachable" value={unreachable} tone={unreachable > 0 ? "bad" : ""} />
        <Stat label="Open alerts" value={alerts.filter((a) => !a.resolved_at).length} tone={bySev.some((x) => x.sev === "critical" || x.sev === "error") ? "bad" : bySev.length ? "warn" : "good"} />
      </StatStrip>
      <Panel title="Active alerts by severity">
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : bySev.length === 0 ? (
          <div className="empty">No active alerts. 🎉</div>
        ) : (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {bySev.map((x) => (
              <span key={x.sev} className={`badge ${sevTone(x.sev)}`}>{x.sev}: {x.n}</span>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

// ── Device inventory & uptime (from the discovery inventory) ───────────────────
function DeviceInventory() {
  const [rows, setRows] = useState<Device[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const d = await api.devices();
        if (alive) { setRows(d ?? []); setErr(null); }
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const now = Date.now();
  const cols = useMemo<Column<Device>[]>(() => [
    {
      key: "reach", header: "", width: "28px", render: (d) => {
        const seen = Date.parse(d.last_seen || "");
        const up = Number.isFinite(seen) && now - seen < 5 * 60_000;
        return <span title={up ? "Reachable" : "Unreachable"} style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: up ? "var(--good)" : "var(--bad)" }} />;
      },
    },
    { key: "name", header: "Device", sortable: true, text: (d) => d.name, render: (d) => d.name },
    { key: "address", header: "Address", sortable: true, text: (d) => d.address, render: (d) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{d.address}</span> },
    { key: "vendor", header: "Vendor", sortable: true, text: (d) => d.vendor || "—", render: (d) => d.vendor || "—" },
    { key: "model", header: "Model", sortable: true, text: (d) => d.model || "—", render: (d) => d.model || "—" },
    { key: "source", header: "Source", sortable: true, text: (d) => d.source, render: (d) => d.source },
    { key: "last_seen", header: "Last seen", sortable: true, sortValue: (d) => Date.parse(d.last_seen || "") || 0, render: (d) => (d.last_seen ? new Date(d.last_seen).toLocaleString() : "—") },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], []);

  return (
    <Panel title="Devices — inventory & reachability">
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <div className="empty">No devices discovered yet.</div>
      ) : (
        <DataTable<Device> rows={rows} columns={cols} rowKey={(d) => d.id} height={Math.min(420, 44 + rows.length * 30)} ariaLabel="Device inventory" initialSort={{ key: "name", dir: "asc" }} />
      )}
    </Panel>
  );
}

// ── Uptime top-list, from device_sysuptime ───────────────────────────────────
function UptimeList({ minutes }: { minutes: number }) {
  const [rows, setRows] = useState<{ label: string; value: number }[]>([]);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const end = Math.floor(Date.now() / 1000);
        const r = await api.metricsQueryRange("device_sysuptime", end - minutes * 60, end, Math.max(60, minutes * 60));
        if (!alive || r.status !== "success" || !r.data) return;
        const out = (r.data.result ?? []).map((s) => ({ label: seriesLabel(s), value: latest(s) / 100 })).sort((a, b) => b.value - a.value).slice(0, 10);
        setRows(out);
      } catch { /* leave empty */ }
    };
    load();
    const id = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(id); };
  }, [minutes]);

  return (
    <Panel title="Longest device uptime">
      {rows.length === 0 ? (
        <div className="empty">No uptime data.</div>
      ) : (
        <ul className="dm-list">
          {rows.map((r) => (
            <li key={r.label}><span>{r.label}</span><strong>{fmtUptime(r.value)}</strong></li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function DeviceMonitoring({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  return (
    <div className="dm-board">
      <Group title="Fleet pulse & reachability" hue="#22C55E">
        <FleetPulse />
      </Group>

      <Group title="Device resources — CPU & memory" hue="#F59E0B">
        <div className="dm-grid">
          <MetricLine title="Average CPU utilization (%)" query="avg(device_cpu_percent)" minutes={m} fmtY={fmtPct} />
          <MetricLine title="Average memory utilization (%)" query="avg(device_mem_percent)" minutes={m} fmtY={fmtPct} />
          <MetricTop title="Devices with highest CPU (%)" query="device_cpu_percent" minutes={m} fmtX={fmtPct} />
          <MetricTop title="Devices with highest memory (%)" query="device_mem_percent" minutes={m} fmtX={fmtPct} />
        </div>
      </Group>

      <Group title="Interfaces — throughput & utilization" hue="#0EA5E9">
        <div className="dm-grid">
          <MetricTop title="Busiest interfaces — inbound (bps)" query="topk(10, rate(device_if_in_octets[5m]) * 8)" minutes={m} fmtX={fmtBps} />
          <MetricTop title="Busiest interfaces — outbound (bps)" query="topk(10, rate(device_if_out_octets[5m]) * 8)" minutes={m} fmtX={fmtBps} />
        </div>
      </Group>

      <Group title="Fleet aggregates" hue="#3B82F6">
        <div className="dm-grid">
          <MetricLine title="Fleet total throughput (bps)" query="sum(rate(device_if_in_octets[5m]) * 8) + sum(rate(device_if_out_octets[5m]) * 8)" minutes={m} fmtY={fmtBps} />
          <MetricLine title="Reachable targets" query="sum(collector_target_up)" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} />
        </div>
      </Group>

      <Group title="Device inventory & uptime" hue="#EAB308">
        <DeviceInventory />
        <div className="dm-grid">
          <UptimeList minutes={m} />
        </div>
      </Group>

      <Group title="Traffic insights (NetFlow)" hue="#8B5CF6" defaultOpen={false}>
        <Stub
          icon="flows"
          title="Traffic insights"
          summary="Flow-derived traffic for the fleet lives in the dedicated Flows dashboard, which has the full filter bar and per-dimension breakdowns."
          planned={[
            "Embedded flow summary tiles (busiest talkers, top exporters)",
            "Deep-link each device here into its flows",
          ]}
        />
      </Group>

      <Group title="Synthetics & Network Path" hue="#14B8A6" defaultOpen={false}>
        <Stub
          icon="topology"
          title="Synthetic & path monitoring"
          summary="Active checks (ICMP/HTTP runners), NetPath hop-by-hop latency, and synthetic test status. Requires a synthetics/runner pipeline we don't collect yet."
          planned={[
            "ICMP / HTTP response-time runners",
            "NetPath status, active paths and check interval",
            "Synthetic test status board",
          ]}
        />
      </Group>

      <Group title="IPsec VPN tunnels" hue="#A855F7" defaultOpen={false}>
        <Stub
          icon="stack"
          title="IPsec VPN tunnels (SNMP)"
          summary="Tunnel auth/crypto failures and per-tunnel throughput from vendor IPsec SNMP OIDs. Overlay/tunnel telemetry currently lives in the Tunnels view."
          planned={[
            "IPsec auth & crypto failure counters (Cisco-style OIDs)",
            "Per-tunnel throughput",
            "Fold into the existing Tunnels overlay view",
          ]}
        />
      </Group>

      <Group title="Geographic map" hue="#D946EF" defaultOpen={false}>
        <Stub
          icon="explore"
          title="Device geomap"
          summary="Devices plotted by site/region with live health overlays — shared with Infrastructure → Device Geomap."
          planned={["Site/region placement from inventory metadata", "Reachability overlays per location"]}
        />
      </Group>
    </div>
  );
}
