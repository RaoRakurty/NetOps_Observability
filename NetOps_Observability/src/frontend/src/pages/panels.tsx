// panels.tsx — the modular Overview panel library. Each panel is a small,
// self-contained component that fetches its own data on an interval and binds
// to the real backend APIs (metrics over VictoriaMetrics, alerts, flows,
// collectors, devices). The registry below is what the Dashboard shell renders
// and what the "Add panel" picker lists. Panels render only their body — the
// shell draws the title bar + resize/remove tools.

import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Alert, MetricTile, PromRangeResponse, CollectorStatus } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor } from "../theme/charts";
import { severityClass, SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import Topology from "../tabs/Topology";

// ---- shared helpers --------------------------------------------------------

function usePolled<T>(loader: () => Promise<T>, intervalMs = 15000): T | undefined {
  const [val, setVal] = useState<T>();
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await loader();
        if (alive) setVal(r);
      } catch {
        /* leave previous value */
      }
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return val;
}

// latestFromProm pulls the most recent finite sample out of a range response.
function latestFromProm(res?: PromRangeResponse): number | null {
  for (const s of res?.data?.result ?? []) {
    const vals = s.values ?? [];
    for (let i = vals.length - 1; i >= 0; i--) {
      const n = Number(vals[i][1]);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

function nowWindow(seconds: number, step = 60): [number, number, number] {
  const end = Math.floor(Date.now() / 1000);
  return [end - seconds, end, step];
}

function Empty({ msg }: { msg: string }) {
  return <div className="panel-empty">{msg}</div>;
}

// ---- gauge ("wheel") panels ------------------------------------------------

function MetricGauge({
  query,
  unit = "%",
  max = 100,
  goodHigh = false,
}: {
  query: string;
  unit?: string;
  max?: number;
  goodHigh?: boolean; // true => high is good (e.g. availability)
}) {
  const res = usePolled(() => {
    const [s, e, st] = nowWindow(300);
    return api.metricsQueryRange(query, s, e, st);
  });
  const v = res ? latestFromProm(res) : null;
  // Color stops: for "good high" flip the gradient.
  const stops = goodHigh
    ? [[0.5, SEVERITY_COLOR.critical], [0.8, SEVERITY_COLOR.warning], [1, SEVERITY_COLOR.ok]]
    : [[0.7, SEVERITY_COLOR.ok], [0.9, SEVERITY_COLOR.warning], [1, SEVERITY_COLOR.critical]];
  return (
    <ReactECharts
      style={{ height: 200 }}
      option={{
        series: [
          {
            type: "gauge",
            min: 0,
            max,
            startAngle: 215,
            endAngle: -35,
            progress: { show: true, width: 40, roundCap: true },
            axisLine: { lineStyle: { width: 40, color: stops } },
            pointer: { show: false },
            axisTick: { show: false },
            splitLine: { show: false },
            axisLabel: { show: false },
            anchor: { show: false },
            title: { show: false },
            detail: {
              valueAnimation: true,
              fontSize: 28,
              fontWeight: 700,
              offsetCenter: [0, 0],
              formatter: v === null ? "—" : `{v|${Math.round(v)}}{u|${unit}}`,
              rich: {
                v: { fontSize: 30, fontWeight: 800, color: "var(--fg)" },
                u: { fontSize: 13, color: "var(--muted)", padding: [0, 0, 4, 2] },
              },
            },
            data: [{ value: v ?? 0 }],
          },
        ],
      }}
    />
  );
}

// ---- alerts: color-coded count row by severity -----------------------------

const SEV_ORDER: SeverityKey[] = ["critical", "error", "warning", "notice", "info"];

function AlertsSeverity() {
  const alerts = usePolled(() => api.alerts(), 10000) ?? [];
  const counts = alerts.reduce<Record<string, number>>((acc, a) => {
    const k = severityKey(a.severity);
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div className="sev-counts">
      {SEV_ORDER.map((k) => (
        <div
          key={k}
          className="sev-count"
          style={{ borderLeftColor: SEVERITY_COLOR[k] }}
        >
          <div className="n" style={{ color: SEVERITY_COLOR[k] }}>
            {counts[k] ?? 0}
          </div>
          <div className="l">{k}</div>
        </div>
      ))}
    </div>
  );
}

function ActiveAlerts() {
  const alerts = (usePolled(() => api.alerts(), 10000) ?? []).slice(0, 10);
  if (alerts.length === 0) return <Empty msg="All clear — no active alerts." />;
  return (
    <div className="alerts-scroll">
      {alerts.map((a: Alert, i) => (
        <div className="mini-row" key={a.id ?? i}>
          <span className={`badge ${severityClass(a.severity)}`}>{a.severity || "info"}</span>
          <div className="mini-body">
            <div className="mini-title">{a.summary || "(no summary)"}</div>
            <div className="mini-meta">
              {a.rule}
              {a.device_id ? ` · ${a.device_id}` : ""}
              {a.fired_at ? ` · ${new Date(a.fired_at).toLocaleString()}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- flows / traffic -------------------------------------------------------

function TrafficInOut() {
  const data = usePolled(async () => {
    const [s, e, st] = nowWindow(3600);
    const [ins, outs] = await Promise.all([
      api.metricsQueryRange("sum(rate(device_if_in_octets[5m]))*8", s, e, st).catch(() => undefined),
      api.metricsQueryRange("sum(rate(device_if_out_octets[5m]))*8", s, e, st).catch(() => undefined),
    ]);
    return { ins, outs };
  });
  const toSeries = (r?: PromRangeResponse) =>
    (r?.data?.result?.[0]?.values ?? []).map((v) => [v[0] * 1000, Number(v[1])]);
  const inS = toSeries(data?.ins);
  const outS = toSeries(data?.outs);
  if (inS.length === 0 && outS.length === 0)
    return <Empty msg="No interface throughput yet (enable SNMP metrics)." />;
  return (
    <ReactECharts
      style={{ height: 220 }}
      option={{
        ...chartBase,
        grid: { left: 56, right: 12, top: 16, bottom: 24 },
        tooltip: { ...chartBase.tooltip, trigger: "axis" },
        legend: { ...chartBase.legend, top: 0, data: ["In", "Out"] },
        xAxis: { type: "time", ...axisStyle },
        yAxis: { type: "value", name: "bps", ...axisStyle },
        series: [
          { name: "In", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(0), width: 2 }, itemStyle: { color: paletteColor(0) }, areaStyle: { color: areaGradient(0) }, data: inS },
          { name: "Out", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(2), width: 2 }, itemStyle: { color: paletteColor(2) }, areaStyle: { color: areaGradient(2) }, data: outS },
        ],
      }}
    />
  );
}

function TopHosts() {
  const res = usePolled(() => api.topTalkers(3600, 8), 30000);
  const rows = ((res?.data as { src: string; dst: string; bytes_total: number }[]) ?? []).slice(0, 8);
  if (rows.length === 0) return <Empty msg="No flow data yet." />;
  return (
    <table className="mini-table">
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td className="mono">{r.src}</td>
            <td className="mono">{r.dst}</td>
            <td style={{ textAlign: "right" }}>{Number(r.bytes_total).toLocaleString()} B</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ---- collector-derived panels ----------------------------------------------

function useProtocolCollectors(): CollectorStatus[] {
  const items = usePolled(() => api.collectors(), 15000) ?? [];
  return items.filter((c) => (c.kind ?? "protocol") === "protocol");
}

function SiteAvailability() {
  const cols = useProtocolCollectors();
  const targets = cols.reduce((n, c) => n + (c.targets ?? 0), 0);
  const reachable = cols.reduce((n, c) => n + (c.reachable ?? 0), 0);
  const pct = targets > 0 ? Math.round((reachable / targets) * 100) : null;
  const cls = pct === null ? "s-muted" : pct >= 99 ? "s-good" : pct >= 90 ? "s-warn" : "s-bad";
  return (
    <div className={`stat ${cls}`} style={{ border: 0, padding: 0 }}>
      <span className="stat-value">{pct === null ? "—" : `${pct}%`}</span>
      <span className="stat-sub">{reachable}/{targets} targets reachable</span>
    </div>
  );
}

function StackPerformance() {
  const cols = useProtocolCollectors();
  const enabled = cols.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.healthy).length;
  const avgMs =
    cols.length > 0
      ? Math.round(cols.reduce((n, c) => n + (c.last_poll_ms ?? 0), 0) / cols.length)
      : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
      <div className={`stat ${enabled.length && healthy === enabled.length ? "s-good" : "s-bad"}`}>
        <span className="stat-label">Collectors healthy</span>
        <span className="stat-value">{healthy}/{enabled.length}</span>
      </div>
      <div className="stat s-accent">
        <span className="stat-label">Avg poll</span>
        <span className="stat-value">{avgMs === null ? "—" : `${avgMs}`}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></span>
      </div>
    </div>
  );
}

function KpiTiles() {
  const tiles = usePolled(() => api.metricTiles(), 15000) ?? [];
  if (tiles.length === 0) return <Empty msg="Waiting for metrics…" />;
  return (
    <div className="stat-grid">
      {tiles.map((m: MetricTile) => (
        <div className="stat s-accent" key={m.title}>
          <span className="stat-label">{m.title}</span>
          <span className="stat-value">{m.value}</span>
          {m.trend && <span className="stat-sub">{m.trend}</span>}
        </div>
      ))}
    </div>
  );
}

function TopologyPanel() {
  return (
    <div style={{ maxHeight: 420, overflow: "auto" }}>
      <Topology />
    </div>
  );
}

// ---- registry --------------------------------------------------------------

export type PanelDef = {
  type: string;
  title: string;
  defaultSpan: number; // 3 | 4 | 6 | 8 | 12
  render: () => JSX.Element;
};

export const PANELS: Record<string, PanelDef> = {
  "alerts-severity": { type: "alerts-severity", title: "Alerts by severity", defaultSpan: 12, render: () => <AlertsSeverity /> },
  "gauge-cpu": { type: "gauge-cpu", title: "CPU", defaultSpan: 3, render: () => <MetricGauge query="avg(device_cpu_percent)" /> },
  "gauge-mem": { type: "gauge-mem", title: "Memory", defaultSpan: 3, render: () => <MetricGauge query="avg(device_mem_percent)" /> },
  "gauge-storage": { type: "gauge-storage", title: "Storage", defaultSpan: 3, render: () => <MetricGauge query="avg(device_storage_percent)" /> },
  "gauge-network": { type: "gauge-network", title: "Network util", defaultSpan: 3, render: () => <MetricGauge query="avg(device_if_util_percent)" /> },
  "site-availability": { type: "site-availability", title: "Site availability", defaultSpan: 3, render: () => <SiteAvailability /> },
  "stack-performance": { type: "stack-performance", title: "Stack performance", defaultSpan: 6, render: () => <StackPerformance /> },
  traffic: { type: "traffic", title: "Traffic in / out", defaultSpan: 8, render: () => <TrafficInOut /> },
  "top-hosts": { type: "top-hosts", title: "Top hosts", defaultSpan: 4, render: () => <TopHosts /> },
  "active-alerts": { type: "active-alerts", title: "Active alerts", defaultSpan: 12, render: () => <ActiveAlerts /> },
  kpis: { type: "kpis", title: "KPIs", defaultSpan: 12, render: () => <KpiTiles /> },
  topology: { type: "topology", title: "Topology", defaultSpan: 12, render: () => <TopologyPanel /> },
};

// Order shown in the "Add panel" picker.
export const PANEL_ORDER = [
  "gauge-cpu", "gauge-mem", "gauge-storage", "gauge-network",
  "alerts-severity", "active-alerts", "traffic", "top-hosts",
  "site-availability", "stack-performance", "kpis", "topology",
];
