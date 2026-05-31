// panels.tsx — the modular Overview panel library. Each panel is a small,
// self-contained component that fetches its own data on an interval and binds
// to the real backend APIs (metrics over VictoriaMetrics, alerts, flows,
// collectors, devices). The registry below is what the Dashboard shell renders
// and what the "Add panel" picker lists. Panels render only their body — the
// shell draws the title bar + resize/remove tools.

import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Alert, MetricTile, PromRangeResponse, CollectorStatus, Device, Finding, Tunnel } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor, hexToRgba } from "../theme/charts";
import { severityClass, SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import { usePrefs } from "../theme/prefs";
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
  const { theme } = usePrefs(); // re-render the wheel when the theme flips
  const res = usePolled(() => {
    const [s, e, st] = nowWindow(300);
    return api.metricsQueryRange(query, s, e, st);
  });
  const v = res ? latestFromProm(res) : null;
  // Glassy progress color by current value (light tint → vivid), keyed to the
  // good/bad direction. Modern "elite glass" hues, brighter than the severity
  // tokens so the wheel reads lively rather than dark. When there's no data the
  // ring shows a soft indigo "idle" gradient instead of dead grey.
  const pct = v === null ? 0 : Math.min(1, Math.max(0, v / max));
  const band = (() => {
    if (v === null) return ["#a5b4fc", "#818cf8"]; // idle indigo (no data yet)
    const t = goodHigh ? 1 - pct : pct; // t: 0 = healthy, 1 = bad
    if (t < 0.7) return ["#34d399", "#10b981"]; // emerald
    if (t < 0.9) return ["#fbbf24", "#f59e0b"]; // amber
    return ["#fb7185", "#f43f5e"];               // rose
  })();
  const progressColor = {
    type: "linear", x: 0, y: 0, x2: 1, y2: 1,
    colorStops: [{ offset: 0, color: band[0] }, { offset: 1, color: band[1] }],
  };
  // Theme-aware glassy track: a soft cool gradient on light, deep slate on dark
  // (the old flat #eef1f6 looked wrong against the dark canvas). A faint idle
  // ring is always drawn so the wheel never reads as empty grey.
  const dark = theme === "dark";
  const trackColor = {
    type: "linear", x: 0, y: 0, x2: 0, y2: 1,
    colorStops: dark
      ? [{ offset: 0, color: "#2a3550" }, { offset: 1, color: "#1d2740" }]
      : [{ offset: 0, color: "#eef1f8" }, { offset: 1, color: "#e3e8f2" }],
  };
  return (
    <ReactECharts
      notMerge
      style={{ height: 190 }}
      option={{
        series: [
          {
            type: "gauge",
            min: 0,
            max,
            // Big, full wheel that fills the card. Thick rounded arc on a light
            // glassy track — the Datadog/Grafana modern-gauge look.
            center: ["50%", "60%"],
            radius: "118%",
            startAngle: 220,
            endAngle: -40,
            progress: { show: true, width: 30, roundCap: true, itemStyle: { color: progressColor, shadowBlur: 12, shadowColor: hexToRgba(band[1], 0.5) } },
            axisLine: { roundCap: true, lineStyle: { width: 30, color: [[1, trackColor]] } },
            pointer: { show: false },
            axisTick: { show: false },
            splitLine: { show: false },
            axisLabel: { show: false },
            anchor: { show: false },
            title: { show: false },
            detail: {
              valueAnimation: true,
              offsetCenter: [0, "-4%"],
              formatter: v === null ? "—" : `{v|${Math.round(v)}}{u|${unit}}`,
              rich: {
                v: { fontSize: 38, fontWeight: 800, color: dark ? "#e7ebf3" : "#161d29" },
                u: { fontSize: 16, color: dark ? "#9aa6bf" : "#586173", padding: [0, 0, 6, 2] },
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
      {tiles.map((m: MetricTile) => {
        // Color the tile by status: red when something is down/threatening,
        // green when explicitly all-clear, accent otherwise.
        const cls =
          m.trend === "critical" ? "s-bad"
          : m.trend === "all up" || m.trend === "clear" ? "s-good"
          : "s-accent";
        return (
          <div className={`stat ${cls}`} key={m.title}>
            <span className="stat-label">{m.title}</span>
            <span className="stat-value">{m.value}</span>
            {m.trend && <span className="stat-sub">{m.trend}</span>}
          </div>
        );
      })}
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

// ---- donut: a shared colorful ring used by several panels ------------------

function Donut({ rows, unit }: { rows: { name: string; value: number }[]; unit?: string }) {
  if (rows.length === 0) return <Empty msg="No data yet." />;
  return (
    <ReactECharts
      style={{ height: 190 }}
      option={{
        ...chartBase,
        tooltip: { ...chartBase.tooltip, trigger: "item", formatter: `{b}: {c}${unit ? " " + unit : ""} ({d}%)` },
        legend: { ...chartBase.legend, type: "scroll", orient: "vertical", right: 4, top: "center", itemWidth: 9, itemHeight: 9, textStyle: { color: "#667085", fontSize: 12 } },
        series: [{
          type: "pie", radius: ["52%", "76%"], center: ["38%", "50%"],
          avoidLabelOverlap: true, label: { show: false }, labelLine: { show: false },
          itemStyle: { borderColor: "#fff", borderWidth: 2 },
          data: rows.map((r, i) => ({ ...r, itemStyle: { color: paletteColor(i) } })),
        }],
      }}
    />
  );
}

// ---- flows by protocol (ClickHouse) ----------------------------------------

function FlowsByProto() {
  const res = usePolled(() => api.flowsByProto(3600), 30000);
  const rows = ((res?.data as { proto: string; bytes_total: number }[]) ?? [])
    .map((r) => ({ name: r.proto || "other", value: Number(r.bytes_total) }))
    .filter((r) => r.value > 0)
    .slice(0, 8);
  return <Donut rows={rows} unit="B" />;
}

// ---- device inventory by vendor --------------------------------------------

function DevicesByVendor() {
  const devices = usePolled(() => api.devices(), 30000) ?? [];
  const by: Record<string, number> = {};
  for (const d of devices as Device[]) by[d.vendor || "unknown"] = (by[d.vendor || "unknown"] ?? 0) + 1;
  const rows = Object.entries(by).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  return <Donut rows={rows} unit="devices" />;
}

// ---- tunnels health (IPsec / SD-WAN) ---------------------------------------

function TunnelsHealth() {
  const res = usePolled(() => api.tunnels(500), 20000);
  const rows = (res?.data as Tunnel[]) ?? [];
  if (rows.length === 0) return <Empty msg="No tunnel telemetry yet." />;
  const up = rows.filter((t) => String(t.status).toLowerCase() === "up").length;
  const down = rows.length - up;
  const lats = rows.map((t) => Number(t.latency_ms)).filter((n) => Number.isFinite(n) && n > 0);
  const avg = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null;
  const worst = lats.length ? Math.round(Math.max(...lats)) : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
      <div className="stat s-good"><span className="stat-label">Tunnels up</span><span className="stat-value">{up}</span></div>
      <div className={`stat ${down ? "s-bad" : "s-good"}`}><span className="stat-label">Tunnels down</span><span className="stat-value">{down}</span></div>
      <div className="stat s-accent"><span className="stat-label">Avg latency</span><span className="stat-value">{avg ?? "—"}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></span></div>
      <div className={`stat ${worst && worst > 120 ? "s-warn" : "s-accent"}`}><span className="stat-label">Worst latency</span><span className="stat-value">{worst ?? "—"}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></span></div>
    </div>
  );
}

// ---- recent incidents (correlation findings) -------------------------------

function RecentIncidents() {
  const res = usePolled(() => api.findings(12), 20000);
  const rows = ((res?.data as Finding[]) ?? []).slice(0, 8);
  if (rows.length === 0) return <Empty msg="No correlated incidents." />;
  return (
    <div className="alerts-scroll">
      {rows.map((f, i) => (
        <div className="mini-row" key={f.id ?? i}>
          <span className={`badge ${severityClass(f.severity)}`}>{f.severity || "info"}</span>
          <div className="mini-body">
            <div className="mini-title">{f.summary || f.kind || "(incident)"}</div>
            <div className="mini-meta">
              {f.device}{f.component ? ` · ${f.component}` : ""}
              {f.ts ? ` · ${new Date(f.ts).toLocaleString()}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- registry --------------------------------------------------------------

export type PanelCategory = "Health & KPIs" | "Resources" | "Alerts" | "Traffic" | "Inventory" | "Topology";

export type PanelDef = {
  type: string;
  title: string;
  defaultSpan: number; // 3 | 4 | 6 | 8 | 12
  category: PanelCategory;
  render: () => JSX.Element;
};

export const PANELS: Record<string, PanelDef> = {
  kpis: { type: "kpis", title: "KPIs", defaultSpan: 12, category: "Health & KPIs", render: () => <KpiTiles /> },
  "site-availability": { type: "site-availability", title: "Site availability", defaultSpan: 3, category: "Health & KPIs", render: () => <SiteAvailability /> },
  "stack-performance": { type: "stack-performance", title: "Stack performance", defaultSpan: 6, category: "Health & KPIs", render: () => <StackPerformance /> },
  "gauge-cpu": { type: "gauge-cpu", title: "CPU", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_cpu_percent)" /> },
  "gauge-mem": { type: "gauge-mem", title: "Memory", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_mem_percent)" /> },
  "gauge-storage": { type: "gauge-storage", title: "Storage", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_storage_percent)" /> },
  "gauge-network": { type: "gauge-network", title: "Network util", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_if_util_percent)" /> },
  "alerts-severity": { type: "alerts-severity", title: "Alerts by severity", defaultSpan: 12, category: "Alerts", render: () => <AlertsSeverity /> },
  "active-alerts": { type: "active-alerts", title: "Active alerts", defaultSpan: 6, category: "Alerts", render: () => <ActiveAlerts /> },
  incidents: { type: "incidents", title: "Recent incidents", defaultSpan: 6, category: "Alerts", render: () => <RecentIncidents /> },
  traffic: { type: "traffic", title: "Traffic in / out", defaultSpan: 8, category: "Traffic", render: () => <TrafficInOut /> },
  "top-hosts": { type: "top-hosts", title: "Top hosts", defaultSpan: 4, category: "Traffic", render: () => <TopHosts /> },
  "flows-proto": { type: "flows-proto", title: "Traffic by protocol", defaultSpan: 4, category: "Traffic", render: () => <FlowsByProto /> },
  "tunnels-health": { type: "tunnels-health", title: "Tunnels health", defaultSpan: 4, category: "Traffic", render: () => <TunnelsHealth /> },
  "devices-vendor": { type: "devices-vendor", title: "Devices by vendor", defaultSpan: 4, category: "Inventory", render: () => <DevicesByVendor /> },
  topology: { type: "topology", title: "Topology", defaultSpan: 12, category: "Topology", render: () => <TopologyPanel /> },
};

// Category groups for the "Add panel" picker, in display order.
export const PANEL_CATEGORIES: { category: PanelCategory; types: string[] }[] = [
  { category: "Health & KPIs", types: ["kpis", "site-availability", "stack-performance"] },
  { category: "Resources", types: ["gauge-cpu", "gauge-mem", "gauge-storage", "gauge-network"] },
  { category: "Alerts", types: ["alerts-severity", "active-alerts", "incidents"] },
  { category: "Traffic", types: ["traffic", "top-hosts", "flows-proto", "tunnels-health"] },
  { category: "Inventory", types: ["devices-vendor"] },
  { category: "Topology", types: ["topology"] },
];

// Flat order (derived) — kept for any callers that still want a simple list.
export const PANEL_ORDER = PANEL_CATEGORIES.flatMap((c) => c.types);
