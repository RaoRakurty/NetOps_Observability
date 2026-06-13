// panels.tsx — the modular Overview panel library. Each panel is a small,
// self-contained component that fetches its own data on an interval and binds
// to the real backend APIs (metrics over VictoriaMetrics, alerts, flows,
// collectors, devices). The registry below is what the Dashboard shell renders
// and what the "Add panel" picker lists. Panels render only their body — the
// shell draws the title bar + resize/remove tools.

import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Alert, MetricTile, PromRangeResponse, PromInstantResponse, CollectorStatus, Device, Finding, Tunnel } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor, hexToRgba } from "../theme/charts";
import { cssVar } from "../theme/tokens";
import { severityClass, SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import { usePrefs } from "../theme/prefs";
import { useShell } from "../context/shell";
import { setDrill } from "../theme/drill";
import Topology from "../tabs/Topology";

// Map a KPI tile title to its drilldown destination (and optional one-shot
// filter the destination page consumes). Keeps the Overview's headline numbers
// clickable: a count is only useful if you can jump to what it counts.
function kpiDestination(title: string): { route: string; drill?: Record<string, string> } | null {
  const t = title.toLowerCase();
  if (t.includes("down")) return { route: "infrastructure/devices", drill: { devices: "down" } };
  if (t.includes("threat") || t.includes("critical")) return { route: "alerts/active" };
  if (t.includes("site")) return { route: "topology/map" };
  if (t.includes("device")) return { route: "infrastructure/devices" };
  return null;
}

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
  // Multi-colored arc: a vivid teal→green→amber→orange→rose sweep along the
  // wheel (Grafana style), so the ring reads lively and the fill colour
  // naturally tracks severity as it grows. Idle (no data) shows soft indigo.
  const progressColor = v === null
    ? { type: "linear", x: 0, y: 0, x2: 1, y2: 1, colorStops: [{ offset: 0, color: "#a5b4fc" }, { offset: 1, color: "#818cf8" }] }
    : {
        type: "linear", x: 0, y: 0, x2: 1, y2: 0,
        colorStops: [
          { offset: 0.0, color: "#22d3ee" }, // cyan
          { offset: 0.35, color: "#34d399" }, // emerald
          { offset: 0.6, color: "#fbbf24" }, // amber
          { offset: 0.8, color: "#fb923c" }, // orange
          { offset: 1.0, color: "#f43f5e" }, // rose
        ],
      };
  // Glow hue tracks the current value's severity band.
  const t = goodHigh ? 1 - pct : pct;
  const glow = v === null ? "#818cf8" : t < 0.7 ? "#10b981" : t < 0.9 ? "#f59e0b" : "#f43f5e";
  // Theme-aware glassy track: a soft cool gradient on light, deep slate on dark
  // (the old flat #eef1f6 looked wrong against the dark canvas). A faint idle
  // ring is always drawn so the wheel never reads as empty grey.
  const dark = theme !== "light"; // dark + oled both use the dark track
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
            // glassy track — the Grafana modern-gauge look.
            center: ["50%", "60%"],
            radius: "118%",
            startAngle: 220,
            endAngle: -40,
            progress: { show: true, width: 30, roundCap: true, itemStyle: { color: progressColor, shadowBlur: 12, shadowColor: hexToRgba(glow, 0.5) } },
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
  const { navigate } = useShell();
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
          style={{ borderLeftColor: SEVERITY_COLOR[k], cursor: "pointer" }}
          role="button"
          title={`View ${k} alerts`}
          onClick={() => navigate("alerts/active")}
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
  const { navigate } = useShell();
  const alerts = (usePolled(() => api.alerts(), 10000) ?? []).slice(0, 10);
  if (alerts.length === 0) return <Empty msg="All clear — no active alerts." />;
  return (
    <div className="alerts-scroll">
      {alerts.map((a: Alert, i) => (
        <div
          className="mini-row"
          key={a.id ?? i}
          style={{ cursor: "pointer" }}
          role="button"
          title="Open in Alerts"
          onClick={() => navigate("alerts/active")}
        >
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
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ color: "var(--muted)", fontSize: "var(--fs-meta)", marginBottom: 2 }}>
        Aggregate of all interfaces across all devices (Σ, bit/s)
      </div>
      <ReactECharts
        style={{ height: 220 }}
        option={{
          ...chartBase,
          grid: { left: 64, right: 12, top: 16, bottom: 24 },
          tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtBps(v) },
          legend: { ...chartBase.legend, top: 0, data: ["In", "Out"] },
          xAxis: { type: "time", ...axisStyle },
          yAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtBps(v) } },
          series: [
            { name: "In", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(0), width: 2 }, itemStyle: { color: paletteColor(0) }, areaStyle: { color: areaGradient(0) }, data: inS },
            { name: "Out", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(2), width: 2 }, itemStyle: { color: paletteColor(2) }, areaStyle: { color: areaGradient(2) }, data: outS },
          ],
        }}
      />
    </div>
  );
}

// fmtBps renders a bit/s value with industry-standard SI scaling.
function fmtBps(v: number): string {
  if (!isFinite(v) || v <= 0) return "0 bps";
  const u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0, n = v;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n.toFixed(n < 10 && i > 0 ? 2 : 0)} ${u[i]}`;
}

// ---- WAN interfaces — continuous live telemetry ------------------------------
// Identifies WAN/edge ports by device-name pattern (no ifName label exists in
// the SNMP metric set, so device identity is the reliable selector; the
// pattern is editable + persisted). Polls every 10s: aggregate in/out bps
// trend plus a per-interface live table (throughput, utilization vs ifSpeed,
// error rate, oper status).
const WAN_PATTERN_KEY = "netops.overview.wanPattern";

function WanInterfaces() {
  const [pattern, setPattern] = useState<string>(() => localStorage.getItem(WAN_PATTERN_KEY) || "wan|edge|dmz|gw");
  const [draft, setDraft] = useState(pattern);
  const sel = `{device=~"(?i).*(${pattern}).*"}`;

  const data = usePolled(async () => {
    const [s0, e0, st0] = nowWindow(1800, 30);
    const [trIn, trOut, inb, outb, speed, errs, oper] = await Promise.all([
      api.metricsQueryRange(`sum(rate(device_if_in_octets${sel}[2m]))*8`, s0, e0, st0).catch(() => undefined),
      api.metricsQueryRange(`sum(rate(device_if_out_octets${sel}[2m]))*8`, s0, e0, st0).catch(() => undefined),
      api.metricsQuery(`rate(device_if_in_octets${sel}[2m])*8`).catch(() => undefined),
      api.metricsQuery(`rate(device_if_out_octets${sel}[2m])*8`).catch(() => undefined),
      api.metricsQuery(`device_if_speed${sel}`).catch(() => undefined),
      api.metricsQuery(`rate(device_if_in_errors${sel}[5m]) + rate(device_if_out_errors${sel}[5m]) + rate(device_if_in_discards${sel}[5m]) + rate(device_if_out_discards${sel}[5m])`).catch(() => undefined),
      api.metricsQuery(`device_if_oper_status${sel}`).catch(() => undefined),
    ]);
    return { trIn, trOut, inb, outb, speed, errs, oper };
  }, 10000);

  const key = (m: Record<string, string>) => `${m.device}#${m.index}`;
  const idx = (r?: PromInstantResponse) => {
    const out: Record<string, number> = {};
    for (const x of r?.data?.result ?? []) out[key(x.metric)] = Number(x.value?.[1]);
    return out;
  };
  const inB = idx(data?.inb), outB = idx(data?.outb), spd = idx(data?.speed), erR = idx(data?.errs), opS = idx(data?.oper);
  type Row = { k: string; device: string; ifx: string; inb: number; outb: number; util: number; errs: number; up: boolean };
  const rows: Row[] = (data?.inb?.data?.result ?? []).map((x) => {
    const k = key(x.metric);
    const speedBps = (spd[k] || 0) * 1e6; // device_if_speed is ifHighSpeed (Mbps)
    const maxBps = Math.max(inB[k] || 0, outB[k] || 0);
    return {
      k, device: x.metric.device, ifx: x.metric.index,
      inb: inB[k] || 0, outb: outB[k] || 0,
      util: speedBps > 0 ? (maxBps / speedBps) * 100 : 0,
      errs: erR[k] || 0,
      up: (opS[k] ?? 1) === 1,
    };
  }).sort((a, b) => b.util - a.util || (b.inb + b.outb) - (a.inb + a.outb)).slice(0, 8);

  const toSeries = (r?: PromRangeResponse) => (r?.data?.result?.[0]?.values ?? []).map((v) => [v[0] * 1000, Number(v[1])]);
  const inS = toSeries(data?.trIn), outS = toSeries(data?.trOut);
  const totIn = rows.reduce((a, r) => a + r.inb, 0), totOut = rows.reduce((a, r) => a + r.outb, 0);
  const down = rows.filter((r) => !r.up).length;
  const worst = rows.length ? Math.max(...rows.map((r) => r.util)) : 0;

  const applyPattern = () => {
    const v = draft.trim() || "wan";
    setPattern(v); localStorage.setItem(WAN_PATTERN_KEY, v);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <span className="badge good" title="Polling every 10 seconds">● LIVE · 10s</span>
        <span className="mini-meta">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)} · peak util {worst.toFixed(1)}%{down > 0 ? ` · ${down} down` : ""}</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 4, alignItems: "center" }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && applyPattern()}
            title="WAN device pattern (regex on device name)" style={{ width: 130, fontSize: 12, padding: "3px 6px", border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", color: "var(--fg)" }} />
          <button className="dash-btn" style={{ padding: "3px 8px", fontSize: 12 }} onClick={applyPattern}>Apply</button>
        </span>
      </div>
      {inS.length === 0 && rows.length === 0 ? (
        <Empty msg={`No interfaces match device pattern “${pattern}” — adjust it (regex, e.g. wan|edge|dmz).`} />
      ) : (
        <>
          <ReactECharts
            style={{ height: 150 }}
            option={{
              ...chartBase,
              grid: { left: 60, right: 10, top: 8, bottom: 20 },
              tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtBps(v) },
              legend: { show: false },
              xAxis: { type: "time", ...axisStyle },
              yAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtBps(v) } },
              series: [
                { name: "In", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(0), width: 2 }, itemStyle: { color: paletteColor(0) }, areaStyle: { color: areaGradient(0) }, data: inS },
                { name: "Out", type: "line", smooth: true, showSymbol: false, lineStyle: { color: paletteColor(2), width: 2 }, itemStyle: { color: paletteColor(2) }, data: outS },
              ],
            }}
          />
          <table className="mini-table">
            <tbody>
              {rows.map((r) => (
                <tr key={r.k}>
                  <td><span className="dot" style={{ display: "inline-block", width: 8, height: 8, borderRadius: 4, background: r.up ? "var(--good)" : "var(--bad)", marginRight: 6 }} />
                    <span className="mono">{r.device}</span> <span className="mini-meta">if{r.ifx}</span></td>
                  <td style={{ textAlign: "right" }} className="mono">↓ {fmtBps(r.inb)}</td>
                  <td style={{ textAlign: "right" }} className="mono">↑ {fmtBps(r.outb)}</td>
                  <td style={{ width: 110 }}>
                    <div className="bar-track" style={{ background: "var(--surface-2)", borderRadius: 4, height: 8, overflow: "hidden" }}>
                      <div style={{ width: `${Math.min(100, r.util)}%`, height: "100%", borderRadius: 4,
                        background: r.util >= 90 ? "var(--bad)" : r.util >= 70 ? "var(--warn)" : "var(--accent)" }} />
                    </div>
                  </td>
                  <td style={{ textAlign: "right", width: 70 }} className={r.util >= 90 ? "mono" : "mini-meta mono"}>{r.util.toFixed(1)}%</td>
                  <td style={{ textAlign: "right", width: 80 }} className="mini-meta mono" title="errors+discards per second">{r.errs > 0.005 ? `${r.errs.toFixed(2)}/s` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function TopHosts() {
  const { navigate } = useShell();
  const res = usePolled(() => api.topTalkers(3600, 8), 30000);
  const rows = ((res?.data as { src: string; dst: string; bytes_total: number }[]) ?? []).slice(0, 8);
  if (rows.length === 0) return <Empty msg="No flow data yet." />;
  return (
    <table className="mini-table">
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} style={{ cursor: "pointer" }} title="View in Flows" onClick={() => navigate("explore/flows")}>
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
  const { navigate } = useShell();
  const cols = useProtocolCollectors();
  const targets = cols.reduce((n, c) => n + (c.targets ?? 0), 0);
  const reachable = cols.reduce((n, c) => n + (c.reachable ?? 0), 0);
  const pct = targets > 0 ? Math.round((reachable / targets) * 100) : null;
  const cls = pct === null ? "s-muted" : pct >= 99 ? "s-good" : pct >= 90 ? "s-warn" : "s-bad";
  return (
    <div className={`stat ${cls}`} style={{ border: 0, padding: 0, cursor: "pointer" }} role="button" title="View devices" onClick={() => navigate("infrastructure/devices")}>
      <span className="stat-value">{pct === null ? "—" : `${pct}%`}</span>
      <span className="stat-sub">{reachable}/{targets} targets reachable</span>
    </div>
  );
}

function StackPerformance() {
  const { navigate } = useShell();
  const cols = useProtocolCollectors();
  const enabled = cols.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.healthy).length;
  const avgMs =
    cols.length > 0
      ? Math.round(cols.reduce((n, c) => n + (c.last_poll_ms ?? 0), 0) / cols.length)
      : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr", cursor: "pointer" }} role="button" title="View metrics" onClick={() => navigate("explore/metrics")}>
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
  const { navigate } = useShell();
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
        const dest = kpiDestination(m.title);
        const go = dest
          ? () => {
              if (dest.drill) setDrill(dest.drill);
              navigate(dest.route);
            }
          : undefined;
        return (
          <div
            className={`stat ${cls}${go ? " stat-link" : ""}`}
            key={m.title}
            onClick={go}
            role={go ? "button" : undefined}
            title={go ? "View details" : undefined}
            style={go ? { cursor: "pointer" } : undefined}
          >
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

function Donut({ rows, unit, onClick }: { rows: { name: string; value: number }[]; unit?: string; onClick?: () => void }) {
  if (rows.length === 0) return <Empty msg="No data yet." />;
  return (
    <ReactECharts
      style={{ height: 190, cursor: onClick ? "pointer" : undefined }}
      onEvents={onClick ? { click: onClick } : undefined}
      option={{
        ...chartBase,
        tooltip: { ...chartBase.tooltip, trigger: "item", formatter: `{b}: {c}${unit ? " " + unit : ""} ({d}%)` },
        legend: { ...chartBase.legend, type: "scroll", orient: "vertical", right: 4, top: "center", itemWidth: 9, itemHeight: 9, textStyle: { color: cssVar("--fg-muted", "#667085"), fontSize: 12 } },
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

const PROTO_NAMES: Record<string, string> = {
  "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "47": "GRE",
  "50": "ESP", "51": "AH", "58": "ICMPv6", "89": "OSPF", "132": "SCTP",
};

function FlowsByProto() {
  const { navigate } = useShell();
  const res = usePolled(() => api.flowsByProto(3600), 30000);
  const rows = ((res?.data as { proto: string | number; bytes_total: number }[]) ?? [])
    .map((r) => ({ name: PROTO_NAMES[String(r.proto)] ?? `proto ${r.proto}`, value: Number(r.bytes_total) }))
    .filter((r) => r.value > 0)
    .slice(0, 8);
  return <Donut rows={rows} unit="B" onClick={() => navigate("explore/flows")} />;
}

// ---- device inventory by vendor --------------------------------------------

function DevicesByVendor() {
  const { navigate } = useShell();
  const devices = usePolled(() => api.devices(), 30000) ?? [];
  const by: Record<string, number> = {};
  for (const d of devices as Device[]) by[d.vendor || "unknown"] = (by[d.vendor || "unknown"] ?? 0) + 1;
  const rows = Object.entries(by).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  return <Donut rows={rows} unit="devices" onClick={() => navigate("infrastructure/devices")} />;
}

// ---- tunnels health (IPsec / SD-WAN) ---------------------------------------

function TunnelsHealth() {
  const { navigate } = useShell();
  const res = usePolled(() => api.tunnels(500), 20000);
  const rows = (res?.data as Tunnel[]) ?? [];
  if (rows.length === 0) return <Empty msg="No tunnel telemetry yet." />;
  const up = rows.filter((t) => String(t.status).toLowerCase() === "up").length;
  const down = rows.length - up;
  const lats = rows.map((t) => Number(t.latency_ms)).filter((n) => Number.isFinite(n) && n > 0);
  const avg = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null;
  const worst = lats.length ? Math.round(Math.max(...lats)) : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr", cursor: "pointer" }} role="button" title="View tunnels" onClick={() => navigate("topology/tunnels")}>
      <div className="stat s-good"><span className="stat-label">Tunnels up</span><span className="stat-value">{up}</span></div>
      <div className={`stat ${down ? "s-bad" : "s-good"}`}><span className="stat-label">Tunnels down</span><span className="stat-value">{down}</span></div>
      <div className="stat s-accent"><span className="stat-label">Avg latency</span><span className="stat-value">{avg ?? "—"}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></span></div>
      <div className={`stat ${worst && worst > 120 ? "s-warn" : "s-accent"}`}><span className="stat-label">Worst latency</span><span className="stat-value">{worst ?? "—"}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></span></div>
    </div>
  );
}

// ---- recent incidents (correlation findings) -------------------------------

function RecentIncidents() {
  const { navigate } = useShell();
  const res = usePolled(() => api.findings(12), 20000);
  const rows = ((res?.data as Finding[]) ?? []).slice(0, 8);
  if (rows.length === 0) return <Empty msg="No correlated incidents." />;
  return (
    <div className="alerts-scroll">
      {rows.map((f, i) => (
        <div className="mini-row" key={f.id ?? i} style={{ cursor: "pointer" }} title="Open in Incidents" onClick={() => navigate("alerts/incidents")}>
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
  drill?: string; // hash route the panel header links to (Overview → detail)
};

export const PANELS: Record<string, PanelDef> = {
  kpis: { type: "kpis", title: "KPIs", defaultSpan: 12, category: "Health & KPIs", render: () => <KpiTiles /> },
  "site-availability": { type: "site-availability", title: "Site availability", defaultSpan: 3, category: "Health & KPIs", render: () => <SiteAvailability />, drill: "infrastructure/devices" },
  "stack-performance": { type: "stack-performance", title: "Stack performance", defaultSpan: 6, category: "Health & KPIs", render: () => <StackPerformance />, drill: "explore/metrics" },
  "gauge-cpu": { type: "gauge-cpu", title: "CPU", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_cpu_percent)" />, drill: "explore/metrics" },
  "gauge-mem": { type: "gauge-mem", title: "Memory", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="avg(device_mem_percent or (100 * device_mem_used_bytes / (device_mem_used_bytes + device_mem_free_bytes)) or (100 * (device_mem_total_kb - device_mem_available_kb) / device_mem_total_kb))" />, drill: "explore/metrics" },
  "gauge-storage": { type: "gauge-storage", title: "Storage", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="100 * sum(device_storage_used) / sum(device_storage_size)" />, drill: "explore/metrics" },
  "gauge-network": { type: "gauge-network", title: "Bandwidth utilization", defaultSpan: 3, category: "Resources", render: () => <MetricGauge query="100 * sum(rate(device_if_in_octets[5m]) * 8) / (sum(device_if_speed * 1000000) > 0)" />, drill: "explore/metrics" },
  "wan-interfaces": { type: "wan-interfaces", title: "WAN interfaces — live", defaultSpan: 8, category: "Traffic", render: () => <WanInterfaces />, drill: "infrastructure/ifperf" },
  "alerts-severity": { type: "alerts-severity", title: "Alerts by severity", defaultSpan: 12, category: "Alerts", render: () => <AlertsSeverity />, drill: "alerts/active" },
  "active-alerts": { type: "active-alerts", title: "Active alerts", defaultSpan: 6, category: "Alerts", render: () => <ActiveAlerts />, drill: "alerts/active" },
  incidents: { type: "incidents", title: "Recent incidents", defaultSpan: 6, category: "Alerts", render: () => <RecentIncidents />, drill: "alerts/incidents" },
  traffic: { type: "traffic", title: "Traffic in / out", defaultSpan: 8, category: "Traffic", render: () => <TrafficInOut />, drill: "explore/flows" },
  "top-hosts": { type: "top-hosts", title: "Top hosts", defaultSpan: 4, category: "Traffic", render: () => <TopHosts />, drill: "explore/flows" },
  "flows-proto": { type: "flows-proto", title: "Traffic by protocol", defaultSpan: 4, category: "Traffic", render: () => <FlowsByProto />, drill: "explore/flows" },
  "tunnels-health": { type: "tunnels-health", title: "Tunnels health", defaultSpan: 4, category: "Traffic", render: () => <TunnelsHealth />, drill: "topology/tunnels" },
  "devices-vendor": { type: "devices-vendor", title: "Devices by vendor", defaultSpan: 4, category: "Inventory", render: () => <DevicesByVendor />, drill: "infrastructure/devices" },
  topology: { type: "topology", title: "Topology", defaultSpan: 12, category: "Topology", render: () => <TopologyPanel />, drill: "topology/map" },
};

// Category groups for the "Add panel" picker, in display order.
export const PANEL_CATEGORIES: { category: PanelCategory; types: string[] }[] = [
  { category: "Health & KPIs", types: ["kpis", "site-availability", "stack-performance"] },
  { category: "Resources", types: ["gauge-cpu", "gauge-mem", "gauge-storage", "gauge-network"] },
  { category: "Alerts", types: ["alerts-severity", "active-alerts", "incidents"] },
  { category: "Traffic", types: ["wan-interfaces", "traffic", "top-hosts", "flows-proto", "tunnels-health"] },
  { category: "Inventory", types: ["devices-vendor"] },
  { category: "Topology", types: ["topology"] },
];

// Flat order (derived) — kept for any callers that still want a simple list.
export const PANEL_ORDER = PANEL_CATEGORIES.flatMap((c) => c.types);
