// panels.tsx — the modular Overview panel library. Each panel is a small,
// self-contained component that fetches its own data on an interval and binds
// to the real backend APIs (metrics over VictoriaMetrics, alerts, flows,
// collectors, devices). The registry below is what the Dashboard shell renders
// and what the "Add panel" picker lists. Panels render only their body — the
// shell draws the title bar + resize/remove tools.

import { fmtDateTime } from "../lib/time";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import ReactECharts from "echarts-for-react";
import { api, Alert, PromRangeResponse, PromInstantResponse, CollectorStatus, Device, Finding, Tunnel } from "../services/api";
import { chartBase, axisStyle, timeAxisTicks, areaGradient, paletteColor, hexToRgba } from "../theme/charts";
import { cssVar } from "../theme/tokens";
import { severityClass, SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import { usePrefs } from "../theme/prefs";
import { useShell } from "../context/shell";
import { setDrill } from "../theme/drill";
import TopologyCanvas from "../features/topology/renderers/react-flow/TopologyCanvas";

// pressable — shared keyboard-activation props for click-to-navigate tiles that
// are not <button>s (stat grids, KPI tiles, mini-rows). Gives every role="button"
// a tab stop and Enter/Space activation (WCAG 2.1.1).
function pressable(fn: () => void) {
  return {
    role: "button" as const,
    tabIndex: 0,
    onClick: fn,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fn();
      }
    },
  };
}


// ---- shared helpers --------------------------------------------------------

// ---- board freshness signal ------------------------------------------------
// The Dashboard header's liveness indicator must be driven by REAL fetch
// outcomes, never a wall clock: a ticking "as of HH:MM" beside a pulsing dot is
// an affirmative claim that data is flowing. Every usePolled reports each poll
// outcome here and the shell reads the aggregate — last successful load plus how
// many feeds are currently failing — so a backend outage reads "Disconnected".
export type BoardHealth = { lastOk: number | null; failing: number; feeds: number };

let boardHealth: BoardHealth = { lastOk: null, failing: 0, feeds: 0 };
const boardListeners = new Set<() => void>();

function setBoardHealth(patch: Partial<BoardHealth>) {
  boardHealth = { ...boardHealth, ...patch };
  for (const l of boardListeners) l();
}

function subscribeBoardHealth(fn: () => void): () => void {
  boardListeners.add(fn);
  return () => { boardListeners.delete(fn); };
}

/** useBoardHealth — the honest liveness of the panel board (see BoardHealth). */
export function useBoardHealth(): BoardHealth {
  return useSyncExternalStore(subscribeBoardHealth, () => boardHealth, () => boardHealth);
}

/** Test seam: reset the module-level freshness signal between renders. */
export function __resetBoardHealth(): void {
  boardHealth = { lastOk: null, failing: 0, feeds: 0 };
  for (const l of boardListeners) l();
}

// Polled<T> — the {data, err} shape used across the app (FrontPage's usePoll,
// the appobs tri-state). A failed fetch is NOT no-data: callers must be able to
// tell "the API said zero" from "the API never answered", because an empty array
// rendered as "All clear" is a failure reported as good news.
type Polled<T> = { data: T | undefined; err: boolean };

function usePolled<T>(loader: () => Promise<T>, intervalMs = 15000): Polled<T> {
  const [state, setState] = useState<Polled<T>>({ data: undefined, err: false });
  const failing = useRef(false);
  useEffect(() => {
    let alive = true;
    setBoardHealth({ feeds: boardHealth.feeds + 1 });
    const tick = async () => {
      try {
        const r = await loader();
        if (!alive) return;
        setState({ data: r, err: false });
        if (failing.current) { failing.current = false; setBoardHealth({ failing: Math.max(0, boardHealth.failing - 1) }); }
        setBoardHealth({ lastOk: Date.now() });
      } catch {
        if (!alive) return;
        // Keep the last good value on screen, but SAY the refresh failed.
        setState((cur) => ({ data: cur.data, err: true }));
        if (!failing.current) { failing.current = true; setBoardHealth({ failing: boardHealth.failing + 1 }); }
      }
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
      setBoardHealth({
        feeds: Math.max(0, boardHealth.feeds - 1),
        failing: failing.current ? Math.max(0, boardHealth.failing - 1) : boardHealth.failing,
      });
      failing.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return state;
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

// Unavailable — the DEGRADED reading (FrontPage's Panel state="degraded"
// equivalent for the registry panels). Never rendered as an empty/zero state:
// "we could not read this" is a different claim from "there is nothing here".
function Unavailable({ msg = "Source unavailable — this panel could not be refreshed." }: { msg?: string }) {
  return (
    <div className="panel-empty" role="status" style={{ color: "var(--warn)" }}>
      <span style={{ fontWeight: 600 }}>Unavailable</span>
      <div style={{ color: "var(--muted)", marginTop: 2 }}>{msg}</div>
    </div>
  );
}

// Loading — an explicit third state, so "still reading" never looks like a
// verdict about the network.
function Loading() {
  return <div className="panel-empty">…</div>;
}

// seriesLabel picks the most identifying label off a metric's label set, in the
// order that reads best for an operator: interface (device·ifName) → device
// (device·index) → synthetic-probe target (dst) → generic. Shared by every
// per-series panel so labelling is consistent across the board.
function seriesLabel(m: Record<string, string>): string {
  if (m.ifName) return m.device ? `${m.device}·${m.ifName}` : m.ifName;
  if (m.device) return m.index ? `${m.device}·${m.index}` : m.device;
  return m.dst || m.instance || m.mount || m.peer || "series";
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
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(300);
    return api.metricsQueryRange(query, s, e, st);
  });
  // A metrics-plane outage must not draw an idle wheel that reads "0 / nothing
  // wrong" — say the reading failed.
  if (err && !res) return <Unavailable msg="Metrics query failed — this gauge has no current reading." />;
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
                v: { fontSize: 34, fontWeight: 800, color: dark ? "#e7ebf3" : "#161d29" },
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

// ---- saturation time-series panels (replaces the radial gauges) ------------
// The "Top Jobs / Auxiliary Storage Pools" treatment from the reference boards:
// a compact multi-series area chart over a short window — a real trend, not a
// single instantaneous wheel. One series per source (device / mount / interface),
// top-N by current value, with a headline current+peak summary so the card still
// reads at NOC distance. Source-agnostic: any PromQL that yields one-or-more
// series works; a single aggregate query just draws one line.
function MetricArea({
  query,
  unit = "%",
  summary = "avg", // headline aggregate across series: avg (for %) or sum (counts)
  goodHigh = false,
  fmt,
  windowSec = 1800,
  step = 30,
}: {
  query: string;
  unit?: string;
  summary?: "avg" | "sum";
  goodHigh?: boolean; // true => high is good (color flips)
  fmt?: (v: number) => string;
  windowSec?: number;
  step?: number;
}) {
  usePrefs(); // re-render on theme flip (chart chrome resolves from tokens)
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(windowSec, step);
    return api.metricsQueryRange(query, s, e, st);
  });
  // "No telemetry yet" is a claim about the NETWORK; only make it when the query
  // actually answered.
  if (err && !res) return <Unavailable msg="Metrics query failed — telemetry coverage is unknown." />;
  const raw = res?.data?.result ?? [];
  if (res && raw.length === 0)
    return <Empty msg="No telemetry yet (enable SNMP metrics)." />;

  type S = { name: string; data: [number, number][]; last: number };
  const series: S[] = raw
    .map((s) => {
      const data = (s.values ?? []).map((v) => [v[0] * 1000, Number(v[1])] as [number, number]);
      let last = 0;
      for (let i = data.length - 1; i >= 0; i--) if (Number.isFinite(data[i][1])) { last = data[i][1]; break; }
      return { name: seriesLabel(s.metric), data, last };
    })
    .sort((a, b) => b.last - a.last);

  const fmtv = fmt ?? ((v: number) => `${Math.round(v)}${unit}`);
  const lasts = series.map((s) => s.last);
  const total = lasts.reduce((a, b) => a + b, 0);
  const current = summary === "sum" ? total : total / (lasts.length || 1);
  let peak = 0;
  for (const s of series) for (const p of s.data) if (Number.isFinite(p[1]) && p[1] > peak) peak = p[1];

  // headline color tracks the saturation band (only meaningful for %)
  const t = unit === "%" ? (goodHigh ? 100 - current : current) / 100 : 0;
  const headColor = unit !== "%" ? "var(--fg)" : t < 0.7 ? "var(--good)" : t < 0.9 ? "var(--warn)" : "var(--bad)";

  const top = series.slice(0, 8);
  const echSeries = top.map((s, i) => ({
    name: s.name,
    type: "line" as const,
    smooth: true,
    showSymbol: false,
    lineStyle: { width: 1.5, color: paletteColor(i) },
    itemStyle: { color: paletteColor(i) },
    areaStyle: { color: areaGradient(i), opacity: top.length > 1 ? 0.55 : 0.9 },
    data: s.data,
  }));

  return (
    <div className="sat-panel">
      <div className="sat-head">
        <span className="sat-now" style={{ color: headColor }}>{res ? fmtv(current) : "—"}</span>
        <span className="sat-sub">peak {fmtv(peak)}{series.length > 1 ? ` · ${series.length} src` : ""}</span>
      </div>
      <ReactECharts
        notMerge
        style={{ height: 134 }}
        option={{
          ...chartBase,
          grid: { left: 2, right: 8, top: 6, bottom: 2, containLabel: true },
          tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtv(v) },
          legend: { show: false },
          xAxis: { type: "time", ...axisStyle, ...timeAxisTicks(), axisLabel: { ...timeAxisTicks().axisLabel, fontSize: 11 } },
          yAxis: {
            type: "value",
            ...axisStyle,
            max: unit === "%" ? 100 : undefined,
            axisLabel: { ...(axisStyle as any).axisLabel, fontSize: 11, formatter: (v: number) => fmtv(v) },
          },
          series: echSeries,
        }}
      />
    </div>
  );
}

// ---- Top-N horizontal bar --------------------------------------------------
// The reference boards' "Avg Request duration by country (Top 20)" treatment:
// rank entities by a single instant value, colour each bar by its severity band.
// The correct answer for "which N are worst" — you can't trend 2000 ports, but
// you can rank them. (USE-method: rank utilisation/errors, don't gauge each.)
function TopNBar({
  query,
  unit = "%",
  n = 8,
  fmt,
  warn = 70,
  danger = 90,
  goodHigh = false,
}: {
  query: string;
  unit?: string;
  n?: number;
  fmt?: (v: number) => string;
  warn?: number;
  danger?: number;
  goodHigh?: boolean;
}) {
  usePrefs();
  const { data: res, err } = usePolled(() => api.metricsQuery(query), 15000);
  const rows = (res?.data?.result ?? [])
    .map((x) => ({ name: seriesLabel(x.metric), v: Number(x.value?.[1]) }))
    .filter((r) => Number.isFinite(r.v) && r.v > 0)
    .sort((a, b) => b.v - a.v)
    .slice(0, n);
  // "Nothing above zero" would report a query outage as a clean network.
  if (err && !res) return <Unavailable msg="Metrics query failed — this ranking is unavailable." />;
  if (res && rows.length === 0) return <Empty msg="Nothing above zero in this window." />;
  if (!res) return <Loading />;

  const fmtv = fmt ?? ((v: number) => `${Math.round(v)}${unit}`);
  const band = (v: number) => {
    const t = goodHigh ? -v : v;
    const w = goodHigh ? -warn : warn;
    const d = goodHigh ? -danger : danger;
    return t >= d ? "#f43f5e" : t >= w ? "#f59e0b" : "#06b6d4";
  };
  // ECharts horizontal bar: category Y (reversed so the largest sits on top).
  const names = rows.map((r) => r.name).reverse();
  const data = rows.map((r) => ({ value: r.v, itemStyle: { color: band(r.v), borderRadius: [0, 3, 3, 0] } })).reverse();
  return (
    <ReactECharts
      notMerge
      style={{ height: Math.max(120, rows.length * 24 + 24) }}
      option={{
        ...chartBase,
        grid: { left: 4, right: 56, top: 6, bottom: 4, containLabel: true },
        tooltip: { ...chartBase.tooltip, trigger: "axis", axisPointer: { type: "shadow" }, valueFormatter: (v: number) => fmtv(v) },
        xAxis: { type: "value", ...axisStyle, splitLine: { show: false }, axisLabel: { show: false }, axisTick: { show: false }, axisLine: { show: false } },
        yAxis: { type: "category", ...axisStyle, data: names, axisTick: { show: false }, axisLine: { show: false }, axisLabel: { ...(axisStyle as any).axisLabel, fontSize: 12 } },
        series: [
          {
            type: "bar",
            data,
            barWidth: 14,
            label: { show: true, position: "right", formatter: (p: any) => fmtv(p.value), fontSize: 12, color: cssVar("--fg-muted", "#667085") },
          },
        ],
      }}
    />
  );
}

// ---- status grid -----------------------------------------------------------
// One cell per entity (BGP peer / OSPF neighbour / device), coloured by state —
// the canonical NOC "wall": the eye finds the red cell instantly, and N peers'
// health is visible at once where a single count only says *that* something is
// down, not *which*.
function StatusGrid({
  query,
  classify,
  okLabel = "up",
}: {
  query: string;
  classify: (v: number) => "ok" | "warn" | "bad"; // state value → band
  okLabel?: string;
}) {
  usePrefs();
  const { data: res, err } = usePolled(() => api.metricsQuery(query), 15000);
  const cells = (res?.data?.result ?? [])
    .map((x) => ({ name: seriesLabel(x.metric), st: classify(Number(x.value?.[1])) }))
    .sort((a, b) => (a.st === b.st ? a.name.localeCompare(b.name) : a.st === "bad" ? -1 : b.st === "bad" ? 1 : a.st === "warn" ? -1 : 1));
  // Never render "0 / 0 down" out of a failed read — the control plane's state
  // is UNKNOWN, which is not the same as converged.
  if (err && !res) return <Unavailable msg="Metrics query failed — session state is unknown." />;
  if (res && cells.length === 0) return <Empty msg="No sessions reported yet." />;
  if (!res) return <Loading />;
  const ok = cells.filter((c) => c.st === "ok").length;
  const bad = cells.filter((c) => c.st === "bad").length;
  return (
    <div className="status-wrap">
      <div className="status-summary">
        <span className="status-ok">{ok}</span>
        <span className="status-slash">/ {cells.length} {okLabel}</span>
        {bad > 0 && <span className="status-bad">{bad} down</span>}
      </div>
      <div className="status-grid">
        {cells.map((c, i) => (
          <span key={`${c.name}-${i}`} className={`sgc ${c.st}`} role="img" aria-label={`${c.name} — ${c.st === "ok" ? okLabel : c.st === "bad" ? "down" : "transient"}`} title={`${c.name} — ${c.st === "ok" ? okLabel : c.st === "bad" ? "down" : "transient"}`} />
        ))}
      </div>
    </div>
  );
}

// ---- alerts: color-coded count row by severity -----------------------------

const SEV_ORDER: SeverityKey[] = ["critical", "error", "warning", "notice", "info"];

function AlertsSeverity() {
  const { navigate } = useShell();
  const { data, err } = usePolled(() => api.alerts(), 10000);
  const alerts = data ?? [];
  // A failed alerts read rendered as five zeros in severity colours is the same
  // lie as "All clear" — the counts are UNKNOWN, so say so.
  if (err && !data) return <Unavailable msg="Alerts API unreachable — severity counts are unknown." />;
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
          title={`View ${k} alerts`}
          {...pressable(() => navigate("alerts/active"))}
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
  const { data, err } = usePolled(() => api.alerts(), 10000);
  // THE defect this pattern exists to prevent: an alerts 500 became an empty
  // array became "All clear". Only claim all-clear when the API answered.
  if (err && !data) return <Unavailable msg="Alerts API unreachable — active alerts cannot be listed. Do NOT read this as all-clear." />;
  if (!data) return <Loading />;
  const alerts = data.slice(0, 10);
  if (alerts.length === 0) return <Empty msg="All clear — no active alerts." />;
  return (
    <div className="alerts-scroll">
      {alerts.map((a: Alert, i) => (
        <div
          className="mini-row"
          key={a.id ?? i}
          style={{ cursor: "pointer" }}
          title="Open in Alerts"
          {...pressable(() => navigate("alerts/active"))}
        >
          <span className={`badge ${severityClass(a.severity)}`}>{a.severity || "info"}</span>
          <div className="mini-body">
            <div className="mini-title">{a.summary || "(no summary)"}</div>
            <div className="mini-meta">
              {a.rule}
              {a.device_id ? ` · ${a.device_id}` : ""}
              {a.fired_at ? ` · ${fmtDateTime(a.fired_at)}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- flows / traffic -------------------------------------------------------

function TrafficInOut() {
  // No per-query .catch: a swallowed rejection here produced an empty chart and
  // the claim "no interface throughput", i.e. a metrics outage reported as a
  // silent network. Let the rejection reach the hook's error channel.
  const { data, err } = usePolled(async () => {
    const [s, e, st] = nowWindow(3600);
    const [ins, outs] = await Promise.all([
      api.metricsQueryRange("sum(rate(device_if_in_octets[5m]))*8", s, e, st),
      api.metricsQueryRange("sum(rate(device_if_out_octets[5m]))*8", s, e, st),
    ]);
    return { ins, outs };
  });
  const toSeries = (r?: PromRangeResponse) =>
    (r?.data?.result?.[0]?.values ?? []).map((v) => [v[0] * 1000, Number(v[1])]);
  if (err && !data) return <Unavailable msg="Throughput query failed — traffic volume is unknown." />;
  if (!data) return <Loading />;
  const inS = toSeries(data.ins);
  const outS = toSeries(data.outs);
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
          grid: { left: 6, right: 14, top: 28, bottom: 6, containLabel: true },
          tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtBps(v) },
          legend: { ...chartBase.legend, top: 0, data: ["In", "Out"] },
          xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
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

  // No per-query .catch: swallowing them rendered a WAN outage as "no interfaces
  // match your pattern" — a config problem, not the outage it actually is.
  const { data, err } = usePolled(async () => {
    const [s0, e0, st0] = nowWindow(1800, 30);
    const [trIn, trOut, inb, outb, speed, errs, oper] = await Promise.all([
      api.metricsQueryRange(`sum(rate(device_if_in_octets${sel}[2m]))*8`, s0, e0, st0),
      api.metricsQueryRange(`sum(rate(device_if_out_octets${sel}[2m]))*8`, s0, e0, st0),
      api.metricsQuery(`rate(device_if_in_octets${sel}[2m])*8`),
      api.metricsQuery(`rate(device_if_out_octets${sel}[2m])*8`),
      api.metricsQuery(`device_if_speed${sel}`),
      api.metricsQuery(`rate(device_if_in_errors${sel}[5m]) + rate(device_if_out_errors${sel}[5m]) + rate(device_if_in_discards${sel}[5m]) + rate(device_if_out_discards${sel}[5m])`),
      api.metricsQuery(`device_if_oper_status${sel}`),
    ]);
    return { trIn, trOut, inb, outb, speed, errs, oper };
  }, 10000);
  const degraded = err && !data;

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
      k, device: x.metric.device, ifx: x.metric.ifName || `if${x.metric.index}`,
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
        {degraded
          ? <span className="badge warn" title="The last poll failed">● NO DATA</span>
          : <span className="badge good" title="Polling every 10 seconds">● LIVE · 10s</span>}
        {!degraded && (
          <span className="mini-meta">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)} · peak util {worst.toFixed(1)}%{down > 0 ? ` · ${down} down` : ""}</span>
        )}
        <span style={{ marginLeft: "auto", display: "flex", gap: 4, alignItems: "center" }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && applyPattern()}
            aria-label="WAN device name pattern (regex)" title="WAN device pattern (regex on device name)" style={{ width: 130, fontSize: 12, padding: "3px 6px", border: "1px solid var(--border)", borderRadius: 6, background: "var(--surface)", color: "var(--fg)" }} />
          <button className="dash-btn" style={{ padding: "3px 8px", fontSize: 12 }} onClick={applyPattern}>Apply</button>
        </span>
      </div>
      {degraded ? (
        <Unavailable msg="Interface telemetry query failed — WAN state is unknown (this is not a pattern problem)." />
      ) : inS.length === 0 && rows.length === 0 ? (
        <Empty msg={`No interfaces match device pattern “${pattern}” — adjust it (regex, e.g. wan|edge|dmz).`} />
      ) : (
        <>
          <ReactECharts
            style={{ height: 150 }}
            option={{
              ...chartBase,
              grid: { left: 6, right: 12, top: 8, bottom: 6, containLabel: true },
              tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtBps(v) },
              legend: { show: false },
              xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
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
                  <td><span className="dot" aria-hidden="true" style={{ display: "inline-block", width: 8, height: 8, borderRadius: 4, background: r.up ? "var(--good)" : "var(--bad)", marginRight: 6 }} />
                    <span className="sr-only">{r.up ? "up" : "down"} </span>
                    <span className="mono">{r.device}</span> <span className="mini-meta">{r.ifx}</span></td>
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
  const { data: res, err } = usePolled(() => api.topTalkers(3600, 8), 30000);
  const rows = ((res?.data as { src: string; dst: string; bytes_total: number }[]) ?? []).slice(0, 8);
  if (err && !res) return <Unavailable msg="Flow store unreachable — top talkers are unknown." />;
  if (!res) return <Loading />;
  if (rows.length === 0) return <Empty msg="No flow data yet." />;
  return (
    <table className="mini-table">
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} style={{ cursor: "pointer" }} title="View in Flows" tabIndex={0} onClick={() => navigate("explore/flows")} onKeyDown={(e) => { if (e.key === "Enter") navigate("explore/flows"); }}>
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

function useProtocolCollectors(): { cols: CollectorStatus[]; err: boolean; loaded: boolean } {
  const { data, err } = usePolled(() => api.collectors(), 15000);
  return {
    cols: (data ?? []).filter((c) => (c.kind ?? "protocol") === "protocol"),
    err: err && !data,
    loaded: data !== undefined,
  };
}

function SiteAvailability() {
  const { navigate } = useShell();
  const { cols, err, loaded } = useProtocolCollectors();
  // Reachability is a percentage of a KNOWN denominator; a failed collector read
  // has no denominator, so it must not render as a reachability figure at all.
  if (err) return <Unavailable msg="Collector status unreachable — reachability is unknown." />;
  if (!loaded) return <Loading />;
  const targets = cols.reduce((n, c) => n + (c.targets ?? 0), 0);
  const reachable = cols.reduce((n, c) => n + (c.reachable ?? 0), 0);
  const pct = targets > 0 ? Math.round((reachable / targets) * 100) : null;
  const cls = pct === null ? "s-muted" : pct >= 99 ? "s-good" : pct >= 90 ? "s-warn" : "s-bad";
  return (
    <div className={`stat ${cls}`} style={{ border: 0, padding: 0, cursor: "pointer" }} title="View devices" {...pressable(() => navigate("infrastructure/devices"))}>
      <span className="stat-value">{pct === null ? "—" : `${pct}%`}</span>
      <span className="stat-sub">{reachable}/{targets} targets reachable</span>
    </div>
  );
}

function StackPerformance() {
  const { navigate } = useShell();
  const { cols, err, loaded } = useProtocolCollectors();
  // "0/0 healthy" out of a failed read is a false negative about the stack.
  if (err) return <Unavailable msg="Collector status unreachable — stack health is unknown." />;
  if (!loaded) return <Loading />;
  const enabled = cols.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.healthy).length;
  const avgMs =
    cols.length > 0
      ? Math.round(cols.reduce((n, c) => n + (c.last_poll_ms ?? 0), 0) / cols.length)
      : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr", cursor: "pointer" }} title="View metrics" {...pressable(() => navigate("explore/metrics"))}>
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

// ---- KPI strip -------------------------------------------------------------
// The reference boards' header strip: dense small boxes, big numbers, a trend
// sparkline behind each (a number with no trend is an anti-pattern — USE method
// is about direction, not a snapshot). The KPIs themselves are the research-
// backed NetOps set: reachability, fleet/interface up%, throughput, control-
// plane health, path latency — the questions a NOC asks first. Tenant-scoped
// device/alert/site counts come from the backend (authoritative, RLS-correct);
// the network-wide health %s are computed from the metric plane with a spark.

type Band = "good" | "warn" | "bad" | "accent";
const BAND_HEX: Record<Band, string> = { good: "#10b981", warn: "#f59e0b", bad: "#f43f5e", accent: "#818cf8" };

type KpiSpec = {
  key: string;
  label: string;
  query: string;
  fmt: (v: number) => string;
  band: (v: number) => Band;
  drill: string;
};

// Ordered most-important-first (research blueprint §4). Each is a single scalar
// PromQL with a short range, so we get both the headline number and a sparkline.
const KPI_SPECS: KpiSpec[] = [
  { key: "reach", label: "Reachability", query: "100 * sum(collector_targets_reachable) / (sum(collector_targets) > 0)", fmt: (v) => `${v.toFixed(1)}%`, band: (v) => (v >= 99 ? "good" : v >= 95 ? "warn" : "bad"), drill: "infrastructure/devices" },
  { key: "ifup", label: "Interfaces up", query: "100 * count(device_if_oper_status == 1) / (count(device_if_admin_status == 1) > 0)", fmt: (v) => `${v.toFixed(1)}%`, band: (v) => (v >= 98 ? "good" : v >= 90 ? "warn" : "bad"), drill: "infrastructure/ifperf" },
  { key: "thru", label: "Throughput", query: "sum(rate(device_if_in_octets[5m]) * 8) + sum(rate(device_if_out_octets[5m]) * 8)", fmt: (v) => fmtBps(v), band: () => "accent", drill: "explore/flows" },
  { key: "bgp", label: "BGP established", query: "100 * count(device_bgp_peer_state == 6) / (count(device_bgp_peer_state) > 0)", fmt: (v) => `${Math.round(v)}%`, band: (v) => (v >= 100 ? "good" : v >= 90 ? "warn" : "bad"), drill: "infrastructure/devices" },
  { key: "rtt", label: "Path RTT", query: "avg(probe_rtt_ms)", fmt: (v) => `${v.toFixed(1)}ms`, band: (v) => (v < 50 ? "good" : v < 150 ? "warn" : "bad"), drill: "explore/metrics" },
  { key: "cpu", label: "Peak CPU", query: "max(device_cpu_percent)", fmt: (v) => `${Math.round(v)}%`, band: (v) => (v < 70 ? "good" : v < 90 ? "warn" : "bad"), drill: "explore/metrics" },
];

// A tiny areaspark — no axes, no chrome, just the shape of the last 30 minutes.
function Spark({ data, color }: { data: [number, number][]; color: string }) {
  if (data.length < 2) return <div style={{ height: 26 }} />;
  return (
    <ReactECharts
      style={{ height: 26 }}
      option={{
        backgroundColor: "transparent",
        grid: { left: 0, right: 0, top: 3, bottom: 0 },
        xAxis: { type: "time", show: false },
        yAxis: { type: "value", show: false, scale: true },
        tooltip: { show: false },
        series: [{ type: "line", data, smooth: true, showSymbol: false, lineStyle: { width: 1.5, color }, areaStyle: { color: hexToRgba(color, 0.16) } }],
      }}
    />
  );
}

function KpiTiles() {
  const { navigate } = useShell();
  const { data: tilesData, err: tilesErr } = usePolled(() => api.metricTiles(), 15000);
  const tiles = tilesData ?? [];
  const { data: computed, err: computedErr } = usePolled(async () => {
    const [s, e, st] = nowWindow(1800, 60);
    const results = await Promise.allSettled(
      KPI_SPECS.map((spec) => api.metricsQueryRange(spec.query, s, e, st)),
    );
    // A per-KPI failure renders "—" (honest unknown). If EVERY query failed the
    // metrics plane is down — reject so the panel says so instead of drawing a
    // full grid of em-dashes that looks like a quiet network.
    if (results.every((r) => r.status === "rejected")) throw new Error("metrics unavailable");
    return KPI_SPECS.map((spec, i) => {
      const r = results[i];
      const res = r.status === "fulfilled" ? r.value : undefined;
      const pts = (res?.data?.result?.[0]?.values ?? [])
        .map((v) => [v[0] * 1000, Number(v[1])] as [number, number])
        .filter((p) => Number.isFinite(p[1]));
      const latest = pts.length ? pts[pts.length - 1][1] : null;
      return { spec, latest, spark: pts };
    });
  }, 15000);

  const tileBy = (title: string) => tiles.find((t) => t.title.toLowerCase() === title.toLowerCase());
  const go = (route: string, drill?: Record<string, string>) => () => {
    if (drill) setDrill(drill);
    navigate(route);
  };

  // tenant-scoped count tiles (no spark — they're authoritative counters)
  const countTile = (title: string, label: string, okWhenZero: boolean, dest: { route: string; drill?: Record<string, string> }) => {
    const m = tileBy(title);
    const n = m ? Number(String(m.value).replace(/[^\d.-]/g, "")) : null;
    const band: Band = m == null ? "accent" : okWhenZero ? (n === 0 ? "good" : "bad") : "accent";
    return { kind: "count" as const, key: title, label, value: m?.value ?? "—", band, dest };
  };

  const counts = [
    countTile("Devices Down", "Devices down", true, { route: "infrastructure/devices", drill: { devices: "down" } }),
    countTile("Critical Threats", "Critical alerts", true, { route: "alerts/active" }),
    countTile("Devices", "Devices", false, { route: "infrastructure/devices" }),
    countTile("Sites", "Sites", false, { route: "topology/map" }),
  ];

  // Both feeds down = the KPI strip is unreadable; "Waiting for metrics…" would
  // frame an outage as a cold start.
  if (tilesErr && computedErr && !tilesData && !computed)
    return <Unavailable msg="Metrics and tile APIs unreachable — no KPI can be stated." />;
  if (tiles.length === 0 && !computed) return <Empty msg="Waiting for metrics…" />;

  return (
    <div className="kpi-grid">
      {/* network-health KPIs with trend sparklines */}
      {(computed ?? []).map(({ spec, latest, spark }) => {
        const band: Band = latest == null ? "accent" : spec.band(latest);
        return (
          <div key={spec.key} className={`kpi k-${band} kpi-link`} title="View details" {...pressable(go(spec.drill))}>
            <span className="kpi-label">{spec.label}</span>
            <span className="kpi-num">{latest == null ? "—" : spec.fmt(latest)}</span>
            <Spark data={spark} color={BAND_HEX[band]} />
          </div>
        );
      })}
      {/* tenant-scoped count tiles */}
      {counts.map((c) => (
        <div key={c.key} className={`kpi k-${c.band} kpi-link`} title="View details" {...pressable(go(c.dest.route, c.dest.drill))}>
          <span className="kpi-label">{c.label}</span>
          <span className="kpi-num">{c.value}</span>
          <div style={{ height: 26 }} />
        </div>
      ))}
    </div>
  );
}

function TopologyPanel() {
  // The single topology surface (Canvas) embedded in the Overview board. Given a
  // fixed height since the Canvas fills its container; drill opens the full view.
  return (
    <div style={{ height: 420, overflow: "hidden" }}>
      <TopologyCanvas />
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
  const { data: res, err } = usePolled(() => api.flowsByProto(3600), 30000);
  const rows = ((res?.data as { proto: string | number; bytes_total: number }[]) ?? [])
    .map((r) => ({ name: PROTO_NAMES[String(r.proto)] ?? `proto ${r.proto}`, value: Number(r.bytes_total) }))
    .filter((r) => r.value > 0)
    .slice(0, 8);
  if (err && !res) return <Unavailable msg="Flow store unreachable — the protocol mix is unknown." />;
  if (!res) return <Loading />;
  return <Donut rows={rows} unit="B" onClick={() => navigate("explore/flows")} />;
}

// ---- device inventory by vendor --------------------------------------------

function DevicesByVendor() {
  const { navigate } = useShell();
  const { data: devicesData, err } = usePolled(() => api.devices(), 30000);
  if (err && !devicesData) return <Unavailable msg="Inventory API unreachable — the device mix is unknown." />;
  if (!devicesData) return <Loading />;
  const by: Record<string, number> = {};
  for (const d of devicesData as Device[]) by[d.vendor || "unknown"] = (by[d.vendor || "unknown"] ?? 0) + 1;
  const rows = Object.entries(by).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  return <Donut rows={rows} unit="devices" onClick={() => navigate("infrastructure/devices")} />;
}

// ---- tunnels health (IPsec / SD-WAN) ---------------------------------------

function TunnelsHealth() {
  const { navigate } = useShell();
  const { data: res, err } = usePolled(() => api.tunnels(500), 20000);
  const rows = (res?.data as Tunnel[]) ?? [];
  // "Tunnels down: 0" out of a failed read is the most dangerous zero on the board.
  if (err && !res) return <Unavailable msg="Tunnel API unreachable — tunnel state is unknown." />;
  if (!res) return <Loading />;
  if (rows.length === 0) return <Empty msg="No tunnel telemetry yet." />;
  const up = rows.filter((t) => String(t.status).toLowerCase() === "up").length;
  const down = rows.length - up;
  const lats = rows.map((t) => Number(t.latency_ms)).filter((n) => Number.isFinite(n) && n > 0);
  const avg = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null;
  const worst = lats.length ? Math.round(Math.max(...lats)) : null;
  return (
    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr", cursor: "pointer" }} title="View tunnels" {...pressable(() => navigate("topology/tunnels"))}>
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
  const { data: res, err } = usePolled(() => api.findings(12), 20000);
  const rows = ((res?.data as Finding[]) ?? []).slice(0, 8);
  if (err && !res) return <Unavailable msg="Correlation API unreachable — incidents cannot be listed." />;
  if (!res) return <Loading />;
  if (rows.length === 0) return <Empty msg="No correlated incidents." />;
  return (
    <div className="alerts-scroll">
      {rows.map((f, i) => (
        <div className="mini-row" key={f.id ?? i} style={{ cursor: "pointer" }} title="Open in Incidents" {...pressable(() => navigate("alerts/incidents"))}>
          <span className={`badge ${severityClass(f.severity)}`}>{f.severity || "info"}</span>
          <div className="mini-body">
            <div className="mini-title">{f.summary || f.kind || "(incident)"}</div>
            <div className="mini-meta">
              {f.device}{f.component ? ` · ${f.component}` : ""}
              {f.ts ? ` · ${fmtDateTime(f.ts)}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---- registry --------------------------------------------------------------

export type PanelCategory = "Health & KPIs" | "Resources" | "Interfaces" | "Routing" | "Active measurement" | "Alerts" | "Traffic" | "Inventory" | "Topology";

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
  // Saturation trend panels (the "Top Jobs" treatment — per-device trend, not a wheel).
  "sat-cpu": { type: "sat-cpu", title: "CPU utilization", defaultSpan: 3, category: "Resources", render: () => <MetricArea query="max by (device) (device_cpu_percent)" unit="%" />, drill: "explore/metrics" },
  "sat-mem": { type: "sat-mem", title: "Memory utilization", defaultSpan: 3, category: "Resources", render: () => <MetricArea query="max by (device) (device_mem_percent)" unit="%" />, drill: "explore/metrics" },
  "sat-storage": { type: "sat-storage", title: "Storage used", defaultSpan: 3, category: "Resources", render: () => <MetricArea query="100 * sum by (device) (device_storage_used) / (sum by (device) (device_storage_size) > 0)" unit="%" />, drill: "explore/metrics" },
  "sat-temp": { type: "sat-temp", title: "Temperature", defaultSpan: 3, category: "Resources", render: () => <MetricArea query="max by (device) (device_temp_celsius)" unit="°C" fmt={(v) => `${Math.round(v)}°C`} /> },
  // Errors & quality (USE-Errors): rank the worst, separate errors from discards.
  "if-util-topn": { type: "if-util-topn", title: "Interface utilization — Top 10", defaultSpan: 6, category: "Interfaces", render: () => <TopNBar query="topk(10, 100 * (rate(device_if_in_octets[5m]) * 8) / (device_if_speed * 1000000 > 0))" unit="%" n={10} warn={70} danger={90} />, drill: "infrastructure/ifperf" },
  "if-errors-topn": { type: "if-errors-topn", title: "Interface errors — Top 8", defaultSpan: 6, category: "Interfaces", render: () => <TopNBar query="topk(8, sum by (device, ifName) (rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m])))" unit="/s" fmt={(v) => `${v.toFixed(2)}/s`} warn={0.1} danger={1} />, drill: "infrastructure/ifperf" },
  "if-discards-topn": { type: "if-discards-topn", title: "Interface discards — Top 8", defaultSpan: 6, category: "Interfaces", render: () => <TopNBar query="topk(8, sum by (device, ifName) (rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m])))" unit="/s" fmt={(v) => `${v.toFixed(2)}/s`} warn={0.1} danger={1} />, drill: "infrastructure/ifperf" },
  // Control-plane (routing) status — which peer/adjacency, not just a count.
  "bgp-peers": { type: "bgp-peers", title: "BGP peers", defaultSpan: 6, category: "Routing", render: () => <StatusGrid query="device_bgp_peer_state" classify={(v) => (v >= 6 ? "ok" : v <= 2 ? "bad" : "warn")} okLabel="established" />, drill: "infrastructure/devices" },
  "ospf-nbrs": { type: "ospf-nbrs", title: "OSPF / IS-IS adjacencies", defaultSpan: 6, category: "Routing", render: () => <StatusGrid query="device_ospf_nbr_state or device_isis_adj_state" classify={(v) => (v >= 8 ? "ok" : v <= 1 ? "bad" : "warn")} okLabel="full" />, drill: "infrastructure/devices" },
  // Active measurement (RED-analogue): latency/jitter/loss as trends, not gauges.
  "probe-rtt": { type: "probe-rtt", title: "Path RTT", defaultSpan: 4, category: "Active measurement", render: () => <MetricArea query="probe_rtt_ms" unit="ms" fmt={(v) => `${v.toFixed(1)}ms`} windowSec={3600} />, drill: "explore/metrics" },
  "probe-jitter": { type: "probe-jitter", title: "Path jitter (PDV)", defaultSpan: 4, category: "Active measurement", render: () => <MetricArea query="probe_pdv_ms" unit="ms" fmt={(v) => `${v.toFixed(2)}ms`} windowSec={3600} />, drill: "explore/metrics" },
  "probe-loss": { type: "probe-loss", title: "Path packet loss", defaultSpan: 4, category: "Active measurement", render: () => <MetricArea query="probe_loss_pct" unit="%" fmt={(v) => `${v.toFixed(1)}%`} windowSec={3600} />, drill: "explore/metrics" },
  "wan-interfaces": { type: "wan-interfaces", title: "WAN interfaces — live", defaultSpan: 8, category: "Traffic", render: () => <WanInterfaces />, drill: "infrastructure/ifperf" },
  "alerts-severity": { type: "alerts-severity", title: "Alerts by severity", defaultSpan: 12, category: "Alerts", render: () => <AlertsSeverity />, drill: "alerts/active" },
  "active-alerts": { type: "active-alerts", title: "Active alerts", defaultSpan: 6, category: "Alerts", render: () => <ActiveAlerts />, drill: "alerts/active" },
  incidents: { type: "incidents", title: "Recent incidents", defaultSpan: 6, category: "Alerts", render: () => <RecentIncidents />, drill: "alerts/incidents" },
  traffic: { type: "traffic", title: "Traffic in / out", defaultSpan: 8, category: "Traffic", render: () => <TrafficInOut />, drill: "explore/flows" },
  "top-hosts": { type: "top-hosts", title: "Top hosts", defaultSpan: 4, category: "Traffic", render: () => <TopHosts />, drill: "explore/flows" },
  "flows-proto": { type: "flows-proto", title: "Traffic by protocol", defaultSpan: 4, category: "Traffic", render: () => <FlowsByProto />, drill: "explore/flows" },
  "tunnels-health": { type: "tunnels-health", title: "Tunnels health", defaultSpan: 4, category: "Traffic", render: () => <TunnelsHealth />, drill: "topology/tunnels" },
  "devices-vendor": { type: "devices-vendor", title: "Devices by vendor", defaultSpan: 4, category: "Inventory", render: () => <DevicesByVendor />, drill: "infrastructure/devices" },
  topology: { type: "topology", title: "Topology", defaultSpan: 12, category: "Topology", render: () => <TopologyPanel />, drill: "topology-canvas" },
};

// Category groups for the "Add panel" picker, in display order.
export const PANEL_CATEGORIES: { category: PanelCategory; types: string[] }[] = [
  { category: "Health & KPIs", types: ["kpis", "site-availability", "stack-performance"] },
  { category: "Resources", types: ["sat-cpu", "sat-mem", "sat-storage", "sat-temp", "gauge-cpu", "gauge-mem", "gauge-storage", "gauge-network"] },
  { category: "Interfaces", types: ["if-util-topn", "if-errors-topn", "if-discards-topn"] },
  { category: "Routing", types: ["bgp-peers", "ospf-nbrs"] },
  { category: "Active measurement", types: ["probe-rtt", "probe-jitter", "probe-loss"] },
  { category: "Alerts", types: ["alerts-severity", "active-alerts", "incidents"] },
  { category: "Traffic", types: ["wan-interfaces", "traffic", "top-hosts", "flows-proto", "tunnels-health"] },
  { category: "Inventory", types: ["devices-vendor"] },
  { category: "Topology", types: ["topology"] },
];

// Flat order (derived) — kept for any callers that still want a simple list.
export const PANEL_ORDER = PANEL_CATEGORIES.flatMap((c) => c.types);
