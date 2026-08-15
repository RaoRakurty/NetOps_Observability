// Board framework — reusable dashboard primitives shared by the device-monitoring
// suite (Device Monitoring, Interface Performance, BGP/OSPF, Troubleshooting).
// Panels are query-string based: callers compose PromQL from the current scope
// and pass the final query, keeping these primitives simple and reusable. See
// docs/design/device-monitoring-dashboards.md.
import { ReactNode, createContext, useContext, useEffect, useState } from "react";
import ReactECharts from "../EChart";
import { api, PromSeries } from "../../services/api";
import { chartBase, axisStyle, timeAxisTicks, paletteColor, colorForMetric, hexToRgba } from "../../theme/charts";
import { cssVar } from "../../theme/tokens";
import Icon from "../Icon";
import { Modal, Stat, StatTone } from "../ui";
import { escapeHtml } from "../../lib/text";
export { escapeHtml }; // re-exported: panels was the original home; canonical lives in lib/text

// ── formatters ───────────────────────────────────────────────────────────────
export const fmtNum = (n: number) => Number(n).toLocaleString();
export const fmtPct = (n: number) => `${(Number(n) || 0).toFixed(0)}%`;
export function fmtBytes(n: number): string {
  const x = Number(n) || 0;
  if (x < 1024) return `${x} B`;
  const u = ["KB", "MB", "GB", "TB", "PB"];
  let v = x / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
}
export function fmtBps(n: number): string {
  const x = Number(n) || 0;
  if (x < 1000) return `${x.toFixed(0)} bps`;
  const u = ["kbps", "Mbps", "Gbps", "Tbps"];
  let v = x / 1000;
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
}
export function fmtUptime(sec: number): string {
  const s = Number(sec) || 0;
  if (s <= 0) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

// ── PromQL helpers ───────────────────────────────────────────────────────────
// sanitizeLabel keeps only characters valid in our device/interface identifiers,
// so an interpolated PromQL label selector can't be used for injection. Values
// come from our own inventory/metric labels; we sanitize regardless.
export const sanitizeLabel = (v: string) => (v || "").replace(/[^A-Za-z0-9._:\- ]/g, "");


// labelSelector builds a `{k="v",…}` PromQL selector from set parts (skips empty).
export function labelSelector(parts: Record<string, string | undefined>): string {
  const inner = Object.entries(parts)
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}="${sanitizeLabel(v as string)}"`)
    .join(",");
  return inner ? `{${inner}}` : "";
}

export const latest = (s: PromSeries): number => (s.values.length ? Number(s.values[s.values.length - 1][1]) : 0);

export function seriesLabel(s: PromSeries, keys?: string[]): string {
  const m = s.metric || {};
  if (keys) {
    const parts = keys.map((k) => m[k]).filter(Boolean);
    if (parts.length) return parts.join(" · ");
  }
  const dev = m.device || m.instance || m.host || "";
  const idx = m.index || m.ifName || m.neighbor || m.peer || "";
  if (dev && idx) return `${dev} · ${idx}`;
  return dev || idx || m.__name__ || "series";
}

// ── onboarding-aware empty state ──────────────────────────────────────────────
// A board panel with no data is usually not "broken" — it's "nothing has been
// connected yet". For a from-zero (no-telemetry) customer, the empty state should
// teach what to turn on rather than show a dead "No data". Keyed by the data the
// panel needs so the hint names the right onboarding step.
export type DataKind = "metrics" | "flows" | "logs" | "tunnels" | "synthetics" | "generic";
const EMPTY_HINTS: Record<DataKind, { msg: string; hint: string }> = {
  metrics: { msg: "No SNMP metrics in this window.", hint: "Enable SNMP (read-only v2c/v3) on your devices and confirm reachability — no agent required." },
  flows: { msg: "No flow records in this window.", hint: "Point NetFlow / IPFIX / sFlow export from your routers at the collector." },
  logs: { msg: "No events in this window.", hint: "Forward syslog and SNMP traps from your devices to the collector." },
  tunnels: { msg: "No tunnels discovered.", hint: "Set ENABLE_TUNNEL_DISCOVERY=true — tunnel interfaces (IPsec / GRE / VTI) are found via standard IF-MIB & TUNNEL-MIB SNMP walks, no per-vendor setup." },
  synthetics: { msg: "No active measurements in this window.", hint: "Set FEATURE_SYNTHETICS=true with SYNTHETIC_HTTP/ICMP/TCP_TARGETS for service checks, and FEATURE_ACTIVE_PROBE + STAMP_TARGETS for path SLA (RFC 8762)." },
  generic: { msg: "No data in this window.", hint: "" },
};
export function EmptyHint({ kind = "metrics" }: { kind?: DataKind }) {
  const h = EMPTY_HINTS[kind];
  return (
    <div className="empty board-empty">
      <div className="board-empty-msg">{h.msg}</div>
      {h.hint && <div className="board-empty-hint">{h.hint}</div>}
      <a className="board-empty-link" href="#/infrastructure/devices">Onboard devices →</a>
    </div>
  );
}

// ── layout ───────────────────────────────────────────────────────────────────
export function Group({ title, hue, children, defaultOpen = true }: { title: string; hue: string; children: ReactNode; defaultOpen?: boolean }) {
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

// Zoom context: charts rendered inside the deep-look modal pick a taller
// height so the expanded view is genuinely more readable, not just wider.
export const PanelZoom = createContext(false);

// Render-prop helper: yields the chart height, swapping to a tall variant when
// rendered inside the Panel zoom modal (context re-evaluates under the provider).
function Zoomable({ base, children }: { base: number; children: (h: number) => ReactNode }) {
  const zoomed = useContext(PanelZoom);
  return <>{children(zoomed ? Math.max(440, Math.round(window.innerHeight * 0.62)) : base)}</>;
}

export function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  const [zoom, setZoom] = useState(false);
  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3 className="panel-zoomable" title="Click to enlarge" onClick={() => setZoom(true)}>{title}</h3>
        {action}
        <button className="panel-zoom-btn" aria-label={`Enlarge ${title}`} title="Enlarge" onClick={() => setZoom(true)}>⤢</button>
      </div>
      {children}
      {zoom && (
        <Modal title={title} wide onClose={() => setZoom(false)}>
          <PanelZoom.Provider value={true}>
            <div className="panel-zoom-body">{children}</div>
          </PanelZoom.Provider>
        </Modal>
      )}
    </div>
  );
}

// ── data hook ────────────────────────────────────────────────────────────────
// useMetricRange runs a PromQL range query against the metrics proxy on a
// 30s poll, returning the series, an error, and a loading flag.
export function useMetricRange(query: string, minutes: number, pointsPerWindow = 180) {
  const [series, setSeries] = useState<PromSeries[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const end = Math.floor(Date.now() / 1000);
        const start = end - minutes * 60;
        const step = Math.max(30, Math.floor((minutes * 60) / pointsPerWindow));
        const r = await api.metricsQueryRange(query, start, end, step);
        if (!alive) return;
        if (r.status !== "success" || !r.data) throw new Error((r as any).error || "query failed");
        setSeries(r.data.result ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      } finally {
        if (alive) setLoading(false);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [query, minutes, pointsPerWindow]);
  return { series, err, loading };
}

// ── MetricLine — timeseries ──────────────────────────────────────────────────
export function MetricLine({ title, query, minutes, fmtY, height = 240, labelKeys, stepped = false, dataKind = "metrics" }: {
  title: string; query: string; minutes: number; fmtY: (n: number) => string; height?: number; labelKeys?: string[]; stepped?: boolean; dataKind?: DataKind;
}) {
  const { series, err } = useMetricRange(query, minutes);
  return (
    <Panel title={title}>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : series.length === 0 ? (
        <EmptyHint kind={dataKind} />
      ) : (
        <Zoomable base={height}>{(h) => (
        <ReactECharts
          style={{ height: h }}
          option={{
            ...chartBase,
            tooltip: { ...chartBase.tooltip, trigger: "axis" },
            legend: series.length > 1 && series.length <= 10 ? { ...chartBase.legend, top: 0, type: "scroll" } : { show: false },
            // containLabel so formatted y-axis ticks ("1.5 Gbps", "100 %") are never
            // clipped regardless of width, and the last x-tick isn't cut (#71 ⑧).
            grid: { left: 6, right: 16, top: series.length > 1 ? 30 : 12, bottom: 6, containLabel: true },
            xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
            yAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtY(v) } },
            series: series.slice(0, 14).map((s, i) => {
              // single-series → colour by what the metric MEANS (consistent app-wide);
              // multi-series → the distinct categorical palette.
              const c = series.length === 1 ? colorForMetric(title) : paletteColor(i);
              return {
                name: seriesLabel(s, labelKeys),
                type: "line",
                step: stepped ? "end" : undefined,
                showSymbol: false,
                smooth: !stepped,
                lineStyle: { color: c, width: 2 },
                itemStyle: { color: c },
                areaStyle: series.length === 1
                  ? { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: hexToRgba(c, 0.45) }, { offset: 1, color: hexToRgba(c, 0) }] } }
                  : undefined,
                data: s.values.map(([t, v]) => [t * 1000, Number(v)]),
              };
            }),
          }}
        />
        )}</Zoomable>
      )}
    </Panel>
  );
}

// ── MetricTop — top-N horizontal bars (latest value per series) ───────────────
export function MetricTop({ title, query, minutes, fmtX, limit = 10, labelKeys, dataKind = "metrics" }: {
  title: string; query: string; minutes: number; fmtX: (n: number) => string; limit?: number; labelKeys?: string[]; dataKind?: DataKind;
}) {
  const { series, err } = useMetricRange(query, minutes, 60);
  const rows = series
    .map((s) => ({ label: seriesLabel(s, labelKeys), value: latest(s) }))
    .filter((x) => Number.isFinite(x.value))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
  return (
    <Panel title={title}>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <EmptyHint kind={dataKind} />
      ) : (
        <Zoomable base={360}>{(h) => (
        <ReactECharts
          style={{ height: Math.min(h, 36 + rows.length * 26) }}
          option={{
            ...chartBase,
            grid: { left: 8, right: 70, top: 6, bottom: 6, containLabel: true },
            tooltip: { ...chartBase.tooltip, trigger: "axis", axisPointer: { type: "shadow" }, formatter: (ps: any) => { const p = Array.isArray(ps) ? ps[0] : ps; return `${escapeHtml(p.name)}<br/><b>${fmtX(p.value)}</b>`; } },
            xAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtX(v) } },
            yAxis: { type: "category", inverse: true, data: rows.map((r) => r.label), ...axisStyle, splitLine: { show: false } },
            series: [{ type: "bar", barMaxWidth: 16, data: rows.map((r, i) => ({ value: r.value, itemStyle: { color: paletteColor(i), borderRadius: [0, 3, 3, 0] } })) }],
          }}
        />
        )}</Zoomable>
      )}
    </Panel>
  );
}

// ── BarPanel — horizontal bars from an arbitrary {label,value} list ───────────
// For non-Prometheus data (flows/ClickHouse). Optional per-row tint via `danger`.
export function BarPanel({ title, rows, fmtX, loading, err, danger, dataKind = "flows" }: {
  title: string; rows: { label: string; value: number; danger?: boolean }[];
  fmtX: (n: number) => string; loading?: boolean; err?: string | null; danger?: boolean; dataKind?: DataKind;
}) {
  return (
    <Panel title={title}>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : loading && rows.length === 0 ? (
        <div className="empty">Loading…</div>
      ) : rows.length === 0 ? (
        <EmptyHint kind={dataKind} />
      ) : (
        <Zoomable base={380}>{(h) => (
        <ReactECharts
          style={{ height: Math.min(h, 36 + rows.length * 26) }}
          option={{
            ...chartBase,
            grid: { left: 8, right: 76, top: 6, bottom: 6, containLabel: true },
            tooltip: { ...chartBase.tooltip, trigger: "axis", axisPointer: { type: "shadow" }, formatter: (ps: any) => { const p = Array.isArray(ps) ? ps[0] : ps; return `${escapeHtml(p.name)}<br/><b>${fmtX(p.value)}</b>`; } },
            xAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtX(v) } },
            yAxis: { type: "category", inverse: true, data: rows.map((r) => r.label), ...axisStyle, splitLine: { show: false } },
            series: [{
              type: "bar", barMaxWidth: 16,
              data: rows.map((r, i) => ({ value: r.value, itemStyle: { color: (danger || r.danger) ? cssVar("--crit", "#ef4444") : paletteColor(i), borderRadius: [0, 3, 3, 0] } })),
            }],
          }}
        />
        )}</Zoomable>
      )}
    </Panel>
  );
}

// ── MetricStat — single scalar tile (latest of an aggregated query) ───────────
export function MetricStat({ label, query, minutes, fmt, tone }: {
  label: string; query: string; minutes: number; fmt: (n: number) => string; tone?: (n: number) => StatTone;
}) {
  const { series, err } = useMetricRange(query, minutes, 30);
  const v = series.length ? latest(series[0]) : NaN;
  const t: StatTone = !err && Number.isFinite(v) && tone ? tone(v) : "";
  return <Stat label={label} value={err ? "—" : Number.isFinite(v) ? fmt(v) : "—"} tone={t} />;
}
