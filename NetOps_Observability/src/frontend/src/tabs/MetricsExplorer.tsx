import { useEffect, useMemo, useRef, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, PromSeries } from "../services/api";
import { chartBase, axisStyle, paletteColor } from "../theme/charts";

// Native Metrics Explorer — a Grafana/Datadog-style surface that renders charts
// in-app (ECharts) over the Go /api/metrics/* proxy. Instead of leading with
// Prometheus self-metrics, it presents a curated, categorized catalog of the
// network telemetry the stack actually collects (SNMP device health, interface
// throughput, gNMI streaming, collector health) — the way Datadog's Metric
// Explorer and Zabbix's Latest Data front the operator with real signals.

type Props = { rangeMinutes?: number };

type CatalogItem = { label: string; q: string; base: string; unit?: string };
type CatalogGroup = { group: string; items: CatalogItem[] };

// Curated catalog. `base` is the underlying metric name used to check whether
// the series exists in the store (so we never show a dead quick-pick); `q` is
// the PromQL actually run. Mirrors Datadog's "pick a metric, get a graph".
// Queries aggregate per device (avg/sum/max by device|source) so a chart shows
// one clean line per device rather than dozens of raw per-core / per-interface
// series — the difference between a readable graph and noise. unit drives axis
// + tooltip formatting.
const CATALOG: CatalogGroup[] = [
  {
    group: "Device health (SNMP)",
    items: [
      { label: "CPU utilization", q: "avg by (device) (device_cpu_percent)", base: "device_cpu_percent", unit: "%" },
      { label: "Memory %", q: "avg by (device) (device_mem_percent)", base: "device_mem_percent", unit: "%" },
      { label: "Memory used", q: "sum by (device) (device_mem_used_kb)", base: "device_mem_used_kb", unit: "KB" },
      { label: "Temperature", q: "max by (device) (device_temp_celsius)", base: "device_temp_celsius", unit: "°C" },
    ],
  },
  {
    group: "Interfaces (SNMP)",
    items: [
      { label: "Ingress bit/s", q: "sum by (device) (rate(device_if_in_octets[5m]) * 8)", base: "device_if_in_octets", unit: "bps" },
      { label: "Egress bit/s", q: "sum by (device) (rate(device_if_out_octets[5m]) * 8)", base: "device_if_out_octets", unit: "bps" },
      { label: "In errors/s", q: "sum by (device) (rate(device_if_in_errors[5m]))", base: "device_if_in_errors", unit: "/s" },
      { label: "In discards/s", q: "sum by (device) (rate(device_if_in_discards[5m]))", base: "device_if_in_discards", unit: "/s" },
    ],
  },
  {
    group: "gNMI streaming",
    items: [
      { label: "gNMI ingress bit/s", q: "sum by (source) (rate(gnmi_interfaces_interface_state_counters_in_octets[5m]) * 8)", base: "gnmi_interfaces_interface_state_counters_in_octets", unit: "bps" },
      { label: "gNMI egress bit/s", q: "sum by (source) (rate(gnmi_interfaces_interface_state_counters_out_octets[5m]) * 8)", base: "gnmi_interfaces_interface_state_counters_out_octets", unit: "bps" },
      { label: "SR Linux CPU", q: "avg by (source) (gnmi_srl_nokia_platform_platform_srl_nokia_platform_control_control_srl_nokia_platform_cpu_cpu_total_instant)", base: "gnmi_srl_nokia_platform_platform_srl_nokia_platform_control_control_srl_nokia_platform_cpu_cpu_total_instant", unit: "%" },
    ],
  },
  {
    group: "Collector health",
    items: [
      { label: "Reachable targets", q: "collector_targets_reachable", base: "collector_targets_reachable" },
      { label: "Samples / poll", q: "collector_samples", base: "collector_samples" },
      { label: "Collector up", q: "collector_up", base: "collector_up" },
    ],
  },
];

// Compact SI/unit formatter for the Y axis + tooltip.
function fmtVal(v: number, unit?: string): string {
  if (!isFinite(v)) return "—";
  if (unit === "bps") {
    const u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let i = 0, n = v;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
  }
  if (unit === "KB") {
    const u = ["KB", "MB", "GB", "TB"];
    let i = 0, n = v;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(1)} ${u[i]}`;
  }
  const s = Math.abs(v) >= 1000 ? v.toLocaleString(undefined, { maximumFractionDigits: 0 })
    : v.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return unit ? `${s}${unit === "%" || unit === "°C" ? "" : " "}${unit}` : s;
}

// unitFor guesses a display unit from a raw metric name (best-effort).
function unitFor(name: string): string | undefined {
  const n = name.toLowerCase();
  if (n.includes("percent") || n.endsWith("_pct")) return "%";
  if (n.includes("celsius") || n.includes("temp")) return "°C";
  if (n.includes("_kb") || n.includes("kbyte")) return "KB";
  return undefined;
}

// MetricPicker — a modern searchable combobox over the metric catalog. Opens on
// click, filters as you type, scrolls, and selects on click. Replaces the
// browser <datalist>, which forced you to clear the field before browsing.
function MetricPicker({ names, onPick }: { names: string[]; onPick: (n: string) => void }) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onEsc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onEsc); };
  }, [open]);

  const filtered = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const list = f ? names.filter((n) => n.toLowerCase().includes(f)) : names;
    return list;
  }, [names, filter]);
  const shown = filtered.slice(0, 400);

  return (
    <div className="combo" ref={ref}>
      <button type="button" className="combo-btn" onClick={() => setOpen((o) => !o)} title="Browse all metrics">
        Browse metrics <span style={{ opacity: 0.6 }}>({names.length})</span> ▾
      </button>
      {open && (
        <div className="combo-menu">
          <input
            autoFocus
            className="combo-search"
            placeholder="Filter metrics…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="combo-list">
            {shown.length === 0 ? (
              <div className="combo-empty">No metric matches “{filter}”.</div>
            ) : (
              shown.map((n) => (
                <div
                  key={n}
                  className="combo-item"
                  onClick={() => { onPick(n); setOpen(false); setFilter(""); }}
                >
                  {n}
                </div>
              ))
            )}
            {filtered.length > shown.length && (
              <div className="combo-empty">+{filtered.length - shown.length} more — refine the filter</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function MetricsExplorer({ rangeMinutes = 60 }: Props) {
  const [query, setQuery] = useState("avg by (device) (device_cpu_percent)");
  const [unit, setUnit] = useState<string | undefined>("%");
  const [series, setSeries] = useState<PromSeries[]>([]);
  const [names, setNames] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const ran = useRef(false);

  useEffect(() => {
    api.metricNames().then((r) => setNames(r?.data ?? [])).catch(() => setNames([]));
  }, []);

  const nameSet = useMemo(() => new Set(names), [names]);
  // Only surface catalog items whose underlying metric is actually present.
  const groups = useMemo(
    () => CATALOG.map((g) => ({ ...g, items: g.items.filter((it) => nameSet.size === 0 || nameSet.has(it.base)) }))
      .filter((g) => g.items.length > 0),
    [nameSet],
  );

  const run = async (q = query, minutes = rangeMinutes, u = unit) => {
    if (!q.trim()) return;
    setBusy(true);
    setError(null);
    setUnit(u);
    try {
      const end = Math.floor(Date.now() / 1000);
      const start = end - minutes * 60;
      const step = Math.max(15, Math.floor((minutes * 60) / 240));
      const r = await api.metricsQueryRange(q, start, end, step);
      if (r.status !== "success" || !r.data) throw new Error(r.error || "query failed");
      setSeries(r.data.result ?? []);
    } catch (e) {
      setError((e as Error).message);
      setSeries([]);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    run(query, rangeMinutes, unit);
    ran.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rangeMinutes]);

  // Live mode — re-poll every 5s so the chart streams/draws in real time
  // (Versa-style live monitoring). Cleared when toggled off or unmounted.
  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => run(query, rangeMinutes, unit), 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, query, rangeMinutes, unit]);

  const pick = (it: CatalogItem) => {
    setQuery(it.q);
    run(it.q, rangeMinutes, it.unit);
  };

  const option = useMemo(() => {
    const label = (m: Record<string, string>) => {
      // Prefer the friendly device/source label over raw instance/job.
      const dev = m.device || m.source || m.instance || "";
      const iface = m.interface_name || m.index || m.interface || "";
      const name = m.__name__ ?? "value";
      if (dev || iface) return [dev, iface].filter(Boolean).join(" · ");
      return name;
    };
    return {
      ...chartBase,
      animationDuration: 900,
      animationEasing: "cubicOut",
      grid: { left: 64, right: 16, top: 24, bottom: 28 },
      tooltip: {
        ...chartBase.tooltip,
        trigger: "axis",
        valueFormatter: (v: number) => fmtVal(v, unit),
      },
      legend: { ...chartBase.legend, type: "scroll", top: 0 },
      xAxis: { type: "time", ...axisStyle },
      yAxis: {
        type: "value",
        ...axisStyle,
        axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtVal(v, unit) },
      },
      series: series.map((s, i) => ({
        name: label(s.metric),
        type: "line",
        showSymbol: false,
        smooth: true,
        lineStyle: { color: paletteColor(i), width: 2 },
        itemStyle: { color: paletteColor(i) },
        areaStyle: { color: paletteColor(i), opacity: 0.12 },
        data: s.values.map(([t, v]) => [t * 1000, Number(v)]),
      })),
    };
  }, [series, unit]);

  return (
    <>
      <div className="card">
        <h2>Metrics Explorer</h2>
        <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 0 }}>
          Pick a metric below or write PromQL. Charts query <code>/api/metrics/query_range</code> and
          follow the global time range.
        </p>

        {/* Datadog-style categorized quick-picks of real telemetry. */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 12 }}>
          {groups.map((g) => (
            <div key={g.group} style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
              <span style={{ color: "var(--muted)", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, minWidth: 130 }}>
                {g.group}
              </span>
              {g.items.map((it) => {
                const active = query === it.q;
                return (
                  <button
                    key={it.q}
                    type="button"
                    onClick={() => pick(it)}
                    className={active ? "chip chip-active" : "chip"}
                    title={it.q}
                  >
                    {it.label}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        <form
          onSubmit={(e) => { e.preventDefault(); run(); }}
          style={{ display: "grid", gridTemplateColumns: "auto 1fr auto auto", gap: 8 }}
        >
          <MetricPicker
            names={names}
            onPick={(n) => { setQuery(n); run(n, rangeMinutes, unitFor(n)); }}
          />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="PromQL, e.g. rate(device_if_in_octets[5m]) * 8"
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}
          />
          <button disabled={busy} type="submit">{busy ? "Running…" : "Run"}</button>
          <button
            type="button"
            onClick={() => setLive((l) => !l)}
            className={live ? "chip chip-active" : "chip"}
            title="Stream the chart live (refresh every 5s)"
          >
            {live ? "● Live" : "○ Live"}
          </button>
        </form>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 12 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <h2 style={{ fontFamily: "ui-monospace, monospace", fontSize: 14 }}>{query}</h2>
        {series.length === 0 ? (
          <div className="empty">
            {busy ? "Loading…" : (
              <>
                No data for this query / range. Telemetry arrives every ~30–60s once collectors poll —
                try a quick-pick above (e.g. <strong>CPU utilization</strong>) or widen the time range.
                {names.length > 0 && <div style={{ marginTop: 6, fontSize: 12 }}>{names.length} metric names available.</div>}
              </>
            )}
          </div>
        ) : (
          <ReactECharts style={{ height: 420 }} option={option} notMerge />
        )}
      </div>
    </>
  );
}
