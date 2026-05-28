import { useEffect, useMemo, useRef, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, PromSeries } from "../services/api";
import { chartBase, axisStyle, paletteColor } from "../theme/charts";

// Native Metrics Explorer — a Grafana-style PromQL surface that renders
// charts in-app (ECharts) instead of iframing Prometheus. Queries the
// Go /api/metrics/* proxy, governed by the shell's global time range.

type Props = { rangeMinutes?: number };

const SUGGESTIONS = [
  "go_goroutines",
  "rate(go_memstats_alloc_bytes_total[5m])",
  "process_resident_memory_bytes",
  "up",
];

export default function MetricsExplorer({ rangeMinutes = 60 }: Props) {
  const [query, setQuery] = useState("go_goroutines");
  const [series, setSeries] = useState<PromSeries[]>([]);
  const [names, setNames] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ran = useRef(false);

  // Metric-name list for the datalist autocomplete.
  useEffect(() => {
    api.metricNames().then((r) => setNames(r?.data ?? [])).catch(() => setNames([]));
  }, []);

  const run = async (q = query, minutes = rangeMinutes) => {
    if (!q.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const end = Math.floor(Date.now() / 1000);
      const start = end - minutes * 60;
      // Aim for ~240 points across the window.
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

  // Run on mount and whenever the global time range changes.
  useEffect(() => {
    run(query, rangeMinutes);
    ran.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rangeMinutes]);

  const option = useMemo(() => {
    const label = (m: Record<string, string>) => {
      const name = m.__name__ ?? "value";
      const inst = m.instance ? `{${m.instance}}` : "";
      const job = m.job ? ` ${m.job}` : "";
      return `${name}${job}${inst}`.trim();
    };
    return {
      ...chartBase,
      grid: { left: 56, right: 16, top: 16, bottom: 28 },
      tooltip: { ...chartBase.tooltip, trigger: "axis" },
      legend: { ...chartBase.legend, type: "scroll", top: 0 },
      xAxis: { type: "time", ...axisStyle },
      yAxis: { type: "value", ...axisStyle },
      series: series.map((s, i) => ({
        name: label(s.metric),
        type: "line",
        showSymbol: false,
        smooth: true,
        lineStyle: { color: paletteColor(i), width: 2 },
        itemStyle: { color: paletteColor(i) },
        data: s.values.map(([t, v]) => [t * 1000, Number(v)]),
      })),
    };
  }, [series]);

  return (
    <>
      <div className="card">
        <h2>Metrics Explorer</h2>
        <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 0 }}>
          PromQL against <code>/api/metrics/query_range</code>. Time range follows the
          global picker. Try: {SUGGESTIONS.map((s) => <code key={s} style={{ marginRight: 8 }}>{s}</code>)}
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run();
          }}
          style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8 }}
        >
          <input
            list="metric-names"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="PromQL, e.g. rate(go_memstats_alloc_bytes_total[5m])"
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 13 }}
          />
          <datalist id="metric-names">
            {names.slice(0, 2000).map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
          <button disabled={busy} type="submit">
            {busy ? "Running…" : "Run"}
          </button>
        </form>
        {error && (
          <p style={{ color: "var(--bad)", marginTop: 12 }}>
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <h2>{query}</h2>
        {series.length === 0 ? (
          <div className="empty">{busy ? "Loading…" : "No data for this query / range."}</div>
        ) : (
          <ReactECharts style={{ height: 420 }} option={option} notMerge />
        )}
      </div>
    </>
  );
}
