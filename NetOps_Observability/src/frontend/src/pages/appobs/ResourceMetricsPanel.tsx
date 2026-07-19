// ResourceMetricsPanel — the cloud metric charts (Wave 5 #14 slice 1).
// Renders provider metric-lane time series (CloudWatch / Azure Monitor / GCP
// Monitoring → VictoriaMetrics) for one resource (drawer) or an app's
// resources (App Detail). Honest states throughout: a resource the lane has
// never reported renders "not ingested — connect the source", an unreachable
// metric store is an error, never an empty chart.

import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../../services/api";
import type { CloudMetricSeriesResponse } from "../../services/api";
import { Segmented } from "../../components/ui";
import { chartBase, axisStyle, timeAxisTicks, colorForMetric, paletteColor } from "../../theme/charts";
import { EmptyState } from "./badges";
import {
  DEFAULT_CLOUD_METRIC, DEFAULT_METRIC_WINDOW, METRIC_MAX_RESOURCES, METRIC_WINDOWS,
  chartSeriesOf, fmtMetricValue, metricChoicesOf, silentResourcesOf,
} from "./metricsPanel";

export interface MetricTarget {
  id: string;   // resource_id — the inventory/VM join key
  name: string; // display name
}

export default function ResourceMetricsPanel({ targets, subject }: {
  targets: MetricTarget[]; subject: string;
}) {
  const [metric, setMetric] = useState<string>(DEFAULT_CLOUD_METRIC);
  const [minutes, setMinutes] = useState<number>(DEFAULT_METRIC_WINDOW);
  const [resp, setResp] = useState<CloudMetricSeriesResponse | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [err, setErr] = useState<string>("");

  const charted = targets.slice(0, METRIC_MAX_RESOURCES);
  const idsKey = charted.map((t) => t.id).join("|");

  useEffect(() => {
    if (charted.length === 0) return;
    let live = true;
    setStatus("loading");
    api.cloudMetricSeries(charted.map((t) => t.id), metric, minutes).then(
      (r) => { if (live) { setResp(r); setStatus("ready"); } },
      (e) => { if (live) { setErr((e as Error).message); setStatus("error"); } },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idsKey, metric, minutes]);

  const unit = resp?.unit ?? "";
  const series = useMemo(() => (resp ? chartSeriesOf(resp) : []), [resp]);
  const silent = resp ? silentResourcesOf(resp) : [];
  const choices = metricChoicesOf(resp);
  const metricLabel = choices.find((c) => c.name === metric)?.label ?? metric;

  const option = useMemo(() => ({
    ...chartBase,
    animationDuration: 600,
    animationEasing: "cubicOut",
    grid: { left: 64, right: 16, top: 28, bottom: 28 },
    tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number) => fmtMetricValue(v, unit) },
    legend: { ...chartBase.legend, type: "scroll", top: 0 },
    xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
    yAxis: {
      type: "value", ...axisStyle,
      axisLabel: { ...(axisStyle as { axisLabel: object }).axisLabel, formatter: (v: number) => fmtMetricValue(v, unit) },
    },
    series: series.map((s, i) => {
      const c = series.length === 1 ? colorForMetric(metricLabel) : paletteColor(i);
      return {
        name: s.name, type: "line", showSymbol: false, smooth: true,
        lineStyle: { color: c, width: 2 }, itemStyle: { color: c },
        areaStyle: { color: c, opacity: 0.12 }, data: s.data,
      };
    }),
  }), [series, unit, metricLabel]);

  if (targets.length === 0) {
    return (
      <EmptyState title="No cloud resources to chart"
        hint="Metrics attach to inventory resources — none is mapped here yet." />
    );
  }

  return (
    <div className="ao-metrics-panel">
      <div className="ao-metrics-ctl">
        <select className="app-select" value={metric} aria-label="Cloud metric"
          onChange={(e) => setMetric(e.target.value)}>
          {choices.map((c) => <option key={c.name} value={c.name}>{c.label}</option>)}
        </select>
        <Segmented
          value={String(minutes)}
          onChange={(v) => setMinutes(Number(v))}
          ariaLabel={`${subject} metric window`}
          options={METRIC_WINDOWS.map((w) => ({ value: String(w.minutes), label: w.label }))}
        />
      </div>

      {targets.length > METRIC_MAX_RESOURCES && (
        <p className="ao-set-d">Charting the first {METRIC_MAX_RESOURCES} of {targets.length} resources.</p>
      )}

      {status === "loading" && <div className="ao-muted">Loading metrics…</div>}

      {status === "error" && (
        <EmptyState title="Metric store unreachable"
          hint={`The chart could not be loaded — this is a query failure, not an empty series. ${err}`} />
      )}

      {status === "ready" && series.length === 0 && (
        <EmptyState title={`No ${metricLabel} ingested for ${subject} in this window`}
          hint="Cloud metrics arrive on the provider metric lane (CloudWatch / Azure Monitor / GCP Monitoring). Connect the account's metrics source in Data sources, or widen the window — nothing is simulated here." />
      )}

      {status === "ready" && series.length > 0 && (
        <>
          <ReactECharts style={{ height: 300 }} option={option} notMerge />
          {silent.length > 0 && (
            <p className="ao-set-d">
              No samples in this window for: {silent.join(", ")} — not ingested, not zero.
            </p>
          )}
        </>
      )}
    </div>
  );
}
