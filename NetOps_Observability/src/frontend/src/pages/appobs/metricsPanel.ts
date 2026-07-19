// metricsPanel.ts — pure logic for the cloud metric charts (Wave 5 #14 slice 1).
// Everything here is view-model math (no fetch, no React) so it unit-tests
// directly: window choices, value formatting by unit, and the mapping from the
// API's [unix_seconds, value] points to ECharts [ms, value] series.

import type { CloudMetricCatalogEntry, CloudMetricSeriesResponse } from "../../services/api";

// The metric picker's fallback vocabulary — mirrors the backend's closed
// catalog (cloud_metrics_series.go). The response's own `catalog` replaces this
// once the first load lands, so the two can never drift for long.
export const CLOUD_METRIC_FALLBACK: CloudMetricCatalogEntry[] = [
  { name: "cloud_cpu_util", label: "CPU utilization", unit: "percent" },
  { name: "cloud_net_in_bytes", label: "Network in", unit: "bytes" },
  { name: "cloud_net_out_bytes", label: "Network out", unit: "bytes" },
  { name: "cloud_status_check_failed", label: "Provider status check failed", unit: "count" },
  { name: "cloud_cpu_credit_balance", label: "CPU credit balance", unit: "count" },
];

export const DEFAULT_CLOUD_METRIC = "cloud_cpu_util";

// Window choices: one provider period is 5m, so anything below 1h is noise.
export const METRIC_WINDOWS: { minutes: number; label: string }[] = [
  { minutes: 60, label: "1h" },
  { minutes: 180, label: "3h" },
  { minutes: 1440, label: "24h" },
  { minutes: 10080, label: "7d" },
];
export const DEFAULT_METRIC_WINDOW = 180;

// The backend charts at most this many resources per request (its hard cap).
export const METRIC_MAX_RESOURCES = 6;

// fmtMetricValue — unit-aware axis/tooltip formatting. Bytes get IEC steps,
// percent gets a % suffix, counts stay plain.
export function fmtMetricValue(v: number, unit: string): string {
  if (!Number.isFinite(v)) return "—";
  if (unit === "percent") return `${v.toFixed(v >= 10 ? 0 : 1)}%`;
  if (unit === "bytes") {
    const abs = Math.abs(v);
    if (abs >= 1 << 30) return `${(v / (1 << 30)).toFixed(1)} GiB`;
    if (abs >= 1 << 20) return `${(v / (1 << 20)).toFixed(1)} MiB`;
    if (abs >= 1 << 10) return `${(v / (1 << 10)).toFixed(1)} KiB`;
    return `${Math.round(v)} B`;
  }
  return abbreviateCount(v);
}

function abbreviateCount(v: number): string {
  const abs = Math.abs(v);
  if (abs >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `${(v / 1e3).toFixed(1)}k`;
  return Number.isInteger(v) ? String(v) : v.toFixed(2);
}

export interface MetricChartSeries {
  name: string;
  data: [number, number][]; // [epoch_ms, value] for the ECharts time axis
}

// chartSeriesOf — API response → chart series, DROPPING resources with no
// samples (they get the honest per-resource "not ingested" note instead of a
// blank line pretending to be zero).
export function chartSeriesOf(resp: CloudMetricSeriesResponse): MetricChartSeries[] {
  return resp.series
    .filter((s) => s.points.length > 0)
    .map((s) => ({
      name: s.resource_name || s.resource_id,
      data: s.points.map(([sec, v]) => [sec * 1000, v] as [number, number]),
    }));
}

// silentResourcesOf — the resources the store had NO samples for in the window
// (named explicitly in the empty/partial state).
export function silentResourcesOf(resp: CloudMetricSeriesResponse): string[] {
  return resp.series.filter((s) => s.points.length === 0).map((s) => s.resource_name || s.resource_id);
}

// metricChoicesOf — the picker list: the server catalog once present, else the
// fallback mirror.
export function metricChoicesOf(resp: CloudMetricSeriesResponse | null): CloudMetricCatalogEntry[] {
  if (resp && resp.catalog && resp.catalog.length > 0) return resp.catalog;
  return CLOUD_METRIC_FALLBACK;
}
