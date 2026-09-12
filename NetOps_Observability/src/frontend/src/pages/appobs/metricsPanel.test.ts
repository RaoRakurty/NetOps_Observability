// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import {
  CLOUD_METRIC_FALLBACK, METRIC_MAX_RESOURCES, chartSeriesOf, fmtMetricValue,
  metricChoicesOf, silentResourcesOf,
} from "./metricsPanel";
import type { CloudMetricSeriesResponse } from "../../services/api";

const resp = (over: Partial<CloudMetricSeriesResponse> = {}): CloudMetricSeriesResponse => ({
  metric: "cloud_cpu_util", label: "CPU utilization", unit: "percent",
  window_minutes: 180, step_seconds: 60, start: 0, end: 10800,
  series: [], catalog: [], ...over,
});

describe("chartSeriesOf", () => {
  it("maps [sec,val] points to [ms,val] and names by resource_name", () => {
    const r = resp({
      series: [{ resource_id: "i-1", resource_name: "web-1", points: [[100, 1.5], [160, 2]] }],
    });
    const s = chartSeriesOf(r);
    expect(s).toHaveLength(1);
    expect(s[0].name).toBe("web-1");
    expect(s[0].data).toEqual([[100000, 1.5], [160000, 2]]);
  });

  it("drops empty series (honest 'not ingested', not a zero line) and falls back to the id", () => {
    const r = resp({
      series: [
        { resource_id: "i-1", points: [[100, 1]] },
        { resource_id: "i-2", resource_name: "db-1", points: [] },
      ],
    });
    expect(chartSeriesOf(r).map((s) => s.name)).toEqual(["i-1"]);
    expect(silentResourcesOf(r)).toEqual(["db-1"]);
  });
});

describe("fmtMetricValue", () => {
  it("formats by unit", () => {
    expect(fmtMetricValue(42.4, "percent")).toBe("42%");
    expect(fmtMetricValue(3.14, "percent")).toBe("3.1%");
    expect(fmtMetricValue(2048, "bytes")).toBe("2.0 KiB");
    expect(fmtMetricValue(3 * 1024 * 1024, "bytes")).toBe("3.0 MiB");
    expect(fmtMetricValue(12, "count")).toBe("12");
    expect(fmtMetricValue(2500, "count")).toBe("2.5k");
  });
  it("never fabricates a number for non-finite input", () => {
    expect(fmtMetricValue(NaN, "percent")).toBe("—");
    expect(fmtMetricValue(Infinity, "bytes")).toBe("—");
  });
});

describe("metricChoicesOf", () => {
  it("prefers the server catalog, falls back to the local mirror", () => {
    expect(metricChoicesOf(null)).toBe(CLOUD_METRIC_FALLBACK);
    expect(metricChoicesOf(resp())).toBe(CLOUD_METRIC_FALLBACK);
    const withCat = resp({ catalog: [{ name: "cloud_cpu_util", label: "CPU", unit: "percent" }] });
    expect(metricChoicesOf(withCat)).toEqual(withCat.catalog);
  });
});

describe("bounds", () => {
  it("mirrors the backend resource cap", () => {
    expect(METRIC_MAX_RESOURCES).toBe(6);
  });
});
