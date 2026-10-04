// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// charts.tsx — the Iris TIME_SERIES and BAR views on the app's single ECharts
// host (components/EChart). Rules (design Part 2 §31, §65):
//
//   · No dead ends — clicking a point or a bar emits the rows behind it, so the
//     renderer can open them as a table.
//   · Unmeasured is not zero — a missing sample is a gap in the line, a missing
//     earlier-window value is no bar plus the words "not measured".
//   · No HTML sink — the tooltip runs in ECharts' richText mode (canvas text), so
//     an entity name like "<img onerror=…>" is drawn as characters, never parsed.
//
// The option building is pure and exported for tests.

import { useMemo } from "react";
import EChart, { type EChartEvents } from "../components/EChart";
import { axisStyle, chartBase, timeAxisTicks } from "../theme/charts";
import { entityLabel, fmtNumber, type OutSeries, type ResultSet, type Row } from "./presentation";

export interface DrillDown {
  label: string;
  rows: Row[];
}

const TOOLTIP = { renderMode: "richText" as const };

// ── time series ──────────────────────────────────────────────────────────────

export function measuredSeries(series: OutSeries[]): OutSeries[] {
  return series.filter((s) => s.points.some((p) => p.v !== null));
}

export function timeSeriesOption(series: OutSeries[], unit: string): Record<string, unknown> {
  return {
    ...chartBase,
    tooltip: { ...chartBase.tooltip, ...TOOLTIP, trigger: "axis" },
    legend: { ...chartBase.legend, type: "scroll", bottom: 0 },
    grid: { left: 56, right: 20, top: 24, bottom: 48 },
    xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
    yAxis: { type: "value", ...axisStyle, name: unit || undefined },
    series: series.map((s) => ({
      type: "line",
      name: entityLabel(s.entity),
      showSymbol: false,
      // A null sample is a GAP — connectNulls false keeps it visible as one.
      connectNulls: false,
      data: s.points.map((p) => [p.t * 1000, p.v]),
    })),
  };
}

export function TimeSeriesView({
  result,
  onDrill,
}: {
  result: ResultSet;
  onDrill: (d: DrillDown) => void;
}) {
  const series = useMemo(() => measuredSeries(result.series), [result.series]);
  const option = useMemo(() => timeSeriesOption(series, result.unit), [series, result.unit]);
  const events = useMemo<EChartEvents>(
    () => ({
      click: (p: { seriesIndex?: number }) => {
        const s = typeof p?.seriesIndex === "number" ? series[p.seriesIndex] : undefined;
        if (!s) return;
        onDrill({
          label: entityLabel(s.entity),
          rows: s.points.map((pt) => ({ ...s.entity, time: new Date(pt.t * 1000).toISOString(), value: pt.v })),
        });
      },
    }),
    [series, onDrill],
  );
  if (series.length === 0) return <p className="iris-empty" role="status">Nothing found in this window.</p>;
  const gaps = series.some((s) => s.points.some((p) => p.v === null));
  return (
    <figure className="iris-chart">
      <EChart option={option} onEvents={events} notMerge style={{ height: 280 }} />
      <figcaption className="iris-note">
        Select a line to see its values.{gaps && " Gaps in a line are periods with no measurement."}
      </figcaption>
    </figure>
  );
}

// ── bars ──────────────────────────────────────────────────────────────────────

export interface BarModel {
  categories: string[];
  /** Rows behind each category, in the same order — the drill-down payload. */
  groups: Row[][];
  series: { name: string; values: (number | null)[] }[];
  /** Per category label drawn beside the bar (e.g. the delta), or null. */
  labels: (string | null)[];
  kind: "compare" | "values" | "counts";
}

const NOT_RECORDED = "Not recorded";

/** Group rows into bars. Pure. Returns null when the rows have nothing to bar. */
export function barModel(result: ResultSet, groupField?: string): BarModel | null {
  const rows = result.rows;
  if (rows.length === 0) return null;

  if (result.query_type === "change_list" || result.query_type === "incident_list") {
    const field = groupField || (result.query_type === "change_list" ? "actor" : "state");
    const order: string[] = [];
    const by = new Map<string, Row[]>();
    for (const r of rows) {
      const v = r[field];
      const k = typeof v === "string" && v.trim() !== "" ? v : NOT_RECORDED;
      if (!by.has(k)) {
        by.set(k, []);
        order.push(k);
      }
      (by.get(k) as Row[]).push(r);
    }
    order.sort((a, b) => (by.get(b) as Row[]).length - (by.get(a) as Row[]).length);
    return {
      kind: "counts",
      categories: order,
      groups: order.map((k) => by.get(k) as Row[]),
      series: [{ name: result.query_type === "change_list" ? "Changes" : "Incidents", values: order.map((k) => (by.get(k) as Row[]).length) }],
      labels: order.map(() => null),
    };
  }

  const categories = rows.map((r) => entityLabel(r));
  const groups = rows.map((r) => [r]);
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);

  if (result.query_type === "compare_windows") {
    return {
      kind: "compare",
      categories,
      groups,
      series: [
        { name: "Earlier window", values: rows.map((r) => num(r.previous)) },
        { name: "This window", values: rows.map((r) => num(r.value)) },
      ],
      labels: rows.map((r) => {
        const d = num(r.delta);
        if (d === null) return "change not measured";
        const s = fmtNumber(d, result.unit) as string;
        return d > 0 ? `+${s}` : s;
      }),
    };
  }

  if (!rows.some((r) => num(r.value) !== null)) return null;
  return {
    kind: "values",
    categories,
    groups,
    series: [{ name: result.metric || "Value", values: rows.map((r) => num(r.value)) }],
    labels: rows.map((r) => (num(r.value) === null ? "not measured" : null)),
  };
}

export function barOption(m: BarModel, unit: string): Record<string, unknown> {
  const last = m.series.length - 1;
  return {
    ...chartBase,
    tooltip: { ...chartBase.tooltip, ...TOOLTIP, trigger: "axis", axisPointer: { type: "shadow" } },
    legend: m.series.length > 1 ? { ...chartBase.legend, bottom: 0 } : undefined,
    grid: { left: 150, right: 90, top: 16, bottom: m.series.length > 1 ? 40 : 16 },
    xAxis: { type: "value", ...axisStyle, name: m.kind === "counts" ? undefined : unit || undefined },
    yAxis: { type: "category", ...axisStyle, inverse: true, data: m.categories },
    series: m.series.map((s, si) => ({
      type: "bar",
      name: s.name,
      data: s.values,
      label:
        si === last
          ? {
              show: true,
              position: "right",
              fontSize: 14,
              // Canvas text, not HTML. Shows the delta (compare) or the words
              // "not measured" where a value is missing — never a 0.
              formatter: (p: { dataIndex: number; value: number | null }) =>
                m.labels[p.dataIndex] ?? (p.value === null || p.value === undefined ? "" : (fmtNumber(p.value) ?? "")),
            }
          : { show: false },
    })),
  };
}

export function BarView({
  result,
  groupField,
  onDrill,
}: {
  result: ResultSet;
  groupField?: string;
  onDrill: (d: DrillDown) => void;
}) {
  const model = useMemo(() => barModel(result, groupField), [result, groupField]);
  const option = useMemo(() => (model ? barOption(model, result.unit) : null), [model, result.unit]);
  const events = useMemo<EChartEvents>(
    () => ({
      click: (p: { dataIndex?: number }) => {
        if (!model || typeof p?.dataIndex !== "number") return;
        const rows = model.groups[p.dataIndex];
        if (rows) onDrill({ label: model.categories[p.dataIndex], rows });
      },
    }),
    [model, onDrill],
  );
  if (!model || !option) return <p className="iris-empty" role="status">Nothing found in this window.</p>;
  const height = Math.min(Math.max(model.categories.length * (model.series.length > 1 ? 44 : 32) + 60, 160), 520);
  return (
    <figure className="iris-chart">
      <EChart option={option} onEvents={events} notMerge style={{ height }} />
      <figcaption className="iris-note">
        Select a bar to see the rows behind it.
        {model.kind === "compare" && " The number beside each pair is the change from the earlier window."}
        {result.truncated && model.kind === "counts" && " Counts cover only the rows returned, not every match."}
      </figcaption>
    </figure>
  );
}
