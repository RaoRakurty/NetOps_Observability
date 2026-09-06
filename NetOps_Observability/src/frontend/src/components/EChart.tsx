// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EChart — the app's single ECharts host, built on the tree-shakeable
// `echarts/core` path (same pattern GeoTopologyMap.tsx already used for
// registerMap). Replaces the class-based `echarts-for-react` default wrapper,
// which required the FULL echarts build (~1.1 MB min) into every chunk that
// drew a chart. Only the renderers/charts/components the app actually uses are
// registered below — adding a new series type means registering it here.
//
// Prop surface intentionally mirrors the subset of echarts-for-react the app
// used: option, style, notMerge, lazyUpdate, onEvents. Charts resize with
// their container (ResizeObserver), dispose on unmount.

import { CSSProperties, useEffect, useRef } from "react";
import { init, use, type EChartsCoreOption, type EChartsType } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import {
  BarChart,
  EffectScatterChart,
  GaugeChart,
  HeatmapChart,
  LineChart,
  LinesChart,
  PieChart,
} from "echarts/charts";
import {
  GeoComponent,
  GridComponent,
  LegendComponent,
  MarkLineComponent,
  TitleComponent,
  TooltipComponent,
  VisualMapComponent,
} from "echarts/components";

// Census of series/components across the app (2026-08-03): line, bar, pie,
// gauge, heatmap, effectScatter, lines(geo); grid/tooltip/legend(scroll)/
// title/visualMap/markLine and the geo coordinate system (world basemap).
use([
  CanvasRenderer,
  LineChart,
  BarChart,
  PieChart,
  GaugeChart,
  HeatmapChart,
  EffectScatterChart,
  LinesChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  TitleComponent,
  VisualMapComponent,
  MarkLineComponent,
  GeoComponent,
]);

// Loose on purpose, mirroring echarts-for-react's surface: options are built
// as plain literals across 9 call sites and event handlers type their own
// params — the chart treats both as data it hands to echarts verbatim.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type EChartEvents = Record<string, (params: any) => void>;

export default function EChart({
  option,
  style,
  notMerge = false,
  lazyUpdate = false,
  onEvents,
}: {
  option: Record<string, unknown>;
  style?: CSSProperties;
  notMerge?: boolean;
  lazyUpdate?: boolean;
  onEvents?: EChartEvents;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<EChartsType | null>(null);

  // Init once per mount; resize with the container; dispose on unmount.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const chart = init(el);
    chartRef.current = chart;
    let ro: ResizeObserver | undefined;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(() => {
        if (!chart.isDisposed()) chart.resize();
      });
      ro.observe(el);
    }
    return () => {
      ro?.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Push option changes (mount order guarantees the chart exists by now).
  useEffect(() => {
    const chart = chartRef.current;
    if (chart && !chart.isDisposed()) chart.setOption(option as EChartsCoreOption, { notMerge, lazyUpdate });
  }, [option, notMerge, lazyUpdate]);

  // Event map — bound per identity of onEvents (memoize it in the caller to
  // avoid per-render rebinding; rebinding is correct either way).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart || !onEvents) return;
    const entries = Object.entries(onEvents);
    for (const [evt, handler] of entries) chart.on(evt, handler as (...args: unknown[]) => void);
    return () => {
      if (chart.isDisposed()) return;
      for (const [evt, handler] of entries) chart.off(evt, handler as (...args: unknown[]) => void);
    };
  }, [onEvents]);

  // echarts-for-react defaulted the host to 300px tall; keep that so callers
  // that only set width (none today) render identically.
  return <div ref={ref} style={{ height: 300, ...style }} />;
}
