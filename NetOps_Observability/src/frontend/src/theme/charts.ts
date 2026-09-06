// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Shared ECharts theming so every graph in the app reads as one product —
// a vivid, modern categorical palette tuned for the LIGHT canvas (saturated
// enough to feel alive on white, still AA-legible), in the spirit of
// the reference platform / Grafana. Ordered so adjacent series stay maximally distinct.

// 2026-07: the darker slots (indigo/violet/red/pink/sky/orange — the old
// Tailwind 500/600 steps) lifted one step lighter (~25% brightness) so dense
// bar boards read airy instead of heavy; hues that were already light
// (amber/gold, cyan, emerald, teal) stay put. Validated (lightness band,
// chroma floor, CVD adjacent-pair separation) on the light canvas.
export const CHART_PALETTE = [
  "#818cf8", // indigo (brand)
  "#06b6d4", // cyan
  "#f59e0b", // amber
  "#f472b6", // pink
  "#10b981", // emerald
  "#a78bfa", // violet
  "#f87171", // red
  "#38bdf8", // sky
  "#fb923c", // orange
  "#14b8a6", // teal
];

// colorForMetric — the design pattern that ends the "everything is purple" problem.
// A single metric always gets the SAME hue across the whole app (learnable), and
// different metric families get DIFFERENT hues by meaning. Semantic keywords first
// (so traffic is always cyan, errors always red, latency always amber…), then a
// stable hash into the palette so any unmatched metric still gets a distinct,
// consistent colour rather than the brand indigo every time.
const METRIC_HUES: [RegExp, string][] = [
  [/error|discard|drop|fail|deny|reject|crit/i, "#f87171"], // red
  [/loss|miss/i, "#f472b6"],                                // pink
  [/latency|rtt|delay|jitter|response/i, "#f59e0b"],        // amber
  [/traffic|throughput|bandwidth|bits|bps|octet|byte|\btx\b|\brx\b/i, "#06b6d4"], // cyan
  [/packet|pps|flow|session|conn/i, "#38bdf8"],             // sky
  [/cpu|load|util/i, "#a78bfa"],                            // violet
  [/mem|heap|buffer/i, "#818cf8"],                          // indigo
  [/temp|fan|power|env|heat/i, "#fb923c"],                  // orange
  [/up\b|avail|health|online|reach|ok\b/i, "#10b981"],      // emerald
  [/disk|storage|queue|depth/i, "#14b8a6"],                 // teal
];
export function colorForMetric(name: string): string {
  const n = name || "";
  for (const [re, c] of METRIC_HUES) if (re.test(n)) return c;
  let h = 0;
  for (let i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) | 0;
  return CHART_PALETTE[Math.abs(h) % CHART_PALETTE.length];
}

import { cssVar } from "./tokens";
import { fmtAxisTick, fmtDateTime } from "../lib/time";

// Axis/grid chrome resolves from the semantic tokens at chart-build time, so
// charts follow [data-theme] (light/dark/oled) instead of assuming light.
const axisColor = () => cssVar("--fg-muted", "#667085");
const gridColor = () => cssVar("--border", "rgba(17,24,39,0.07)");

export function hexToRgba(hex: string, a: number): string {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

export function paletteColor(i = 0): string {
  return CHART_PALETTE[((i % CHART_PALETTE.length) + CHART_PALETTE.length) % CHART_PALETTE.length];
}

// Base option fragment — spread first into any chart's `option`. Font sizes are
// set explicitly (ECharts defaults to a small 12px) so axis ticks, legends and
// tooltips stay legible on dense boards. Property getters re-resolve the theme
// tokens each time the object is spread, so a rebuilt chart picks up the theme.
export const chartBase = {
  backgroundColor: "transparent",
  color: CHART_PALETTE,
  get textStyle() {
    return { color: axisColor(), fontFamily: "inherit", fontSize: 13 };
  },
  get tooltip() {
    return {
      backgroundColor: cssVar("--overlay", "#ffffff"),
      borderColor: cssVar("--border", "#e4e7ec"),
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: cssVar("--fg", "#1a2230"), fontSize: 13 },
      // Richer hover: a crosshair that tracks both axes, plus a soft shadow card.
      axisPointer: { type: "cross", lineStyle: { color: "rgba(127,137,160,0.45)", width: 1 }, crossStyle: { color: "rgba(127,137,160,0.45)" }, label: { backgroundColor: axisColor(), fontSize: 12 } },
      extraCssText: "box-shadow:0 8px 28px rgba(16,24,40,0.14); border-radius:8px;",
    };
  },
  get legend() {
    return { textStyle: { color: axisColor(), fontSize: 13 }, inactiveColor: cssVar("--fg-subtle", "#c2c8d0"), itemGap: 16, itemWidth: 16, itemHeight: 10 };
  },
};

// Reusable axis styling for cartesian charts. Larger tick labels + named-axis
// styling so units/labels read clearly; hideOverlap avoids crowded ticks.
export const axisStyle = {
  get axisLine() { return { lineStyle: { color: axisColor() } }; },
  get axisLabel() { return { color: axisColor(), fontSize: 13, hideOverlap: true, margin: 10 }; },
  get axisTick() { return { lineStyle: { color: axisColor() } }; },
  get nameTextStyle() { return { color: axisColor(), fontSize: 12, fontWeight: 600, padding: [0, 0, 0, 4] }; },
  get splitLine() { return { lineStyle: { color: gridColor() } }; },
};

// Time-axis fragments (log-time standard S6): axis tick labels and the
// crosshair pill obey the top-bar Local/UTC knob via lib/time — ECharts'
// built-in time-axis labels always render browser-local, which contradicted
// every other timestamp on the page when the knob was on UTC. Spread INTO the
// axis object AFTER axisStyle so the formatter wins:
//   xAxis: { type: "time", ...axisStyle, ...timeAxisTicks }
// (Charts rebuild on toggle — the page remounts — so the mode is re-read.)
export function timeAxisTicks() {
  return {
    axisLabel: { ...axisStyle.axisLabel, formatter: (v: number) => fmtAxisTick(v) },
    axisPointer: { label: { formatter: (p: { value: number | string | Date }) => fmtDateTime(p.value) } },
  };
}

// Translucent top-to-bottom gradient fill for an area/line series, keyed to
// the palette so each series gets its own hue.
export function areaGradient(i = 0) {
  const c = paletteColor(i);
  return {
    type: "linear",
    x: 0,
    y: 0,
    x2: 0,
    y2: 1,
    colorStops: [
      { offset: 0, color: hexToRgba(c, 0.45) },
      { offset: 1, color: hexToRgba(c, 0.0) },
    ],
  };
}

// reference-grade line series defaults: thin smooth stroke, no markers, a soft
// area wash keyed to the series hue. Spread into any line series object.
export function lineSeriesDefaults(i = 0) {
  return {
    type: "line",
    smooth: true,
    showSymbol: false,
    lineStyle: { width: 2, color: paletteColor(i) },
    itemStyle: { color: paletteColor(i) },
    areaStyle: { color: areaGradient(i) },
  };
}
