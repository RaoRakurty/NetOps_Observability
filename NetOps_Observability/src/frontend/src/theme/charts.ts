// Shared ECharts theming so every graph in the app reads as one product —
// a vivid, modern categorical palette tuned for the LIGHT canvas (saturated
// enough to feel alive on white, still AA-legible), in the spirit of
// the reference platform / Grafana. Ordered so adjacent series stay maximally distinct.

export const CHART_PALETTE = [
  "#4f46e5", // indigo (brand)
  "#06b6d4", // cyan
  "#f59e0b", // amber
  "#ec4899", // pink
  "#10b981", // emerald
  "#8b5cf6", // violet
  "#ef4444", // red
  "#0ea5e9", // sky
  "#f97316", // orange
  "#14b8a6", // teal
];

import { cssVar } from "./tokens";

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
