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

const AXIS = "#667085";
const GRID = "rgba(17,24,39,0.07)";

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

// Base option fragment — spread first into any chart's `option`.
export const chartBase = {
  backgroundColor: "transparent",
  color: CHART_PALETTE,
  textStyle: { color: "#475467", fontFamily: "inherit" },
  tooltip: {
    backgroundColor: "#ffffff",
    borderColor: "#e4e7ec",
    borderWidth: 1,
    textStyle: { color: "#1a2230" },
  },
  legend: { textStyle: { color: AXIS }, inactiveColor: "#c2c8d0" },
};

// Reusable axis styling for cartesian charts.
export const axisStyle = {
  axisLine: { lineStyle: { color: AXIS } },
  axisLabel: { color: AXIS },
  splitLine: { lineStyle: { color: GRID } },
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
