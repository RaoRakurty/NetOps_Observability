// Shared ECharts theming so every graph in the app reads as one product —
// a vivid, modern categorical palette on a transparent dark canvas, in the
// spirit of Datadog / Grafana.

export const CHART_PALETTE = [
  "#4f9eff", // blue
  "#3ddc97", // green
  "#ffb454", // amber
  "#ff6b81", // pink-red
  "#a78bfa", // violet
  "#22d3ee", // cyan
  "#f472b6", // magenta
  "#facc15", // yellow
  "#5eead4", // teal
  "#fb923c", // orange
];

const AXIS = "#8a93a0";
const GRID = "rgba(255,255,255,0.06)";

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
  textStyle: { color: "#c7cdd6", fontFamily: "inherit" },
  tooltip: {
    backgroundColor: "rgba(18, 22, 28, 0.94)",
    borderColor: "#2c333d",
    borderWidth: 1,
    textStyle: { color: "#e6e8eb" },
  },
  legend: { textStyle: { color: AXIS }, inactiveColor: "#454c57" },
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
      { offset: 0, color: hexToRgba(c, 0.38) },
      { offset: 1, color: hexToRgba(c, 0.02) },
    ],
  };
}
