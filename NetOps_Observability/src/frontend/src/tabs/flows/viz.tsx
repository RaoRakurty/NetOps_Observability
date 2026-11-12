// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// viz — the two small marks the Flows tables draw inline, no chart library per
// row: a utilisation meter and a sparkline. Colours are CSS classes mapped to
// --flow-* tokens (theme/flows-tokens.css); nothing here names a colour.

import { fmtPctOrDash, utilBand } from "./flowsModel";

/** "73%" with a short bar: the calm ramp for normal load, the bands above it. */
export function UtilMeter({ pct, title }: { pct?: number; title?: string }) {
  const band = utilBand(pct);
  const tone = band === "crit" ? "crit" : band === "warn" ? "warn" : "";
  const width = pct === undefined || !Number.isFinite(pct) ? 0 : Math.max(2, Math.min(100, pct));
  return (
    <span className={`tr-util ${tone}`} title={title} data-band={band || "none"}>
      {band && (
        <span className={`tr-meter ${band}`} aria-hidden="true">
          <span style={{ width: `${width}%` }} />
        </span>
      )}
      <span className="tr-pct">{fmtPctOrDash(pct)}</span>
    </span>
  );
}

/**
 * A smooth path through the points (Catmull-Rom as cubic Béziers), the area
 * under it, and an emphasised last point. Pure geometry; exported for tests.
 */
export function sparkPaths(values: readonly number[], w: number, h: number, pad = 3): { line: string; area: string; end: [number, number] } | null {
  const v = values.filter((x) => Number.isFinite(x));
  if (v.length < 2) return null;
  const max = Math.max(...v);
  const min = Math.min(...v);
  const span = max - min || 1;
  const pts = v.map((y, i): [number, number] => [pad + (i / (v.length - 1)) * (w - 2 * pad), h - pad - ((y - min) / span) * (h - 2 * pad)]);
  const f = (n: number) => n.toFixed(1);
  let line = `M${f(pts[0][0])},${f(pts[0][1])}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[Math.min(pts.length - 1, i + 2)];
    const c1: [number, number] = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
    const c2: [number, number] = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
    line += ` C${f(c1[0])},${f(c1[1])} ${f(c2[0])},${f(c2[1])} ${f(p2[0])},${f(p2[1])}`;
  }
  const last = pts[pts.length - 1];
  const area = `${line} L${f(last[0])},${f(h)} L${f(pts[0][0])},${f(h)} Z`;
  return { line, area, end: last };
}

export function Sparkline({ values, label, width = 104, height = 28 }: { values?: number[]; label: string; width?: number; height?: number }) {
  const p = values ? sparkPaths(values, width, height) : null;
  if (!p) return <span className="tr-quiet">—</span>;
  return (
    <svg className="tr-spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <path className="tr-spark-area" d={p.area} />
      <path className="tr-spark-line" d={p.line} />
      <circle className="tr-spark-end" cx={p.end[0]} cy={p.end[1]} r={3} />
    </svg>
  );
}
