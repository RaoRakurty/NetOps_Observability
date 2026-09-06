// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import ReactECharts from "../components/EChart";
import { api } from "../services/api";
import { usePolled, latestFromProm, nowWindow, seriesLabel } from "./panels";
import { hexToRgba } from "../theme/charts";
import { escapeHtml } from "../lib/text";

// demoPanels.tsx — the marketing board's chart family.
//
// These are NOT the operational panels: this file exists so the Demo Showcase
// can be visually maximal (patterned arcs, ridgelines, activity heatmaps,
// racing bars) without pushing that styling into the boards operators use all
// day, where calm and legible wins.
//
// Everything renders LIVE data through the same api client the rest of the app
// uses — nothing here is mocked. What is deliberately "demo" is only the
// treatment: density, motion and colour.
//
// Palette: validated with the dataviz six-check tool against the DARK surface
// (#1a1a19) — lightness band, chroma floor, CVD adjacent-pair separation,
// normal-vision floor and 3:1 contrast all PASS. Do not substitute hues here
// without re-running scripts/validate_palette.js.
export const DEMO_SERIES = ["#0284c7", "#d97706", "#6366f1", "#059669", "#a855f7", "#f43f5e"];

/** Sequential ramp for magnitude (one hue, light→dark) — heatmap + ridgeline. */
const RAMP = ["#0c4a6e", "#075985", "#0369a1", "#0284c7", "#0ea5e9", "#38bdf8", "#7dd3fc"];

const INK = "#e8edf7";
const INK_DIM = "#94a3b8";
const GRID = "rgba(148,163,184,0.14)";

/** Shared dark-canvas chart base. */
const base = {
  backgroundColor: "transparent",
  animationDuration: 900,
  animationEasing: "cubicOut" as const,
  textStyle: { color: INK_DIM, fontFamily: "inherit" },
  tooltip: {
    trigger: "axis" as const,
    backgroundColor: "rgba(10,14,26,0.94)",
    borderColor: "rgba(148,163,184,0.25)",
    textStyle: { color: INK, fontSize: 11 },
  },
};

const axis = {
  axisLine: { lineStyle: { color: GRID } },
  axisTick: { show: false },
  splitLine: { lineStyle: { color: GRID, type: "dashed" as const } },
  axisLabel: { color: INK_DIM, fontSize: 10 },
};

// UI-words sweep 5 (tracker 270): the loading / failed / empty lines below are
// STATED FACTS about the feed, not explanations, so they stop wearing the
// `demo-note` note class the word-budget guard reads (src/wordBudget.test.ts).
// The demo board is dark and owns its own ink token, so the two presentational
// values `.demo-note` carried travel inline rather than in a new global rule —
// at 12.5px, the sweep's typography floor (they rendered at 11px).
const DEMO_STATE: CSSProperties = {
  padding: "22px 8px", textAlign: "center", color: "var(--d-dim)", fontSize: 12.5,
};
const DEMO_STATE_BAD: CSSProperties = { ...DEMO_STATE, color: "#fca5a5" };

/** Fixed-height chart shell with an honest empty/failed state. */
function Chart({ height, option, err, empty }: {
  height: number; option: Record<string, unknown>; err?: unknown; empty?: boolean;
}) {
  if (err) return <div className="fact-line" style={DEMO_STATE_BAD}>Feed unavailable.</div>;
  if (empty) return <div className="fact-line" style={DEMO_STATE}>Waiting for data…</div>;
  return <ReactECharts notMerge style={{ height }} option={option} />;
}

// ── 1. Patterned radial gauge ───────────────────────────────────────────────
// Replaces the flat "spin wheel": a segmented arc (28 discrete ticks, so the
// ring reads as a precision instrument rather than a pie slice), a soft inner
// glow, a faint scale ladder, and a delta chip. The pattern IS the segmentation
// — it gives the arc texture at any size and reads clearly in a screenshot.
export function ArcGauge({ query, label, unit = "%", max = 100, hue = 0 }: {
  query: string; label: string; unit?: string; max?: number; hue?: number;
}) {
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(900);
    return api.metricsQueryRange(query, s, e, st);
  });
  const series = res?.data?.result ?? [];
  const points = series[0]?.values ?? [];
  const v = res ? latestFromProm(res) : null;
  const prev = points.length > 3 ? Number(points[Math.max(0, points.length - 4)][1]) : null;
  const delta = v !== null && prev !== null && isFinite(prev) ? v - prev : null;
  const color = DEMO_SERIES[hue % DEMO_SERIES.length];
  const pct = v === null ? 0 : Math.min(1, Math.max(0, v / max));
  // Spark of the same series under the number — motion without a second panel.
  const spark = points.slice(-40).map((p) => Number(p[1]) || 0);

  return (
    <div className="demo-gauge">
      <Chart
        height={132}
        err={err && !res ? err : undefined}
        option={{
          ...base,
          tooltip: { show: false },
          series: [
            // faint outer scale ladder
            {
              type: "gauge", min: 0, max, center: ["50%", "62%"], radius: "104%",
              startAngle: 214, endAngle: -34, pointer: { show: false }, detail: { show: false },
              progress: { show: false }, title: { show: false }, anchor: { show: false },
              axisLine: { lineStyle: { width: 2, color: [[1, "rgba(148,163,184,0.18)"]] } },
              splitLine: { distance: -6, length: 6, lineStyle: { color: "rgba(148,163,184,0.28)", width: 1 } },
              axisTick: { distance: -3, splitNumber: 4, length: 3, lineStyle: { color: "rgba(148,163,184,0.18)", width: 1 } },
              axisLabel: { show: false },
            },
            // the segmented value arc — the "pattern"
            {
              type: "gauge", min: 0, max, center: ["50%", "62%"], radius: "88%",
              startAngle: 214, endAngle: -34, pointer: { show: false },
              splitLine: { show: false }, axisTick: { show: false }, axisLabel: { show: false },
              anchor: { show: false }, title: { show: false },
              axisLine: {
                lineStyle: {
                  width: 13,
                  color: [[1, "rgba(148,163,184,0.10)"]],
                },
              },
              progress: {
                show: true, width: 13, roundCap: false,
                itemStyle: {
                  shadowBlur: 18, shadowColor: hexToRgba(color, 0.55),
                  color: {
                    type: "linear", x: 0, y: 0, x2: 1, y2: 1,
                    colorStops: [
                      { offset: 0, color: hexToRgba(color, 0.55) },
                      { offset: 1, color },
                    ],
                  },
                  // discrete ticks: a dashed border along the arc gives it grain
                  borderColor: "rgba(10,14,26,0.85)", borderWidth: 1.4, borderType: [3, 3] as unknown as string,
                },
              },
              detail: {
                valueAnimation: true, offsetCenter: [0, "6%"],
                formatter: v === null ? "—" : `{v|${v >= 100 ? Math.round(v) : v.toFixed(v < 10 ? 1 : 0)}}{u|${unit}}`,
                rich: {
                  v: { fontSize: 30, fontWeight: 800, color: INK, fontFamily: "Space Grotesk, inherit" },
                  u: { fontSize: 13, color: INK_DIM, padding: [0, 0, 5, 2] },
                },
              },
              data: [{ value: v ?? 0 }],
            },
          ],
        }}
      />
      <div className="demo-gauge-foot">
        <span className="demo-gauge-label">{label}</span>
        {delta !== null && Math.abs(delta) > 0.05 && (
          <span className={`demo-delta ${delta > 0 ? "up" : "down"}`}>
            {delta > 0 ? "▲" : "▼"} {Math.abs(delta).toFixed(1)}
          </span>
        )}
      </div>
      {spark.length > 4 && (
        <svg className="demo-gauge-spark" viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden>
          <polyline
            points={spark.map((y, i) => {
              const mn = Math.min(...spark), mx = Math.max(...spark);
              const ny = mx === mn ? 8 : 15 - ((y - mn) / (mx - mn)) * 14;
              return `${(i / (spark.length - 1)) * 100},${ny}`;
            }).join(" ")}
            fill="none" stroke={color} strokeWidth={1.2} opacity={0.85}
          />
        </svg>
      )}
      <span className="demo-gauge-pct" style={{ width: `${pct * 100}%`, background: color }} />
    </div>
  );
}

// ── 2. Ridgeline (joyplot) ──────────────────────────────────────────────────
// A stack of overlapping density curves — one per device — so a whole fleet's
// CPU distribution reads as terrain. This is the 2026 replacement for "N line
// charts stacked vertically": it uses the same vertical space for 6× the series.
export function Ridgeline({ query, height = 250, topN = 6 }: {
  query: string; height?: number; topN?: number;
}) {
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(3600, 60);
    return api.metricsQueryRange(query, s, e, st);
  });
  const rows = useMemo(() => {
    const series = res?.data?.result ?? [];
    return series
      .map((s) => ({
        name: seriesLabel(s.metric),
        vals: (s.values ?? []).map((v) => Number(v[1]) || 0),
      }))
      .filter((r) => r.vals.length > 2)
      .sort((a, b) => Math.max(...b.vals) - Math.max(...a.vals))
      .slice(0, topN);
  }, [res, topN]);

  const lane = rows.length ? Math.max(26, (height - 26) / rows.length) : 0;
  const option = {
    ...base,
    grid: { left: 92, right: 14, top: 8, bottom: 20 },
    xAxis: { type: "category", show: false, data: rows[0]?.vals.map((_, i) => i) ?? [], boundaryGap: false },
    yAxis: { type: "value", show: false, max: rows.length * lane },
    series: rows.map((r, i) => {
      const c = DEMO_SERIES[i % DEMO_SERIES.length];
      const off = (rows.length - 1 - i) * lane;
      const mx = Math.max(...r.vals, 1);
      return {
        type: "line", smooth: 0.55, symbol: "none", name: r.name,
        lineStyle: { width: 1.6, color: c },
        areaStyle: {
          origin: off,
          color: {
            type: "linear", x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [{ offset: 0, color: hexToRgba(c, 0.62) }, { offset: 1, color: hexToRgba(c, 0.02) }],
          },
        },
        data: r.vals.map((v) => off + (v / mx) * (lane * 0.92)),
        z: 10 + i,
        markLine: {
          silent: true, symbol: "none",
          lineStyle: { color: "rgba(148,163,184,0.15)", width: 1 },
          data: [{ yAxis: off }],
          label: {
            show: true, position: "start", formatter: r.name, color: INK_DIM,
            fontSize: 10, padding: [0, 8, 0, 0],
          },
        },
      };
    }),
  };
  return <Chart height={height} option={option} err={err && !res ? err : undefined} empty={rows.length === 0} />;
}

// ── 3. Activity heatmap ─────────────────────────────────────────────────────
// Device × time-bucket matrix, sequential single-hue ramp. This is the panel
// that makes a screenshot feel like "a lot is happening" — hundreds of cells,
// all real.
export function ActivityHeatmap({ query, height = 236, topN = 12 }: {
  query: string; height?: number; topN?: number;
}) {
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(3600, 120);
    return api.metricsQueryRange(query, s, e, st);
  });
  const { rows, cells, buckets, max } = useMemo(() => {
    const series = (res?.data?.result ?? [])
      .map((s) => ({ name: seriesLabel(s.metric), vals: (s.values ?? []).map((v) => Number(v[1]) || 0) }))
      .filter((r) => r.vals.length > 1)
      .sort((a, b) => Math.max(...b.vals) - Math.max(...a.vals))
      .slice(0, topN);
    const nb = Math.min(30, Math.max(...series.map((s) => s.vals.length), 0));
    const out: [number, number, number][] = [];
    let mx = 0;
    series.forEach((s, ri) => {
      const step = Math.max(1, Math.floor(s.vals.length / nb));
      for (let b = 0; b < nb; b++) {
        const v = s.vals[Math.min(s.vals.length - 1, b * step)] ?? 0;
        mx = Math.max(mx, v);
        out.push([b, ri, Math.round(v * 10) / 10]);
      }
    });
    return { rows: series.map((s) => s.name), cells: out, buckets: nb, max: mx || 1 };
  }, [res, topN]);

  const option = {
    ...base,
    tooltip: { ...base.tooltip, trigger: "item", formatter: (p: { data: [number, number, number] }) => `${escapeHtml(rows[p.data[1]])}<br/>${p.data[2]}` },
    grid: { left: 96, right: 40, top: 6, bottom: 18 },
    xAxis: { type: "category", data: Array.from({ length: buckets }, (_, i) => i), show: false },
    yAxis: { type: "category", data: rows, ...axis, splitLine: { show: false }, axisLabel: { ...axis.axisLabel, fontSize: 9.5 } },
    visualMap: {
      min: 0, max, calculable: false, orient: "vertical", right: 0, top: "middle",
      itemWidth: 8, itemHeight: 96, inRange: { color: RAMP },
      textStyle: { color: INK_DIM, fontSize: 9 },
    },
    series: [{
      type: "heatmap", data: cells,
      itemStyle: { borderColor: "rgba(10,14,26,0.9)", borderWidth: 1.5, borderRadius: 2 },
      emphasis: { itemStyle: { borderColor: INK, borderWidth: 1 } },
      progressive: 400,
    }],
  };
  return <Chart height={height} option={option} err={err && !res ? err : undefined} empty={rows.length === 0} />;
}

// ── 4. Stacked histogram (distribution) ─────────────────────────────────────
// A true histogram: bucket the current values across the fleet and stack them
// by severity band. Answers "how is the fleet distributed", which a top-N bar
// list cannot.
export function DistributionHistogram({ query, height = 210, bucketSize = 10 }: {
  query: string; height?: number; bucketSize?: number;
}) {
  const { data: res, err } = usePolled(() => api.metricsQuery(query));
  const { labels, bands } = useMemo(() => {
    const vals = (res?.data?.result ?? []).map((r) => Number(r.value?.[1]) || 0);
    const nb = Math.ceil(100 / bucketSize);
    const ok = new Array(nb).fill(0), warn = new Array(nb).fill(0), crit = new Array(nb).fill(0);
    for (const v of vals) {
      const i = Math.min(nb - 1, Math.max(0, Math.floor(v / bucketSize)));
      const pct = i * bucketSize;
      if (pct >= 85) crit[i]++;
      else if (pct >= 65) warn[i]++;
      else ok[i]++;
    }
    return {
      labels: Array.from({ length: nb }, (_, i) => `${i * bucketSize}`),
      bands: [
        { name: "Healthy", data: ok, color: "#059669" },
        { name: "Elevated", data: warn, color: "#d97706" },
        { name: "Saturated", data: crit, color: "#f43f5e" },
      ],
    };
  }, [res, bucketSize]);
  const total = bands.reduce((a, b) => a + b.data.reduce((x: number, y: number) => x + y, 0), 0);

  const option = {
    ...base,
    legend: { show: true, top: 0, right: 0, textStyle: { color: INK_DIM, fontSize: 10 }, itemWidth: 8, itemHeight: 8, icon: "roundRect" },
    grid: { left: 34, right: 8, top: 26, bottom: 24 },
    xAxis: { type: "category", data: labels, ...axis, splitLine: { show: false }, name: "% util", nameTextStyle: { color: INK_DIM, fontSize: 9 }, nameLocation: "end", nameGap: 4 },
    yAxis: { type: "value", ...axis, minInterval: 1 },
    series: bands.map((b, i) => ({
      type: "bar", stack: "d", name: b.name, data: b.data,
      barMaxWidth: 26,
      itemStyle: {
        color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: b.color }, { offset: 1, color: hexToRgba(b.color, 0.45) }] },
        borderRadius: i === bands.length - 1 ? [3, 3, 0, 0] : 0,
        borderColor: "rgba(10,14,26,0.9)", borderWidth: 1.5,
      },
    })),
  };
  return <Chart height={height} option={option} err={err && !res ? err : undefined} empty={total === 0} />;
}

// ── 5. Racing bars (top-N with motion) ──────────────────────────────────────
// Ranked horizontal bars that re-sort as values change, with the value printed
// on the bar. Dense and kinetic — the "something is happening" panel.
export function RacingBars({ query, height = 226, n = 8, unit = "%", fmt }: {
  query: string; height?: number; n?: number; unit?: string; fmt?: (v: number) => string;
}) {
  const { data: res, err } = usePolled(() => api.metricsQuery(query));
  const rows = useMemo(() => {
    return (res?.data?.result ?? [])
      .map((r) => ({ name: seriesLabel(r.metric), v: Number(r.value?.[1]) || 0 }))
      .sort((a, b) => b.v - a.v)
      .slice(0, n)
      .reverse();
  }, [res, n]);
  const max = Math.max(...rows.map((r) => r.v), 1);

  const option = {
    ...base,
    grid: { left: 118, right: 54, top: 4, bottom: 4 },
    xAxis: { type: "value", show: false, max: max * 1.12 },
    yAxis: {
      type: "category", data: rows.map((r) => r.name), ...axis,
      splitLine: { show: false }, axisLine: { show: false },
      axisLabel: { ...axis.axisLabel, fontSize: 10, width: 112, overflow: "truncate" },
    },
    series: [
      // ghost track behind each bar — gives the row structure at a glance
      {
        type: "bar", data: rows.map(() => max * 1.12), barWidth: 13, silent: true,
        itemStyle: { color: "rgba(148,163,184,0.08)", borderRadius: 3 }, barGap: "-100%", z: 1,
      },
      {
        type: "bar", data: rows.map((r) => r.v), barWidth: 13, z: 2,
        itemStyle: {
          borderRadius: 3,
          color: (p: { dataIndex: number }) => {
            const v = rows[p.dataIndex].v;
            const c = v / max > 0.85 ? "#f43f5e" : v / max > 0.6 ? "#d97706" : DEMO_SERIES[p.dataIndex % DEMO_SERIES.length];
            return { type: "linear", x: 0, y: 0, x2: 1, y2: 0, colorStops: [{ offset: 0, color: hexToRgba(c, 0.35) }, { offset: 1, color: c }] };
          },
        },
        label: {
          show: true, position: "right", color: INK, fontSize: 10.5, fontWeight: 600,
          formatter: (p: { dataIndex: number }) => (fmt ? fmt(rows[p.dataIndex].v) : `${rows[p.dataIndex].v.toFixed(1)}${unit}`),
        },
      },
    ],
  };
  return <Chart height={height} option={option} err={err && !res ? err : undefined} empty={rows.length === 0} />;
}

// ── 6. Stream graph (flows over time) ───────────────────────────────────────
export function StreamGraph({ height = 226 }: { height?: number }) {
  const [rows, setRows] = useState<{ t: string; series: Record<string, number> }[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [ts, proto] = await Promise.all([
          api.flowsTimeseries({ since: "3600", step: "120" } as never),
          api.flowsByProto({ since: "3600" } as never),
        ]);
        if (!alive) return;
        const protos = (proto.data ?? []).slice(0, 5).map((p: Record<string, unknown>) => String(p.proto ?? "other"));
        const total = (proto.data ?? []).reduce((a: number, p: Record<string, unknown>) => a + Number(p.bytes_total ?? 0), 0) || 1;
        const share = (proto.data ?? []).slice(0, 5).map((p: Record<string, unknown>) => Number(p.bytes_total ?? 0) / total);
        // Distribute each time bucket's real total across the observed protocol
        // mix — the mix and the totals are both live; only the per-bucket split
        // is apportioned (the flow store keeps them in separate aggregates).
        setRows((ts.data ?? []).map((b: Record<string, unknown>) => {
          const bytes = Number(b.bytes_total ?? 0);
          const series: Record<string, number> = {};
          protos.forEach((p, i) => { series[p] = bytes * (share[i] ?? 0); });
          return { t: String(b.bucket ?? ""), series };
        }));
        setErr(null);
      } catch (e) {
        if (alive) setErr(e);
      }
    };
    void load();
    const iv = setInterval(load, 20000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  const names = rows?.length ? Object.keys(rows[0].series) : [];
  const option = {
    ...base,
    legend: { show: true, top: 0, right: 0, textStyle: { color: INK_DIM, fontSize: 10 }, itemWidth: 8, itemHeight: 8, icon: "roundRect" },
    grid: { left: 46, right: 10, top: 26, bottom: 22 },
    xAxis: { type: "category", data: rows?.map((r) => r.t.slice(11, 16)) ?? [], ...axis, splitLine: { show: false }, boundaryGap: false },
    yAxis: { type: "value", ...axis, axisLabel: { ...axis.axisLabel, formatter: (v: number) => (v > 1e9 ? `${(v / 1e9).toFixed(0)}G` : v > 1e6 ? `${(v / 1e6).toFixed(0)}M` : `${v}`) } },
    series: names.map((n, i) => ({
      type: "line", name: n, stack: "f", smooth: 0.5, symbol: "none",
      lineStyle: { width: 0 },
      areaStyle: {
        color: {
          type: "linear", x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: hexToRgba(DEMO_SERIES[i % DEMO_SERIES.length], 0.9) },
            { offset: 1, color: hexToRgba(DEMO_SERIES[i % DEMO_SERIES.length], 0.35) },
          ],
        },
      },
      data: rows?.map((r) => Math.round(r.series[n] ?? 0)) ?? [],
    })),
  };
  return <Chart height={height} option={option} err={err && !rows ? err : undefined} empty={!rows || rows.length === 0} />;
}

// ── 7. Live event ticker ────────────────────────────────────────────────────
// A scrolling feed of real change events. Motion + "the platform is watching".
export function EventTicker({ height = 226 }: { height?: number }) {
  const [items, setItems] = useState<{ ts: string; title: string; sev: string; src: string }[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await api.eventsFeed({ from: "24h", limit: "40" });
        if (!alive) return;
        setItems((r.items ?? []).map((i) => ({
          ts: String(i.ts ?? "").slice(11, 19), title: i.title, sev: i.severity, src: i.source,
        })));
        setErr(null);
      } catch (e) {
        if (alive) setErr(e);
      }
    };
    void load();
    const iv = setInterval(load, 15000);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  const tone = (s: string) => (s === "crit" ? "#f43f5e" : s === "high" ? "#d97706" : s === "warn" ? "#a855f7" : "#0284c7");
  if (err && !items) return <div className="fact-line" style={DEMO_STATE_BAD}>Feed unavailable.</div>;
  if (!items) return <div className="fact-line" style={DEMO_STATE}>Waiting for events…</div>;
  if (items.length === 0) return <div className="fact-line" style={DEMO_STATE}>No events in the window.</div>;
  return (
    <div className="demo-ticker" style={{ height }} ref={ref}>
      <div className="demo-ticker-track">
        {[...items, ...items].map((it, i) => (
          <div className="demo-ticker-row" key={i}>
            <span className="demo-ticker-dot" style={{ background: tone(it.sev) }} />
            <span className="demo-ticker-ts">{it.ts}</span>
            <span className="demo-ticker-title">{it.title}</span>
            <span className="demo-ticker-src">{it.src}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 8. Big stat with sparkline ──────────────────────────────────────────────
export function BigStat({ query, label, unit = "", fmt, hue = 0, invert = false }: {
  query: string; label: string; unit?: string; fmt?: (v: number) => string; hue?: number; invert?: boolean;
}) {
  const { data: res, err } = usePolled(() => {
    const [s, e, st] = nowWindow(1800, 30);
    return api.metricsQueryRange(query, s, e, st);
  });
  const pts = (res?.data?.result?.[0]?.values ?? []).map((v) => Number(v[1]) || 0);
  const v = res ? latestFromProm(res) : null;
  const first = pts.length ? pts[0] : null;
  const delta = v !== null && first !== null && first !== 0 ? ((v - first) / Math.abs(first)) * 100 : null;
  const color = DEMO_SERIES[hue % DEMO_SERIES.length];
  const good = delta === null ? true : invert ? delta <= 0 : delta >= 0;

  return (
    <div className="demo-stat">
      <div className="demo-stat-label">{label}</div>
      <div className="demo-stat-value" style={{ color: INK }}>
        {err && !res ? "—" : v === null ? "—" : fmt ? fmt(v) : `${Math.round(v)}`}
        <span className="demo-stat-unit">{unit}</span>
      </div>
      {delta !== null && Math.abs(delta) >= 0.5 && (
        <div className={`demo-stat-delta ${good ? "good" : "bad"}`}>
          {delta > 0 ? "▲" : "▼"} {Math.abs(delta).toFixed(1)}% <span>30m</span>
        </div>
      )}
      {pts.length > 3 && (
        <svg className="demo-stat-spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden>
          <defs>
            <linearGradient id={`g-${label.replace(/\W/g, "")}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.55" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          {(() => {
            const mn = Math.min(...pts), mx = Math.max(...pts);
            const pt = (y: number, i: number) => `${(i / (pts.length - 1)) * 100},${mx === mn ? 14 : 26 - ((y - mn) / (mx - mn)) * 24}`;
            const line = pts.map(pt).join(" ");
            return (
              <>
                <polygon points={`0,28 ${line} 100,28`} fill={`url(#g-${label.replace(/\W/g, "")})`} />
                <polyline points={line} fill="none" stroke={color} strokeWidth={1.5} />
              </>
            );
          })()}
        </svg>
      )}
    </div>
  );
}
