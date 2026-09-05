// Icon.geometry.test.ts — geometric guard for the left navigation rail glyphs.
//
// WHY: the rail (`.shell-v2 .rail`) centres a 34px key on the pane and a
// 19px <svg> inside that key, so the ONLY thing that can make the icon column
// look ragged or off-centre is the glyph itself sitting off-centre inside its
// own 24x24 viewBox. That is invisible in review (every glyph "looks fine" on
// its own) and only shows up as a crooked rail. The 2026-09-03 geometry audit
// found three glyphs authored against the top of the box (monitoring -2,
// datasets -1, copilot -1 in y); this test pins the fix so it cannot drift.
//
// The assertion is BOUNDING-BOX centring, which is what the icon families we
// draw from (Feather / Lucide) use. Ink-weight ("optical") centring is
// deliberately NOT asserted: an L-shaped chart glyph like `analytics` has its
// ink mass to the left by construction, and nudging it would break the box
// alignment every other glyph relies on.
//
// The parser below samples every drawing primitive into points and inflates by
// half the stroke width (round caps/joins extend the painted edge by sw/2 in
// every direction), so the box measured here is the box the operator sees.

import { describe, it, expect } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import Icon from "./Icon";

// The glyphs IconRail actually renders: one per nav section (nav.tsx `icon`)
// plus the three foot-cluster utilities. Keep in sync with nav.tsx / IconRail.
const RAIL_GLYPHS = [
  "overview", // Overview
  "monitoring", // Operations
  "explore", // Investigate
  "infrastructure", // Infrastructure
  "datasets", // Explore
  "shield", // Security
  "analytics", // Analytics
  "copilot", // Iris AI
  "sliders", // Administration
  "support", // foot: Support
  "help", // foot: Documentation
  "chevron", // foot: expand/collapse toggle
];

// `.shell-v2 .rail-icon svg { stroke-width: 2 }` — the rail overrides the
// component's 1.75 default, so the rail's painted box uses 2.
const RAIL_STROKE_WIDTH = 2;
const VIEWBOX = 24;
const CENTRE = VIEWBOX / 2;
// Half a device pixel at the rendered 19px is ~0.63 viewBox units; anything
// under 0.25 units is far below perceivable and leaves room for deliberate
// sub-unit optical tuning without failing the build.
const TOLERANCE = 0.25;

type Pt = [number, number];

const NUM = /[-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?/g;
const nums = (s: string): number[] => (s.match(NUM) ?? []).map(Number);

function cubic(p0: Pt, p1: Pt, p2: Pt, p3: Pt, out: Pt[], n = 32): void {
  for (let i = 1; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    out.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
}

function quad(p0: Pt, p1: Pt, p2: Pt, out: Pt[], n = 24): void {
  for (let i = 1; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    out.push([
      u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
      u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
    ]);
  }
}

// SVG endpoint-parameterised elliptical arc -> sampled points. Every arc in
// this icon set is axis-aligned (x-axis-rotation 0), which the unrotated form
// below covers exactly.
function arc(p0: Pt, rxIn: number, ryIn: number, large: number, sweep: number, p1: Pt, out: Pt[], n = 48): void {
  const [x0, y0] = p0;
  const [x1, y1] = p1;
  if (rxIn === 0 || ryIn === 0) {
    out.push(p1);
    return;
  }
  let rx = Math.abs(rxIn);
  let ry = Math.abs(ryIn);
  const x1p = (x0 - x1) / 2;
  const y1p = (y0 - y1) / 2;
  const lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
  if (lam > 1) {
    const s = Math.sqrt(lam);
    rx *= s;
    ry *= s;
  }
  const den = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
  const num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p;
  let co = den === 0 ? 0 : Math.sqrt(Math.max(num, 0) / den);
  if (large === sweep) co = -co;
  const cx = (co * rx * y1p) / ry + (x0 + x1) / 2;
  const cy = (-co * ry * x1p) / rx + (y0 + y1) / 2;
  const ang = (ux: number, uy: number, vx: number, vy: number): number => {
    const d = (ux * vx + uy * vy) / (Math.hypot(ux, uy) * Math.hypot(vx, vy));
    const a = Math.acos(Math.min(1, Math.max(-1, d)));
    return ux * vy - uy * vx < 0 ? -a : a;
  };
  const ux = (x1p - (cx - (x0 + x1) / 2)) / rx;
  const uy = (y1p - (cy - (y0 + y1) / 2)) / ry;
  const vx = (-x1p - (cx - (x0 + x1) / 2)) / rx;
  const vy = (-y1p - (cy - (y0 + y1) / 2)) / ry;
  const th1 = ang(1, 0, ux, uy);
  let dth = ang(ux, uy, vx, vy);
  if (!sweep && dth > 0) dth -= 2 * Math.PI;
  else if (sweep && dth < 0) dth += 2 * Math.PI;
  for (let i = 1; i <= n; i++) {
    const t = th1 + (dth * i) / n;
    out.push([cx + rx * Math.cos(t), cy + ry * Math.sin(t)]);
  }
}

const SEG = /([MmLlHhVvCcSsQqTtAaZz])([^MmLlHhVvCcSsQqTtAaZz]*)/g;

export function samplePath(d: string): Pt[] {
  const out: Pt[] = [];
  let x = 0;
  let y = 0;
  let sx = 0;
  let sy = 0;
  let prevC2: Pt | null = null;
  let prevQ1: Pt | null = null;
  let last = "";
  for (const m of d.matchAll(SEG)) {
    const raw = m[1];
    const rel = raw === raw.toLowerCase();
    let cmd = raw.toUpperCase();
    const a = nums(m[2]);
    if (cmd === "Z") {
      out.push([sx, sy]);
      x = sx;
      y = sy;
      last = cmd;
      continue;
    }
    let i = 0;
    let first = true;
    while (i < a.length) {
      if (cmd === "M") {
        let px = a[i++];
        let py = a[i++];
        if (rel) {
          px += x;
          py += y;
        }
        out.push([px, py]);
        if (first) {
          sx = px;
          sy = py;
          first = false;
        }
        x = px;
        y = py;
        cmd = "L"; // implicit lineto for repeated pairs
      } else if (cmd === "L") {
        let px = a[i++];
        let py = a[i++];
        if (rel) {
          px += x;
          py += y;
        }
        out.push([px, py]);
        x = px;
        y = py;
      } else if (cmd === "H") {
        let px = a[i++];
        if (rel) px += x;
        out.push([px, y]);
        x = px;
      } else if (cmd === "V") {
        let py = a[i++];
        if (rel) py += y;
        out.push([x, py]);
        y = py;
      } else if (cmd === "C") {
        const v = a.slice(i, i + 6);
        i += 6;
        const p1: Pt = rel ? [v[0] + x, v[1] + y] : [v[0], v[1]];
        const p2: Pt = rel ? [v[2] + x, v[3] + y] : [v[2], v[3]];
        const p3: Pt = rel ? [v[4] + x, v[5] + y] : [v[4], v[5]];
        cubic([x, y], p1, p2, p3, out);
        prevC2 = p2;
        [x, y] = p3;
      } else if (cmd === "S") {
        const v = a.slice(i, i + 4);
        i += 4;
        const p2: Pt = rel ? [v[0] + x, v[1] + y] : [v[0], v[1]];
        const p3: Pt = rel ? [v[2] + x, v[3] + y] : [v[2], v[3]];
        const p1: Pt =
          (last === "C" || last === "S") && prevC2 ? [2 * x - prevC2[0], 2 * y - prevC2[1]] : [x, y];
        cubic([x, y], p1, p2, p3, out);
        prevC2 = p2;
        [x, y] = p3;
      } else if (cmd === "Q") {
        const v = a.slice(i, i + 4);
        i += 4;
        const p1: Pt = rel ? [v[0] + x, v[1] + y] : [v[0], v[1]];
        const p2: Pt = rel ? [v[2] + x, v[3] + y] : [v[2], v[3]];
        quad([x, y], p1, p2, out);
        prevQ1 = p1;
        [x, y] = p2;
      } else if (cmd === "T") {
        const v = a.slice(i, i + 2);
        i += 2;
        const p2: Pt = rel ? [v[0] + x, v[1] + y] : [v[0], v[1]];
        const p1: Pt =
          (last === "Q" || last === "T") && prevQ1 ? [2 * x - prevQ1[0], 2 * y - prevQ1[1]] : [x, y];
        quad([x, y], p1, p2, out);
        prevQ1 = p1;
        [x, y] = p2;
      } else if (cmd === "A") {
        const v = a.slice(i, i + 7);
        i += 7;
        const end: Pt = rel ? [v[5] + x, v[6] + y] : [v[5], v[6]];
        arc([x, y], v[0], v[1], v[3], v[4], end, out);
        [x, y] = end;
      } else {
        break;
      }
    }
    last = raw.toUpperCase();
  }
  return out;
}

function ellipsePts(cx: number, cy: number, rx: number, ry: number, out: Pt[], n = 64): void {
  for (let k = 0; k <= n; k++) {
    const t = (2 * Math.PI * k) / n;
    out.push([cx + rx * Math.cos(t), cy + ry * Math.sin(t)]);
  }
}

const attr = (tag: string, name: string): number | undefined => {
  const m = tag.match(new RegExp(`\\b${name}="([-\\d.eE+]+)"`));
  return m ? Number(m[1]) : undefined;
};
const req = (tag: string, name: string): number => {
  const v = attr(tag, name);
  if (v === undefined) throw new Error(`missing ${name} on ${tag}`);
  return v;
};

/** Sample every drawing primitive in an SVG markup string into points. */
export function samplePrimitives(markup: string): Pt[] {
  const pts: Pt[] = [];
  for (const m of markup.matchAll(/<(path|circle|ellipse|rect|line|polyline|polygon)\b([^>]*)>/g)) {
    const kind = m[1];
    const tag = m[2];
    if (kind === "path") {
      const d = tag.match(/\bd="([^"]*)"/);
      if (d) pts.push(...samplePath(d[1]));
    } else if (kind === "circle") {
      const r = req(tag, "r");
      ellipsePts(attr(tag, "cx") ?? 0, attr(tag, "cy") ?? 0, r, r, pts);
    } else if (kind === "ellipse") {
      ellipsePts(attr(tag, "cx") ?? 0, attr(tag, "cy") ?? 0, req(tag, "rx"), req(tag, "ry"), pts);
    } else if (kind === "rect") {
      // Corner radius only rounds the corners INSIDE the rect, so the extreme
      // edges are the rect's own — the plain box bounds it exactly.
      const x = attr(tag, "x") ?? 0;
      const y = attr(tag, "y") ?? 0;
      const w = req(tag, "width");
      const h = req(tag, "height");
      pts.push([x, y], [x + w, y], [x + w, y + h], [x, y + h]);
    } else if (kind === "line") {
      pts.push([req(tag, "x1"), req(tag, "y1")], [req(tag, "x2"), req(tag, "y2")]);
    } else {
      const p = nums(tag.match(/\bpoints="([^"]*)"/)?.[1] ?? "");
      for (let i = 0; i + 1 < p.length; i += 2) pts.push([p[i], p[i + 1]]);
    }
  }
  return pts;
}

type Box = { minX: number; minY: number; maxX: number; maxY: number; cx: number; cy: number };

/** Painted bounding box of a named glyph, inflated by half the stroke width. */
export function glyphBox(name: string, strokeWidth = RAIL_STROKE_WIDTH): Box {
  const markup = renderToStaticMarkup(createElement(Icon, { name }));
  const pts = samplePrimitives(markup);
  expect(pts.length, `glyph "${name}" produced no geometry`).toBeGreaterThan(0);
  const half = strokeWidth / 2;
  const xs = pts.map((p) => p[0]);
  const ys = pts.map((p) => p[1]);
  const minX = Math.min(...xs) - half;
  const maxX = Math.max(...xs) + half;
  const minY = Math.min(...ys) - half;
  const maxY = Math.max(...ys) + half;
  return { minX, minY, maxX, maxY, cx: (minX + maxX) / 2, cy: (minY + maxY) / 2 };
}

describe("rail glyph geometry", () => {
  it("parses a known glyph correctly (parser self-check)", () => {
    // `overview` is four rects spanning x 3..21, y 3..21; +1 each side for the
    // 2-wide stroke gives exactly 2..22.
    const b = glyphBox("overview");
    expect(b.minX).toBeCloseTo(2, 6);
    expect(b.maxX).toBeCloseTo(22, 6);
    expect(b.minY).toBeCloseTo(2, 6);
    expect(b.maxY).toBeCloseTo(22, 6);
  });

  it.each(RAIL_GLYPHS)("%s is horizontally centred in the 24x24 viewBox", (name) => {
    const b = glyphBox(name);
    const dx = b.cx - CENTRE;
    expect(
      Math.abs(dx),
      `glyph "${name}" bbox x-centre is ${b.cx.toFixed(3)} (dx ${dx.toFixed(3)}); ` +
        `left margin ${b.minX.toFixed(3)}, right margin ${(VIEWBOX - b.maxX).toFixed(3)}`,
    ).toBeLessThanOrEqual(TOLERANCE);
  });

  it.each(RAIL_GLYPHS)("%s is vertically centred in the 24x24 viewBox", (name) => {
    const b = glyphBox(name);
    const dy = b.cy - CENTRE;
    expect(
      Math.abs(dy),
      `glyph "${name}" bbox y-centre is ${b.cy.toFixed(3)} (dy ${dy.toFixed(3)}); ` +
        `top margin ${b.minY.toFixed(3)}, bottom margin ${(VIEWBOX - b.maxY).toFixed(3)}`,
    ).toBeLessThanOrEqual(TOLERANCE);
  });

  it.each(RAIL_GLYPHS)("%s stays inside the viewBox at the rail's stroke width", (name) => {
    const b = glyphBox(name);
    expect(b.minX, `${name} overflows left`).toBeGreaterThanOrEqual(-0.001);
    expect(b.minY, `${name} overflows top`).toBeGreaterThanOrEqual(-0.001);
    expect(b.maxX, `${name} overflows right`).toBeLessThanOrEqual(VIEWBOX + 0.001);
    expect(b.maxY, `${name} overflows bottom`).toBeLessThanOrEqual(VIEWBOX + 0.001);
  });
});
