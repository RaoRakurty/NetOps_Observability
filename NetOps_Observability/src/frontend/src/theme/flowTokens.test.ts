// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowTokens.test.ts — the flow views' colours live in ONE token file
// (theme/flows-tokens.css) with a light and a dark value, and the values hold
// up (owner, 2026-11-12: "elegant and modern … for both dark and light themes").
//
//   1. no flow component, and no rule in the Flows CSS block, carries a literal
//      colour — every colour is a token;
//   2. text-bearing tokens reach 4.5:1 on the surface of every theme;
//   3. in and out stay apart for normal vision and the three common
//      colour-vision deficiencies; the categorical hues stay apart for normal,
//      deutan and protan vision;
//   4. the utilisation ramp is sequential (it darkens toward load on light,
//      brightens on dark) and its bands are distinct from the ramp.

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "../lib/copyScan";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(SRC, rel), "utf8");

// ── 1. no literal colour outside the token file ──────────────────────────────

const COMPONENT_FILES = [
  "tabs/Flows.tsx",
  ...readdirSync(join(SRC, "tabs/flows")).filter((f) => /\.tsx?$/.test(f) && !f.includes(".test.")).map((f) => `tabs/flows/${f}`),
  "tabs/flowEmpty.tsx",
  "tabs/flowNames.ts",
  "tabs/flowsAppViews.ts",
  "components/logs/FlowRowParts.tsx",
  "theme/flowTokens.ts",
  "lib/flowsLink.ts",
  "lib/ifUtilisation.ts",
  "lib/refreshTick.ts",
];
const LITERAL = /#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3}(?:[0-9a-fA-F]{2})?)?\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklch|oklab)\(/g;

function literals(text: string, rel: string): string[] {
  const hits: string[] = [];
  stripComments(text).split("\n").forEach((line, i) => {
    for (const m of line.match(LITERAL) ?? []) hits.push(`${rel}:${i + 1} ${m}  ${line.trim().slice(0, 90)}`);
  });
  return hits;
}

/** The CSS between the markers, comments removed. */
function cssBlock(text: string, begin: string, end: string): string {
  const a = text.indexOf(begin);
  const b = text.indexOf(end, a);
  if (a < 0 || b < 0) throw new Error(`markers ${begin} … ${end} not found`);
  return text.slice(a, b).replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, " "));
}

describe("flow colours come only from theme/flows-tokens.css", () => {
  it("no flow component names a literal colour", () => {
    const hits = COMPONENT_FILES.flatMap((rel) => literals(read(rel), rel));
    expect(hits, `Use a --flow-* token (theme/flows-tokens.css) via CSS or theme/flowTokens.ts:\n${hits.join("\n")}`).toEqual([]);
  });

  it("the Flows CSS block and the Logs flow-row rules name no literal colour", () => {
    const css = read("styles.css");
    const flows = cssBlock(css, "FLOWS-CSS-BEGIN", "FLOWS-CSS-END");
    const flRules = css.split("\n").filter((l) => /^\.fl-|^\s+(background|color|border)[^;]*;/.test(l) && /\.fl-/.test(l)).join("\n");
    const hits = [...literals(flows, "styles.css#flows"), ...literals(flRules, "styles.css#fl-")];
    expect(hits, hits.join("\n")).toEqual([]);
    // The block really is the page's CSS (a guard aimed at nothing passes forever).
    expect(flows).toContain(".flows-page .tr-meter.crit");
    expect(flRules).toContain("var(--flow-src)");
  });

  it("the guard catches the shapes it forbids", () => {
    expect(literals('const c = "#1f2937"; x(rgba(0,0,0,.2)); hsl(1 2 3)', "x").length).toBe(3);
    expect(literals("color: hsl(210 40% 50%)", "x").length).toBe(1);
    expect(literals('href="#/explore/flows" // #fff in a comment', "x")).toEqual([]);
  });
});

// ── token values ─────────────────────────────────────────────────────────────

type Theme = "light" | "dark";
function tokenBlocks(): Record<Theme, Record<string, string>> {
  const css = read("theme/flows-tokens.css").replace(/\/\*[\s\S]*?\*\//g, "");
  const blocks = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)];
  const out: Record<Theme, Record<string, string>> = { light: {}, dark: {} };
  for (const [, sel, body] of blocks) {
    const theme: Theme = sel.includes('data-theme="dark"') ? "dark" : "light";
    for (const [, k, v] of body.matchAll(/(--flow-[\w-]+)\s*:\s*([^;]+);/g)) out[theme][k] = v.trim();
  }
  for (const t of ["light", "dark"] as Theme[]) {
    for (const k of Object.keys(out[t])) {
      const alias = /^var\((--flow-[\w-]+)\)$/.exec(out[t][k]);
      if (alias) out[t][k] = out[t][alias[1]] ?? out.light[alias[1]];
    }
  }
  return out;
}
const T = tokenBlocks();
const hex = (t: Theme, k: string) => {
  const v = T[t][`--flow-${k}`] ?? T.light[`--flow-${k}`];
  if (!/^#[0-9a-fA-F]{6}$/.test(v ?? "")) throw new Error(`--flow-${k} (${t}) is not a #rrggbb value: ${v}`);
  return v;
};

/** Theme surfaces, read from styles.css: light, and every dark theme. */
function surfaces(): Record<Theme, string[]> {
  const css = read("styles.css");
  const all = [...new Set([...css.matchAll(/--surface:\s*(#[0-9a-fA-F]{6})\b/g)].map((m) => m[1].toLowerCase()))];
  return { light: all.filter((c) => lum(rgb(c)) > 0.5), dark: all.filter((c) => lum(rgb(c)) <= 0.5) };
}

const rgb = (h: string): [number, number, number] => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255) as [number, number, number];
const lin = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const lum = (c: [number, number, number]) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
function contrast(a: string, b: string): number {
  const [x, y] = [lum(rgb(a)), lum(rgb(b))].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
// Machado et al. (2009), severity 1.0, applied in linear RGB.
const CVD: Record<string, number[][]> = {
  deutan: [[0.367322, 0.860646, -0.227968], [0.280085, 0.672501, 0.047413], [-0.01182, 0.04294, 0.968881]],
  protan: [[0.152286, 1.052583, -0.204868], [0.114503, 0.786281, 0.099216], [-0.003882, -0.048116, 1.051998]],
  tritan: [[1.255528, -0.076749, -0.178779], [-0.078411, 0.930809, 0.147602], [0.004733, 0.691367, 0.3039]],
};
function labOf(h: string, cvd?: string): [number, number, number] {
  let l = rgb(h).map(lin);
  if (cvd) l = CVD[cvd].map((row) => Math.min(1, Math.max(0, row[0] * l[0] + row[1] * l[1] + row[2] * l[2])));
  const X = (0.4124 * l[0] + 0.3576 * l[1] + 0.1805 * l[2]) / 0.95047;
  const Y = 0.2126 * l[0] + 0.7152 * l[1] + 0.0722 * l[2];
  const Z = (0.0193 * l[0] + 0.1192 * l[1] + 0.9505 * l[2]) / 1.08883;
  const f = (t: number) => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
  return [116 * f(Y) - 16, 500 * (f(X) - f(Y)), 200 * (f(Y) - f(Z))];
}
const dE = (a: string, b: string, cvd?: string) => Math.hypot(...labOf(a, cvd).map((v, i) => v - labOf(b, cvd)[i]));

describe("flow token values", () => {
  const S = surfaces();

  it("reads both themes and every surface", () => {
    expect(S.light).toContain("#ffffff");
    expect(S.dark.length).toBeGreaterThanOrEqual(3);
    expect(Object.keys(T.light).length).toBeGreaterThan(15);
    expect(Object.keys(T.dark).length).toBeGreaterThan(15);
  });

  it("text-bearing tokens reach 4.5:1 on every surface of their theme", () => {
    const fails: string[] = [];
    for (const t of ["light", "dark"] as Theme[]) {
      for (const k of ["in", "out", "util-warn-fg", "util-crit-fg"]) {
        for (const s of S[t]) {
          const c = contrast(hex(t, k), s);
          if (c < 4.5) fails.push(`${t} --flow-${k} ${hex(t, k)} on ${s}: ${c.toFixed(2)}`);
        }
      }
      // White on the accent button is the app's own convention; checked on the
      // token so a dark accent can never make it unreadable unnoticed.
      expect(hex(t, "on-accent")).toBe("#ffffff");
    }
    expect(fails, fails.join("\n")).toEqual([]);
  });

  it("chart marks are visible on the surface (non-text contrast ≥ 3:1)", () => {
    const fails: string[] = [];
    for (const t of ["light", "dark"] as Theme[]) {
      for (const k of ["in", "out", "util-3", "util-warn", "util-crit", ...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => `cat-${i}`)]) {
        for (const s of S[t]) if (contrast(hex(t, k), s) < 3) fails.push(`${t} --flow-${k} on ${s}: ${contrast(hex(t, k), s).toFixed(2)}`);
      }
    }
    expect(fails, fails.join("\n")).toEqual([]);
  });

  it("in and out stay apart for normal vision and every common colour-vision deficiency", () => {
    for (const t of ["light", "dark"] as Theme[]) {
      for (const cvd of [undefined, "deutan", "protan", "tritan"]) {
        expect(dE(hex(t, "in"), hex(t, "out"), cvd), `${t} ${cvd ?? "normal"}`).toBeGreaterThan(20);
      }
    }
  });

  it("the first six categorical hues stay apart (normal, deutan, protan)", () => {
    const fails: string[] = [];
    for (const t of ["light", "dark"] as Theme[]) {
      const cats = [1, 2, 3, 4, 5, 6].map((i) => hex(t, `cat-${i}`));
      for (const cvd of [undefined, "deutan", "protan"]) {
        const floor = cvd ? 8 : 15;
        for (let i = 0; i < cats.length; i++) {
          for (let j = i + 1; j < cats.length; j++) {
            const d = dE(cats[i], cats[j], cvd);
            if (d < floor) fails.push(`${t} ${cvd ?? "normal"} cat-${i + 1}/cat-${j + 1}: ΔE ${d.toFixed(1)} < ${floor}`);
          }
        }
      }
    }
    expect(fails, fails.join("\n")).toEqual([]);
  });

  it("utilisation is a sequential ramp with semantic bands outside it", () => {
    const L = (t: Theme, k: string) => labOf(hex(t, k))[0];
    // Light: heavier load reads darker. Dark: heavier load reads brighter.
    expect(L("light", "util-1")).toBeGreaterThan(L("light", "util-2"));
    expect(L("light", "util-2")).toBeGreaterThan(L("light", "util-3"));
    expect(L("dark", "util-1")).toBeLessThan(L("dark", "util-2"));
    expect(L("dark", "util-2")).toBeLessThan(L("dark", "util-3"));
    for (const t of ["light", "dark"] as Theme[]) {
      expect(dE(hex(t, "util-warn"), hex(t, "util-3"))).toBeGreaterThan(25);
      expect(dE(hex(t, "util-crit"), hex(t, "util-3"))).toBeGreaterThan(25);
      expect(dE(hex(t, "util-crit"), hex(t, "util-warn"))).toBeGreaterThan(15);
    }
  });
});

// Keep the scanned list honest: every flow component file is in it.
it("every file under tabs/flows is scanned", () => {
  const dir = join(SRC, "tabs/flows");
  for (const f of readdirSync(dir)) {
    if (/\.tsx?$/.test(f) && !f.includes(".test.")) expect(COMPONENT_FILES).toContain(relative(SRC, join(dir, f)).split(sep).join("/"));
  }
});
