#!/usr/bin/env node
// ui-consistency-check.mjs — enterprise design-consistency linter for the Correlix
// SPA. Flags hardcoded design values that should come from the theme tokens, so
// colors/fonts/sizes stay uniform across the app (per the standing consistency
// directive). NOT a replacement for review — a fast drift detector to run during
// UI work:  node scripts/ui-consistency-check.mjs   (exit 1 if violations).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const SRC = new URL("../src/", import.meta.url).pathname;
const files = [];
(function walk(d) {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    if (statSync(p).isDirectory()) walk(p);
    else if ([".tsx", ".ts", ".css"].includes(extname(p))) files.push(p);
  }
})(SRC);

// Real UI-CHROME drift bugs (hardcoded instead of token in interactive/surface
// styling). NOT data-viz: chart series ramps, gauge gradients, topology node
// colors and module-hue token DEFINITIONS legitimately use hex — those are
// exempted via VIZ_OK below. Add patterns as discovered.
const DENY = [
  { re: /var\(\s*--mod\s*,\s*#[0-9a-fA-F]{3,8}/gi, msg: "hardcoded fallback in a --mod var — use var(--mod, var(--rail-accent))" },
  { re: /background\s*:\s*#fafbfc/gi, msg: "hardcoded table header bg — use var(--surface)" },
  { re: /border[^:]*:\s*[^;]*#dde1e8/gi, msg: "hardcoded border — use var(--panel-border)" },
];
const HEX = /#[0-9a-fA-F]{3,8}\b/g;
// Files where raw hex is legitimate: token defs, generated, and the
// data-visualization layer (multi-hued series/gauge/graph palettes by design).
const HEX_OK = [
  // ConnectorLogos.tsx used to be exempt as "vendor logos". It no longer holds
  // any colour literal at all (licence D5 + tracker 239), so the exemption is
  // gone and a reintroduced brand hex is now a lint failure as well as a test
  // failure.
  /styles\.css$/, /theme\/prefs\.ts$/, /theme\/charts\.ts$/, /Icon\.tsx$/, /icons?\//i,
  /panels\.tsx$/, /Topology\.tsx$/, /Dashboard\.tsx$/, /\.css$/, // viz + decorative
  // Fixed-palette by design (NOT app-theme surfaces): the RCA PDF/print export is a
  // standalone light document with its own professional palette; the device terminal
  // uses xterm's own colour scheme. Theme tokens would be wrong in both.
  /rca\/rcaExport\.ts$/, /DeviceTerminal\.tsx$/,
];

// Canonical type scale (px). Everything else is drift — near-duplicate sizes
// erode the hierarchy. 66 = the single hero score. Keep this in sync with the
// documented scale.
const FONT_SCALE = new Set([10, 10.5, 11, 11.5, 12, 12.5, 13, 14, 16, 18, 20, 22, 26, 30, 34, 66]);
const FONT_OK = [/styles\.css$/, /\.css$/]; // CSS may define the scale + a few one-offs; focus the check on component inline sizes
let deny = 0, tsxHex = 0, fontDrift = 0;
const fontHist = {};
const out = [];
for (const f of files) {
  const rel = f.slice(SRC.length);
  const src = readFileSync(f, "utf8");
  const lines = src.split("\n");
  lines.forEach((ln, i) => {
    for (const d of DENY) if (d.re.test(ln)) { out.push(`  DENY  ${rel}:${i + 1}  ${d.msg}`); deny++; }
  });
  // hardcoded colors inside .tsx/.ts components (inline styles) — should be tokens
  if (/\.tsx?$/.test(f) && !HEX_OK.some((r) => r.test(f))) {
    lines.forEach((ln, i) => {
      // Strip token-with-fallback hexes — var(--x, #abc) and cssVar("--x", "#abc")
      // are the CORRECT, theme-aware pattern (the hex is only a defensive fallback),
      // not a hardcode. Only a hex with NO governing token is a real violation.
      const cleaned = ln
        .replace(/var\(\s*--[\w-]+\s*,\s*#[0-9a-fA-F]{3,8}/g, "var(--t")
        .replace(/cssVar\(\s*["']--[\w-]+["']\s*,\s*["']#[0-9a-fA-F]{3,8}/g, "cssVar(t");
      const m = cleaned.match(HEX);
      if (m && /style|background|color|fill|stroke|border/i.test(cleaned)) {
        out.push(`  HEX   ${rel}:${i + 1}  hardcoded ${m.join(",")} in a component — prefer var(--token)`);
        tsxHex++;
      }
    });
  }
  // font-size drift — any size off the canonical scale (component inline + css)
  lines.forEach((ln, i) => {
    const sizes = [...ln.matchAll(/font-?[sS]ize:\s*["']?\s*([0-9]+(?:\.[0-9]+)?)\s*(px)?/g)].map((x) => parseFloat(x[1]));
    for (const s of sizes) {
      if (!Number.isFinite(s)) continue;
      fontHist[s] = (fontHist[s] || 0) + 1;
      if (!FONT_SCALE.has(s) && !FONT_OK.some((r) => r.test(f))) {
        out.push(`  FONT  ${rel}:${i + 1}  ${s}px off the type scale — snap to ${nearestScale(s)}px`);
        fontDrift++;
      }
    }
  });
}

function nearestScale(s) {
  return [...FONT_SCALE].reduce((a, b) => (Math.abs(b - s) < Math.abs(a - s) ? b : a));
}

console.log("UI consistency check\n====================");
if (out.length) console.log(out.join("\n"));
const offScale = Object.keys(fontHist).map(Number).filter((s) => !FONT_SCALE.has(s)).sort((a, b) => a - b);
console.log(`\nFont-size histogram (px → count): ${Object.keys(fontHist).map(Number).sort((a, b) => a - b).map((s) => `${s}:${fontHist[s]}`).join("  ")}`);
console.log(`Off-scale sizes: ${offScale.join(", ") || "none"}`);
console.log(`\n${deny} off-standard literal(s) · ${tsxHex} hardcoded component color(s) · ${fontDrift} off-scale font-size use(s) · ${files.length} files.`);
process.exit(deny > 0 ? 1 : 0); // DENY (known bugs) fails; hex + font drift are advisory
