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
// Files where raw hex is legitimate: token defs, generated, vendor logos, and the
// data-visualization layer (multi-hued series/gauge/graph palettes by design).
const HEX_OK = [
  /styles\.css$/, /theme\/prefs\.ts$/, /theme\/charts\.ts$/, /ConnectorLogos\.tsx$/, /Icon\.tsx$/, /icons?\//i,
  /panels\.tsx$/, /Topology\.tsx$/, /Dashboard\.tsx$/, /\.css$/, // viz + decorative
];

let deny = 0, tsxHex = 0;
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
      const m = ln.match(HEX);
      if (m && /style|background|color|fill|stroke|border/i.test(ln)) {
        out.push(`  HEX   ${rel}:${i + 1}  hardcoded ${m.join(",")} in a component — prefer var(--token)`);
        tsxHex++;
      }
    });
  }
}

console.log("UI consistency check\n====================");
if (out.length) console.log(out.join("\n"));
console.log(`\n${deny} off-standard literal(s), ${tsxHex} hardcoded color(s) in components, across ${files.length} files.`);
process.exit(deny > 0 ? 1 : 0); // DENY (known bugs) fails; tsx hex is advisory
