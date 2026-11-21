// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

// ── TYPE FLOOR RATCHET (design-system pass C2, 2026-10-19) ──────────────────
//
// Owner standard (2026-09-06): body ≥ 14px, headings ≥ 16px, NOTHING below
// 12.5px. The baseline crawl found ≈2,000 text elements at 9–12px; C2 lifted
// them. This keeps them lifted: no font size below 12.5px in styles.css or in
// an inline style, except where a label scales with the zoom of a canvas.
// See docs/ui/DESIGN_SYSTEM.md.

const SRC = dirname(fileURLToPath(import.meta.url));
const SMALL_CSS = /font-size:\s*(9|10|10\.5|11|11\.5|12)px/g;
const SMALL_TSX = /fontSize:\s?"?(9|10|10\.5|11|11\.5|12)(px)?"?(?=[,} ])/g;
// Canvas renderers: node/edge labels are drawn at the canvas zoom, so their
// on-screen size is the zoom's, not this number's.
const EXEMPT_DIRS = ["features/topology/renderers/"];
const EXEMPT_CSS_SELECTOR = /react-flow|\.rf-|topo-canvas|\.tc-|geo-|leaflet|echarts|\.kbd|omni-kbd/i;

function walk(dir: string, out: string[] = []): string[] {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) { if (f !== "node_modules") walk(p, out); }
    else if (/\.(tsx?|css)$/.test(f) && !/\.test\./.test(f)) out.push(p);
  }
  return out;
}

describe("type floor", () => {
  it("styles.css declares nothing below 12.5px outside canvas renderers", () => {
    const hits: string[] = [];
    let selector = "";
    readFileSync(join(SRC, "styles.css"), "utf8").split("\n").forEach((line, i) => {
      if (line.includes("{")) selector = line.split("{")[0];
      if (SMALL_CSS.test(line) && !EXEMPT_CSS_SELECTOR.test(selector)) hits.push(`styles.css:${i + 1} ${line.trim()}`);
      SMALL_CSS.lastIndex = 0;
    });
    expect(hits, "Use var(--fs-meta) / var(--fs-sm) — see docs/ui/DESIGN_SYSTEM.md").toEqual([]);
  });

  // Paths redesign P1 (2026-11-20): the floor held in styles.css while page
  // stylesheets drifted under it — investigation.css carried a 12px label and
  // the pipeline debugger thirteen 11–12px rules, none of them seen. Every
  // shipped .css file is scanned now, with the same canvas exemptions.
  it("no page stylesheet declares anything below 12.5px outside canvas renderers", () => {
    const hits: string[] = [];
    for (const p of walk(SRC)) {
      const rel = relative(SRC, p).split(sep).join("/");
      if (!rel.endsWith(".css") || rel === "styles.css" || EXEMPT_DIRS.some((d) => rel.startsWith(d))) continue;
      let selector = "";
      readFileSync(p, "utf8").split("\n").forEach((line, i) => {
        if (line.includes("{")) selector = line.split("{")[0];
        if (SMALL_CSS.test(line) && !EXEMPT_CSS_SELECTOR.test(selector)) hits.push(`${rel}:${i + 1} ${line.trim()}`);
        SMALL_CSS.lastIndex = 0;
      });
    }
    expect(hits, "Use var(--fs-meta) / var(--fs-sm) — see docs/ui/DESIGN_SYSTEM.md").toEqual([]);
  });

  it("the stylesheet walk reaches the page stylesheets (a broken walk must not pass)", () => {
    const css = walk(SRC).map((p) => relative(SRC, p).split(sep).join("/")).filter((r) => r.endsWith(".css"));
    expect(css).toContain("pages/troubleshoot/investigation.css");
    expect(css.length).toBeGreaterThan(3);
  });

  it("no inline style sets a font size below 12.5px outside canvas renderers", () => {
    const hits: string[] = [];
    for (const p of walk(SRC)) {
      const rel = relative(SRC, p).split(sep).join("/");
      if (!/\.tsx?$/.test(rel) || EXEMPT_DIRS.some((d) => rel.startsWith(d))) continue;
      readFileSync(p, "utf8").split("\n").forEach((line, i) => {
        if (SMALL_TSX.test(line)) hits.push(`${rel}:${i + 1} ${line.trim().slice(0, 90)}`);
        SMALL_TSX.lastIndex = 0;
      });
    }
    expect(hits, "Inline font sizes are ≥ 12.5 (prefer a token class)").toEqual([]);
  });
});
