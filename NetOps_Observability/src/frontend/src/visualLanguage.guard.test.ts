// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// visualLanguage.guard.test.ts — the ratchet behind the visual language
// (owner 2026-11-24, docs/design/visual-language.md › Guard).
//
// Rule 2/3: ONE accent, colour only where it means something, and a state is a
// StatusChip (icon + word + semantic token). New code must not add:
//   1. a hard-coded colour (#hex, rgb()/rgba()/hsl()/hsla()) outside the theme
//      tokens and the kit — colour comes from tokens;
//   2. a per-section hue map (the retired IconRail MOD_HUE / admin group hues);
//   3. a state badge that is not a StatusChip (`className="badge good|warn|bad"`,
//      `badge ${tone}`).
//
// What exists today is recorded per file in visualLanguage.ledger.json, each
// with the reason it is still there. The ledger only SHRINKS: a file may not
// gain a single occurrence, a file not in the ledger may have none, and when a
// file drops below its recorded number the test asks for the ledger to be
// lowered (so the gain is locked in). Regenerate after a cleanup with
//   UPDATE_VL_LEDGER=1 npx vitest run src/visualLanguage.guard.test.ts
// — it refuses to RAISE any number.

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "./lib/copyScan";

const SRC = dirname(fileURLToPath(import.meta.url));
const LEDGER_PATH = join(SRC, "visualLanguage.ledger.json");

type Counts = { colours: number; hueMaps: number; stateBadges: number };
type Entry = Counts & { reason: string };
type Ledger = Record<string, Entry>;

/** Where colour is SUPPOSED to be defined: the kit (semantic tokens only) and
 *  test files. Theme token blocks live in styles.css, which is ledgered like
 *  any other file (it also still holds legacy component rules). */
function exempt(rel: string): boolean {
  return rel.startsWith(`components${sep}kit${sep}`)
    || /\.test\.(ts|tsx)$/.test(rel)
    || rel === "visualLanguage.guard.test.ts";
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|css)$/.test(name)) out.push(p);
  }
  return out;
}

const HEX = /(^|[\s:(,'"`=[])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])/g;
const FUNC = /\b(?:rgba?|hsla?)\(\s*[0-9.]/g;
const HUE_MAP = /\b(?:MOD_HUE|[A-Z_]*_HUES?|hueFor|adm-hue|--adm-(?:ink|solid))\b/g;
const BADGE = /className="badge (?:good|warn|bad|ok|crit)\b|className=\{`badge \$\{/g;

export function countIn(text: string, isCss: boolean): Counts {
  const code = isCss ? text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")) : stripComments(text);
  const n = (re: RegExp) => (code.match(re) ?? []).length;
  return { colours: n(HEX) + n(FUNC), hueMaps: n(HUE_MAP), stateBadges: isCss ? 0 : n(BADGE) };
}

function scan(): Record<string, Counts> {
  const out: Record<string, Counts> = {};
  for (const p of walk(SRC)) {
    const rel = relative(SRC, p);
    if (exempt(rel)) continue;
    const c = countIn(readFileSync(p, "utf8"), p.endsWith(".css"));
    if (c.colours || c.hueMaps || c.stateBadges) out[rel.split(sep).join("/")] = c;
  }
  return out;
}

/** Why a file is still on the ledger — by where it lives. */
function reasonFor(file: string): string {
  if (file === "styles.css") return "theme tokens + legacy component rules; shrinks as pages move to the kit";
  if (/(^|\/)(charts?|sparkline|Chart|NocKpi|heatmap|Geomap|geomap)/i.test(file)) return "chart/map series palette (data encoding, not decoration) — move to tokens";
  if (file.startsWith("features/topology/")) return "topology canvas renderer colours — move to tokens";
  if (file.includes("Logo") || file.includes("brand")) return "brand mark";
  if (/^(pages\/overview|tabs\/(Alerts|Incidents|Correlations|Rules|MaintenanceWindows)|pages\/(Digital|Cloud|Quality|NewMonitor|CommandCenter|ActionQueue)|pages\/(troubleshoot|paths)|components\/rca|tabs\/(Findings|Flows|MetricsExplorer|SavedSearches)|pages\/LogsExplore|features\/)/.test(file))
    return "visual-language phase 3 A/B area — pending its sweep";
  return "visual-language phase 3 residual — replace with tokens / StatusChip when the page is next touched";
}

function loadLedger(): Ledger {
  return existsSync(LEDGER_PATH) ? (JSON.parse(readFileSync(LEDGER_PATH, "utf8")) as Ledger) : {};
}

describe("visual language guard — colour only where it means something", () => {
  const actual = scan();

  if (process.env.UPDATE_VL_LEDGER === "1") {
    it("regenerates the ledger (never raising a number)", () => {
      const old = loadLedger();
      const next: Ledger = {};
      const raised: string[] = [];
      for (const [file, c] of Object.entries(actual).sort(([a], [b]) => a.localeCompare(b))) {
        const prev = old[file];
        if (Object.keys(old).length && (!prev || c.colours > prev.colours || c.hueMaps > prev.hueMaps || c.stateBadges > prev.stateBadges)) {
          raised.push(file);
        }
        next[file] = { ...c, reason: prev?.reason ?? reasonFor(file) };
      }
      expect(raised, "the ledger may only shrink — fix these files instead of recording them").toEqual([]);
      writeFileSync(LEDGER_PATH, JSON.stringify(next, null, 2) + "\n");
    });
    return;
  }

  const ledger = loadLedger();

  it("adds no hard-coded colour, hue map or non-StatusChip state badge anywhere", () => {
    const grown: string[] = [];
    for (const [file, c] of Object.entries(actual)) {
      const l = ledger[file] ?? { colours: 0, hueMaps: 0, stateBadges: 0 };
      if (c.colours > l.colours) grown.push(`${file}: ${c.colours - l.colours} new hard-coded colour(s) — use a theme token`);
      if (c.hueMaps > l.hueMaps) grown.push(`${file}: a per-section hue map — one accent only (visual-language.md rule 2)`);
      if (c.stateBadges > l.stateBadges) grown.push(`${file}: a state badge — render states with <StatusChip> (rule 3)`);
    }
    expect(grown).toEqual([]);
  });

  it("the ledger is not stale — a cleaned-up file is lowered so the gain is kept", () => {
    const stale: string[] = [];
    for (const [file, l] of Object.entries(ledger)) {
      const c = actual[file] ?? { colours: 0, hueMaps: 0, stateBadges: 0 };
      if (c.colours < l.colours || c.hueMaps < l.hueMaps || c.stateBadges < l.stateBadges) {
        stale.push(`${file}: now ${c.colours}/${c.hueMaps}/${c.stateBadges}, ledger ${l.colours}/${l.hueMaps}/${l.stateBadges} — run with UPDATE_VL_LEDGER=1`);
      }
    }
    expect(stale).toEqual([]);
  });

  it("every ledger entry says why it is still there", () => {
    expect(Object.entries(ledger).filter(([, l]) => !l.reason?.trim()).map(([f]) => f)).toEqual([]);
  });

  it("the counter sees what it is meant to see", () => {
    expect(countIn(`const a = "#ff0000"; const b = { color: "rgb(1, 2, 3)" };`, false).colours).toBe(2);
    expect(countIn(`// tracker #123 and #abc in a comment\nconst r = "#/overview";`, false).colours).toBe(0);
    expect(countIn(`.x { color: #fff; } /* #000 */`, true).colours).toBe(1);
    expect(countIn(`const MOD_HUE = {};`, false).hueMaps).toBe(1);
    expect(countIn('<span className="badge good">On</span><span className={`badge ${t}`}>x</span>', false).stateBadges).toBe(2);
    expect(countIn('<span className="badge">count</span>', false).stateBadges).toBe(0);
  });
});
