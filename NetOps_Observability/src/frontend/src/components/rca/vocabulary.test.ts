import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

// ── UI VOCABULARY REGRESSION (owner directive, docs/design/rca-evidence-summary.md §3)
//
// The word "Signals" is ENGINE vocabulary. It must never reach an operator's
// screen: a raw row is an "observation", and the qualified evidence line is
// "Evidence". This test enforces the directive mechanically instead of relying
// on reviewers remembering it — it scans every rendered .tsx and fails naming
// file:line.
//
// Scope: COPY, not code. Only string literals and JSX text nodes are inspected,
// comments are stripped first, and the match is case-sensitive + word-bounded —
// so `signalCount`, `loadHealthSignals`, `deriveHealthFromAvailableSignals`,
// `useAppSignals` and API field names are all deliberately untouched.

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The bare engine word, as it would reach a screen. Case-sensitive, word-bounded. */
const BARE_WORD = /\bSignals\b/;

/** Prose/label props called out explicitly by the directive (redundant with the
 *  bare-word scan, kept as named patterns so a failure says WHICH shape broke). */
const LABEL_SHAPES: ReadonlyArray<{ re: RegExp; why: string }> = [
  { re: /subtitle="Signals/, why: 'subtitle="Signals…' },
  { re: /title="Signals/, why: 'title="Signals…' },
  { re: /label="Signals/, why: 'label="Signals…' },
  { re: /header:\s*"Signals"/, why: 'header: "Signals"' },
  { re: />Signals</, why: "JSX text node" },
  { re: /["'`]Signals["'`]/, why: "quoted label" },
];

/**
 * Blanks out line and block comments, preserving every character position (and
 * therefore line numbers) so hits report the true file:line.
 */
export function stripComments(text: string): string {
  const out = text.split("");
  let i = 0;
  type Mode = "code" | "line" | "block" | "sq" | "dq" | "tpl";
  let mode: Mode = "code";
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (mode === "code") {
      if (c === "/" && n === "/") { mode = "line"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "/" && n === "*") { mode = "block"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "'") mode = "sq"; else if (c === '"') mode = "dq"; else if (c === "`") mode = "tpl";
      i++; continue;
    }
    if (mode === "line") {
      if (c === "\n") { mode = "code"; i++; continue; }
      out[i] = " "; i++; continue;
    }
    if (mode === "block") {
      if (c === "*" && n === "/") { mode = "code"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c !== "\n") out[i] = " ";
      i++; continue;
    }
    // inside a string literal
    if (c === "\\") { i += 2; continue; }
    if ((mode === "sq" && c === "'") || (mode === "dq" && c === '"') || (mode === "tpl" && c === "`")) mode = "code";
    i++;
  }
  return out.join("");
}

/** The parts of a line a user can actually read: string literals + JSX text. */
function readableSpans(line: string): string[] {
  const spans: string[] = [];
  for (const m of line.matchAll(/"([^"]*)"|'([^']*)'|`([^`]*)`/g)) spans.push(m[1] ?? m[2] ?? m[3] ?? "");
  for (const m of line.matchAll(/>([^<>{}]+)</g)) spans.push(m[1]);
  return spans;
}

function tsxFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === "mock") continue;
      tsxFiles(full, out);
      continue;
    }
    if (!e.name.endsWith(".tsx")) continue;
    if (e.name.includes(".test.")) continue;   // fixtures may mirror API JSON
    if (e.name === "rcaPreview.tsx") continue; // standalone static preview harness
    out.push(full);
  }
  return out;
}

/** Returns "path:line — why" for every engine word that reaches the screen. */
export function scanForEngineVocabulary(text: string, label: string): string[] {
  const hits: string[] = [];
  stripComments(text).split("\n").forEach((line, i) => {
    const why = LABEL_SHAPES.find((p) => p.re.test(line))?.why
      ?? (readableSpans(line).some((s) => BARE_WORD.test(s)) ? "bare word in UI copy" : "");
    if (why) hits.push(`${label}:${i + 1} — "Signals" (${why})`);
  });
  return hits;
}

describe('UI vocabulary — the word "Signals" never reaches the screen', () => {
  const files = tsxFiles(SRC);

  it("finds .tsx files to scan (guards against a broken walk silently passing)", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it("no rendered .tsx shows the word to an operator (raw rows are observations)", () => {
    const hits = files.flatMap((f) =>
      scanForEngineVocabulary(readFileSync(f, "utf-8"), relative(SRC, f).split(sep).join("/")),
    );
    expect(hits, `engine vocabulary reached the UI:\n${hits.join("\n")}`).toEqual([]);
  });

  // Teeth: every shape that was actually fixed still trips the scanner.
  it("would fail on the pre-rename source (scanner has teeth)", () => {
    const reverted = [
      '{ key: "sig", header: "Signals", width: 110, align: "right" },',
      '<div className="ao-rca-l">Signals</div>',
      'subtitle="Signals that deviate from baseline and may contribute to incidents."',
      '<Chip label="Signals" />',
      '<h3>Correlated Signals for this window</h3>',
    ].join("\n");
    const hits = scanForEngineVocabulary(reverted, "fixture.tsx");
    expect(hits).toHaveLength(5);
    expect(hits[0]).toContain('fixture.tsx:1 — "Signals" (header: "Signals")');
    expect(hits[1]).toContain("(JSX text node)");
    expect(hits[2]).toContain('(subtitle="Signals…)');
    expect(hits[3]).toContain('(label="Signals…)');
    expect(hits[4]).toContain("(bare word in UI copy)");
  });

  // Anti-false-positive: identifiers and API field names are code, not copy.
  it("never fires on identifiers, API fields, or comments", () => {
    const legit = [
      'import { loadHealthSignals } from "./api";',
      "const sig = useAppSignals(app);",
      "expect(deriveHealthFromAvailableSignals(x)).toBe(y);",
      '<div>{rca.signalCount} observations</div>',
      'const body = JSON.stringify({ signals: rows, signal_count: rows.length });',
      '// Signals/apps/objects are then narrowed CLIENT-side — engine wording is fine here',
      '/* the old "Signals: 300" line is described in this block comment */',
    ].join("\n");
    expect(scanForEngineVocabulary(legit, "legit.tsx")).toEqual([]);
  });
});
