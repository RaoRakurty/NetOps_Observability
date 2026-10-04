// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// jsonDiff.ts — pure before/after comparison for the Iris diff view.
//
// Structured values (JSON objects/arrays, or strings that parse as one) are
// flattened to "path → value" and compared by path. Plain text is compared line
// by line (longest common subsequence). Both are bounded so a hostile or huge
// change record cannot stall the page; hitting a bound sets `truncated`.
//
// Output is data only — the renderer shows every string as escaped text.

import { clip } from "./presentation";

export type DiffKind = "same" | "changed" | "added" | "removed";

export interface DiffRow {
  path: string;
  before: string | null;
  after: string | null;
  kind: DiffKind;
}

export interface DiffModel {
  mode: "structured" | "text";
  rows: DiffRow[];
  added: number;
  removed: number;
  changed: number;
  truncated: boolean;
}

export const DIFF_LIMITS = { depth: 8, entries: 500, lines: 500, value: 500 } as const;

function parseMaybe(v: unknown): unknown {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return v;
  try {
    return JSON.parse(t);
  } catch {
    return v;
  }
}

function isStructured(v: unknown): boolean {
  return typeof v === "object" && v !== null;
}

function leafText(v: unknown): string {
  if (typeof v === "string") return clip(v, DIFF_LIMITS.value);
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return "[]";
  if (typeof v === "object") return "{}";
  return "";
}

function flatten(v: unknown, out: Map<string, string>, state: { truncated: boolean }, path = "", depth = 0): void {
  if (out.size >= DIFF_LIMITS.entries) {
    state.truncated = true;
    return;
  }
  const isArr = Array.isArray(v);
  if (typeof v === "object" && v !== null && depth < DIFF_LIMITS.depth) {
    const entries = isArr ? (v as unknown[]).map((x, i) => [String(i), x] as const) : Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) {
      out.set(path || "(root)", isArr ? "[]" : "{}");
      return;
    }
    for (const [k, child] of entries) {
      const p = isArr ? `${path}[${k}]` : path ? `${path}.${k}` : k;
      flatten(child, out, state, clip(p, 200), depth + 1);
      if (state.truncated) return;
    }
    return;
  }
  if (typeof v === "object" && v !== null) state.truncated = true; // depth bound
  out.set(path || "(root)", leafText(v));
}

function textLines(v: unknown): string[] {
  const s = typeof v === "string" ? v : v === null || v === undefined ? "" : leafText(v);
  if (s === "") return [];
  return s.replace(/\r\n?/g, "\n").split("\n");
}

/** Line diff by LCS over bounded inputs. */
function lineDiff(a: string[], b: string[]): DiffRow[] {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      rows.push({ path: `line ${j + 1}`, before: a[i], after: b[j], kind: "same" });
      i++;
      j++;
    } else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) {
      rows.push({ path: `line ${j + 1}`, before: null, after: b[j], kind: "added" });
      j++;
    } else {
      rows.push({ path: `line ${i + 1} (before)`, before: a[i], after: null, kind: "removed" });
      i++;
    }
  }
  return rows;
}

export function buildDiff(beforeIn: unknown, afterIn: unknown): DiffModel {
  const before = parseMaybe(beforeIn);
  const after = parseMaybe(afterIn);
  let rows: DiffRow[];
  let truncated = false;
  let mode: DiffModel["mode"];
  if (isStructured(before) || isStructured(after)) {
    mode = "structured";
    const st = { truncated: false };
    const a = new Map<string, string>();
    const b = new Map<string, string>();
    if (before !== undefined && before !== null) flatten(before, a, st);
    if (after !== undefined && after !== null) flatten(after, b, st);
    truncated = st.truncated;
    const paths = Array.from(new Set([...a.keys(), ...b.keys()])).sort();
    rows = paths.map((p) => {
      const x = a.has(p) ? (a.get(p) as string) : null;
      const y = b.has(p) ? (b.get(p) as string) : null;
      const kind: DiffKind = x === null ? "added" : y === null ? "removed" : x === y ? "same" : "changed";
      return { path: p, before: x, after: y, kind };
    });
  } else {
    mode = "text";
    let la = textLines(before);
    let lb = textLines(after);
    if (la.length > DIFF_LIMITS.lines || lb.length > DIFF_LIMITS.lines) {
      truncated = true;
      la = la.slice(0, DIFF_LIMITS.lines);
      lb = lb.slice(0, DIFF_LIMITS.lines);
    }
    rows = lineDiff(la.map((l) => clip(l, DIFF_LIMITS.value)), lb.map((l) => clip(l, DIFF_LIMITS.value)));
  }
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (const r of rows) {
    if (r.kind === "added") added++;
    else if (r.kind === "removed") removed++;
    else if (r.kind === "changed") changed++;
  }
  return { mode, rows, added, removed, changed, truncated };
}

/**
 * The same comparison as unified-diff text, for the shared ConfigDiffView.
 * Every line starts with "  ", "- " or "+ " so no value can masquerade as a
 * diff header ("---"/"+++"/"@@").
 */
export function toUnified(d: DiffModel): string {
  const out: string[] = [];
  for (const r of d.rows) {
    const label = d.mode === "structured" ? `${r.path}: ` : "";
    if (r.kind === "same") out.push(`  ${label}${r.after ?? ""}`);
    if (r.kind === "removed" || r.kind === "changed") out.push(`- ${label}${r.before ?? ""}`);
    if (r.kind === "added" || r.kind === "changed") out.push(`+ ${label}${r.after ?? ""}`);
  }
  return out.join("\n");
}
