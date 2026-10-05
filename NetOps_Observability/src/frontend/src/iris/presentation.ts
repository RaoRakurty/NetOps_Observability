// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// presentation.ts — the client half of the Iris presentation contract (tracker
// 337 N-E1; design: docs/architecture/iris-natural-language-platform.md §4.1
// decision 7).
//
// Presentation is SERVER-planned and CLIENT-validated. The server returns a
// typed ResultSet (src/backend/internal/nlquery/plan/result.go) and, beside it,
// a PresentationPlan (src/backend/internal/nlquery/present/present.go) whose
// views come from a CLOSED enum. The model may only *suggest* a view from that
// enum; the server ignores anything else. VIEW_TYPES / HIGHLIGHT_KINDS /
// QUERY_TYPES here and the Go constants are pinned to each other by tests on
// both sides (present/drift_test.go, presentation.test.ts). defaultPlanFor is
// the fallback for a server that sent no plan (older builds). Everything here
// still treats both the plan and the result as untrusted input (§3 zero trust,
// §15 LLM02):
//
//   · validatePlan never throws and never returns a view outside the enum; an
//     unknown view becomes SUMMARY (rendered as escaped text), unknown fields
//     are dropped, oversize strings are clipped, lists are bounded.
//   · normalizeResult copies ONLY the documented fields, bounds every list and
//     drops anything else — in particular a `physical` query text, which the
//     server never serialises and the client must never show if it ever did.
//   · Nothing here produces markup. Every string is data for a React text node.
//
// Pure module: no React, no fetching, no globals.

// ── the closed view enum ─────────────────────────────────────────────────────

export const VIEW_TYPES = [
  "SUMMARY",
  "TABLE",
  "TIME_SERIES",
  "TIMELINE",
  "BAR",
  "TOPOLOGY",
  "PATH",
  "DIFF",
  "EVIDENCE_LIST",
  "INCIDENT_CARD",
  "CHANGE_CARD",
  "RECOMMENDATION_CARD",
] as const;

export type ViewType = (typeof VIEW_TYPES)[number];

export function isViewType(v: unknown): v is ViewType {
  return typeof v === "string" && (VIEW_TYPES as readonly string[]).includes(v);
}

/** The moments the owner's UI standard allows an accent for; all else is neutral. */
export const HIGHLIGHT_KINDS = [
  "root_cause",
  "critical_change",
  "incident_start",
  "recovery",
  "high_confidence",
] as const;

export type HighlightKind = (typeof HIGHLIGHT_KINDS)[number];

export interface Highlight {
  kind: HighlightKind;
  /** Row / change / incident ids the accent applies to. */
  ids: string[];
}

export interface PresentationPlan {
  primary_view: ViewType;
  secondary_view?: ViewType;
  title: string;
  highlight?: Highlight[];
  /** Catalog field names, in display order. */
  table_columns?: string[];
}

/** A validated plan plus WHY it was altered, when it was. */
export interface ValidatedPlan extends PresentationPlan {
  /** Set when the incoming plan was unusable and a fallback was substituted. */
  fallback?: "malformed" | "unknown_view";
  /**
   * The server's note when it ignored the model's view suggestion. Server-
   * written text, shown as escaped text only; clipped like any other string.
   */
  disclosure?: string;
}

// ── the ResultSet mirror (plan/result.go) ────────────────────────────────────

export const QUERY_TYPES = [
  "metric_series",
  "metric_topk",
  "metric_filter",
  "compare_windows",
  "change_list",
  "incident_list",
  "incident_explain",
  "flow_top",
  "log_search",
] as const;

export type QueryType = (typeof QUERY_TYPES)[number];

export interface ResultWindow {
  from: string;
  to: string;
  /** Go time.Duration — nanoseconds. */
  step?: number;
}

export interface EntityRef {
  type: string;
  id: string;
}

/** One sample. `v` is null when the server sent a non-number (unmeasured). */
export interface Point {
  t: number;
  v: number | null;
}

export interface OutSeries {
  entity: Record<string, string>;
  points: Point[];
}

export type Row = Record<string, unknown>;

export interface Constraint {
  path: string;
  from: string;
  to: string;
  reason: string;
}

/** Where the answer came from. There is deliberately NO physical-query field. */
export interface Provenance {
  source: string;
  entities: EntityRef[];
  executed_at: string;
  duration_ms: number | null;
}

export interface ResultSet {
  query_id: string;
  ast_hash: string;
  catalog_version: string;
  query_type: QueryType | null;
  metric: string;
  unit: string;
  window: ResultWindow;
  compare?: ResultWindow;
  series: OutSeries[];
  rows: Row[];
  truncated: boolean;
  constraints_applied: Constraint[];
  notes: string[];
  provenance: Provenance;
  detail?: unknown;
}

// ── bounds ────────────────────────────────────────────────────────────────────

export const LIMITS = {
  title: 200,
  disclosure: 300,
  text: 2000,
  id: 128,
  field: 64,
  columns: 16,
  highlights: 8,
  highlightIds: 64,
  series: 50,
  points: 5000,
  rows: 1000,
  notes: 20,
  constraints: 20,
  entities: 50,
  rowKeys: 40,
} as const;

/** Clip a string to `n` code points (never splits a surrogate pair). */
export function clip(s: string, n: number): string {
  const cps = Array.from(s);
  return cps.length > n ? cps.slice(0, n).join("") + "…" : s;
}

/**
 * Own-key lookup in a constant word map. A plain `map[key]` with an untrusted
 * key resolves "constructor" / "__proto__" to Object's members — which would
 * then be rendered or called. Every lookup keyed by answer data goes here.
 */
export function lookup<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

function str(v: unknown, n: number = LIMITS.text): string {
  return typeof v === "string" ? clip(v, n) : "";
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const FIELD_RE = /^[a-z][a-z0-9_]{0,63}$/;

/** A catalog field name: lower-case identifier. Anything else is dropped. */
export function isFieldName(v: unknown): v is string {
  return typeof v === "string" && FIELD_RE.test(v);
}

// ── validatePlan ──────────────────────────────────────────────────────────────

const FALLBACK_TITLE = "Answer";

/**
 * Turn an untrusted plan into a safe one. Never throws. Only the five contract
 * fields and the server's `disclosure` are read; everything else (including
 * the server's `chosen_by`) is ignored.
 */
export function validatePlan(input: unknown): ValidatedPlan {
  if (!isObj(input)) {
    return { primary_view: "SUMMARY", title: FALLBACK_TITLE, fallback: "malformed" };
  }
  const title = str(input.title, LIMITS.title).trim() || FALLBACK_TITLE;
  const out: ValidatedPlan = { primary_view: "SUMMARY", title };
  if (isViewType(input.primary_view)) {
    out.primary_view = input.primary_view;
  } else {
    out.fallback = input.primary_view === undefined ? "malformed" : "unknown_view";
  }
  if (isViewType(input.secondary_view) && input.secondary_view !== out.primary_view) {
    out.secondary_view = input.secondary_view;
  }
  if (Array.isArray(input.table_columns)) {
    const cols: string[] = [];
    for (const c of input.table_columns) {
      if (cols.length >= LIMITS.columns) break;
      if (isFieldName(c) && !cols.includes(c)) cols.push(c);
    }
    if (cols.length > 0) out.table_columns = cols;
  }
  if (Array.isArray(input.highlight)) {
    const hs: Highlight[] = [];
    for (const h of input.highlight) {
      if (hs.length >= LIMITS.highlights) break;
      if (!isObj(h) || typeof h.kind !== "string") continue;
      if (!(HIGHLIGHT_KINDS as readonly string[]).includes(h.kind)) continue;
      const ids = Array.isArray(h.ids)
        ? h.ids.filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= LIMITS.id).slice(0, LIMITS.highlightIds)
        : [];
      if (ids.length > 0) hs.push({ kind: h.kind as HighlightKind, ids });
    }
    if (hs.length > 0) out.highlight = hs;
  }
  const disclosure = str(input.disclosure, LIMITS.disclosure).trim();
  if (disclosure) out.disclosure = disclosure;
  return out;
}

/**
 * The plan to draw with: the server's (validated) when it sent one, else the
 * client's defaultPlanFor — only for a server that predates N-E1 and sends no
 * plan at all (undefined or null). A plan that IS sent but is unusable is
 * never replaced by the client's own choice: it degrades to SUMMARY, so a
 * broken server plan is visible rather than silently overridden.
 */
export function planFor(result: ResultSet, rawPlan: unknown, hint: QueryHint = {}): ValidatedPlan {
  return rawPlan === undefined || rawPlan === null ? defaultPlanFor(result, hint) : validatePlan(rawPlan);
}

// ── normalizeResult ───────────────────────────────────────────────────────────

export type NormalizeOutcome = { ok: true; result: ResultSet } | { ok: false; reason: string };

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function window(v: unknown): ResultWindow | null {
  if (!isObj(v)) return null;
  const from = str(v.from, 64);
  const to = str(v.to, 64);
  if (!from && !to) return null;
  const w: ResultWindow = { from, to };
  const step = num(v.step);
  if (step !== null && step > 0) w.step = step;
  return w;
}

function entityRefs(v: unknown): EntityRef[] {
  if (!Array.isArray(v)) return [];
  const out: EntityRef[] = [];
  for (const e of v) {
    if (out.length >= LIMITS.entities) break;
    if (!isObj(e)) continue;
    const type = str(e.type, LIMITS.field);
    const id = str(e.id, LIMITS.id);
    if (type && id) out.push({ type, id });
  }
  return out;
}

function row(v: unknown): Row | null {
  if (!isObj(v)) return null;
  const r: Row = {};
  let n = 0;
  for (const [k, val] of Object.entries(v)) {
    if (n >= LIMITS.rowKeys) break;
    if (!isFieldName(k)) continue;
    r[k] = typeof val === "string" ? clip(val, LIMITS.text) : val;
    n++;
  }
  return r;
}

/**
 * Copy an untrusted ResultSet into the typed shape, bounding every list. It
 * refuses only what cannot be rendered at all (not an object); every missing
 * or wrong-typed field degrades to an honest empty value instead.
 */
export function normalizeResult(input: unknown): NormalizeOutcome {
  if (!isObj(input)) return { ok: false, reason: "The answer could not be read." };
  const qt = (QUERY_TYPES as readonly string[]).includes(input.query_type as string)
    ? (input.query_type as QueryType)
    : null;

  const series: OutSeries[] = [];
  if (Array.isArray(input.series)) {
    let budget = LIMITS.points;
    for (const s of input.series) {
      if (series.length >= LIMITS.series || budget <= 0) break;
      if (!isObj(s)) continue;
      const entity: Record<string, string> = {};
      if (isObj(s.entity)) {
        for (const [k, v] of Object.entries(s.entity)) {
          if (isFieldName(k) && typeof v === "string") entity[k] = clip(v, LIMITS.id);
        }
      }
      const points: Point[] = [];
      if (Array.isArray(s.points)) {
        for (const p of s.points) {
          if (budget <= 0) break;
          if (!isObj(p)) continue;
          const t = num(p.t);
          if (t === null) continue;
          points.push({ t, v: num(p.v) });
          budget--;
        }
      }
      series.push({ entity, points });
    }
  }

  const rows: Row[] = [];
  if (Array.isArray(input.rows)) {
    for (const r of input.rows) {
      if (rows.length >= LIMITS.rows) break;
      const nr = row(r);
      if (nr) rows.push(nr);
    }
  }
  const rowsClipped = Array.isArray(input.rows) && input.rows.length > LIMITS.rows;

  const constraints: Constraint[] = [];
  if (Array.isArray(input.constraints_applied)) {
    for (const c of input.constraints_applied) {
      if (constraints.length >= LIMITS.constraints) break;
      if (!isObj(c)) continue;
      constraints.push({ path: str(c.path, LIMITS.field), from: str(c.from, LIMITS.field), to: str(c.to, LIMITS.field), reason: str(c.reason, 300) });
    }
  }

  const notes: string[] = Array.isArray(input.notes)
    ? input.notes.filter((n): n is string => typeof n === "string" && n.trim() !== "").slice(0, LIMITS.notes).map((n) => clip(n, 500))
    : [];

  const prov = isObj(input.provenance) ? input.provenance : {};
  // `physical` is intentionally never read: the backend query text is for
  // administrators through /explain only.
  const provenance: Provenance = {
    source: str(prov.source, 200),
    entities: entityRefs(prov.entities),
    executed_at: str(prov.executed_at, 64),
    duration_ms: num(prov.duration_ms),
  };

  const result: ResultSet = {
    query_id: str(input.query_id, LIMITS.id),
    ast_hash: str(input.ast_hash, LIMITS.id),
    catalog_version: str(input.catalog_version, LIMITS.field),
    query_type: qt,
    metric: str(input.metric, LIMITS.field),
    unit: str(input.unit, 32),
    window: window(input.window) ?? { from: "", to: "" },
    series,
    rows,
    truncated: input.truncated === true || rowsClipped,
    constraints_applied: constraints,
    notes,
    provenance,
  };
  const cmp = window(input.compare);
  if (cmp) result.compare = cmp;
  if (input.detail !== undefined && input.detail !== null) result.detail = input.detail;
  return { ok: true, result };
}

// ── shape predicates ─────────────────────────────────────────────────────────

/** True when there is nothing to draw: no rows and no measured point. */
export function isEmptyResult(r: ResultSet): boolean {
  if (r.rows.length > 0) return false;
  if (r.detail !== undefined && r.query_type === "incident_explain") return false;
  return !r.series.some((s) => s.points.some((p) => p.v !== null));
}

/** A row carries a before/after pair (a diff-able change). */
export function hasBeforeAfter(r: Row): boolean {
  return r.before !== undefined && r.before !== null && r.after !== undefined && r.after !== null;
}

// ── defaultPlanFor ────────────────────────────────────────────────────────────

/**
 * What the question was shaped like, from the validated AST. Optional: without
 * it the plan is chosen from the query type and the result's shape alone.
 */
export interface QueryHint {
  group_by?: string[];
  /** "show exactly what changed" — the compiler marks a request for the diff. */
  wants_diff?: boolean;
}

/**
 * The hint from the server's (untrusted) query: its group-by fields, so a BAR
 * of changes groups — and drills — by what was asked. Bounded; only catalog
 * field names survive.
 */
export function hintFromAst(ast: unknown): QueryHint {
  if (!isObj(ast) || !Array.isArray(ast.group_by)) return {};
  const group_by = ast.group_by.filter(isFieldName).slice(0, 2);
  return group_by.length > 0 ? { group_by } : {};
}

/**
 * Choose a view from the question's semantics (design Part 2 §31):
 *   "how did X change"            → TIME_SERIES           (metric_series)
 *   "who made the most changes"   → BAR                   (change_list grouped)
 *   "what changed"                → TIMELINE + TABLE      (change_list)
 *   "show exactly what changed"   → DIFF                  (one change with before/after)
 *   "why did incident X happen"   → INCIDENT_CARD         (incident_explain)
 *   "compare this week with last" → BAR with delta        (compare_windows)
 */
export function defaultPlanFor(result: ResultSet, hint: QueryHint = {}): PresentationPlan {
  const metric = result.metric ? humanize(result.metric) : "";
  switch (result.query_type) {
    case "metric_series":
      return { primary_view: "TIME_SERIES", secondary_view: "TABLE", title: metric ? `${metric} over time` : "Over time" };
    case "metric_topk":
      return { primary_view: "BAR", secondary_view: "TABLE", title: metric ? `Highest ${metric}` : "Highest values" };
    case "metric_filter":
      return { primary_view: "TABLE", title: metric ? `${metric} matching the condition` : "Matching values" };
    case "compare_windows":
      return { primary_view: "BAR", secondary_view: "TABLE", title: metric ? `${metric}: this window against the earlier one` : "This window against the earlier one" };
    case "change_list": {
      const groups = (hint.group_by ?? []).filter(isFieldName);
      if (groups.length > 0) {
        return { primary_view: "BAR", secondary_view: "TABLE", title: `Changes by ${humanize(groups[0])}` };
      }
      // One change carrying its before/after IS "exactly what changed". Asked for
      // the diff of one change that has none recorded → the change card, which
      // says so, rather than an empty diff.
      if (result.rows.length === 1) {
        if (hasBeforeAfter(result.rows[0])) {
          return { primary_view: "DIFF", secondary_view: "CHANGE_CARD", title: "What changed" };
        }
        if (hint.wants_diff) return { primary_view: "CHANGE_CARD", title: "What changed" };
      }
      return { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" };
    }
    case "incident_list":
      return { primary_view: "TABLE", secondary_view: "TIMELINE", title: "Incidents in this window" };
    case "incident_explain":
      return { primary_view: "INCIDENT_CARD", secondary_view: "EVIDENCE_LIST", title: "Why this incident happened" };
    default:
      return { primary_view: "SUMMARY", title: FALLBACK_TITLE };
  }
}

// ── display helpers (text only) ───────────────────────────────────────────────

const WORDS: Record<string, string> = {
  id: "ID",
  ip: "IP",
  bgp: "BGP",
  cpu: "CPU",
  wan: "WAN",
  lan: "LAN",
  vpn: "VPN",
  rtt: "RTT",
};

/** "object_kind" → "Object kind". Text only. */
export function humanize(field: string): string {
  const words = field.split(/[_.\s]+/).filter(Boolean).map((w) => lookup(WORDS, w.toLowerCase()) ?? w.toLowerCase());
  if (words.length === 0) return "";
  const first = words[0];
  words[0] = first === first.toUpperCase() ? first : first.charAt(0).toUpperCase() + first.slice(1);
  return words.join(" ");
}

/**
 * A measured number for display, or null when the value was not measured.
 * null / undefined / NaN / Infinity / non-numbers are NOT zero.
 */
export function fmtNumber(v: unknown, unit = ""): string | null {
  if (typeof v !== "number" || !Number.isFinite(v)) return null;
  const abs = Math.abs(v);
  const s = abs !== 0 && abs < 0.01 ? v.toExponential(2) : v.toLocaleString("en-US", { maximumFractionDigits: abs >= 100 ? 0 : 2 });
  return unit ? `${s} ${unit}` : s;
}

/** Plain text for any cell value; null means "not measured / not recorded". */
export function cellText(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") return fmtNumber(v);
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "string") return v.trim() === "" ? null : v;
  if (Array.isArray(v)) {
    const parts = v.map((x) => cellText(x)).filter((x): x is string => x !== null);
    return parts.length > 0 ? clip(parts.join(", "), 300) : null;
  }
  try {
    return clip(JSON.stringify(v), 300);
  } catch {
    return null;
  }
}

/** The entity dimensions of a metric row (everything that is not a measure). */
export const MEASURE_FIELDS = new Set(["value", "previous", "delta", "count"]);

export function entityLabel(e: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(e)) {
    if (MEASURE_FIELDS.has(k)) continue;
    if (typeof v === "string" && v !== "") parts.push(v);
  }
  return parts.length > 0 ? parts.join(" · ") : "All";
}

/** Map a backend source tag to the operator's words. Unknown → "Other source". */
export function sourceLabel(tag: string): string {
  switch (tag) {
    case "victoriametrics":
      return "Metrics store";
    case "change_ledger":
      return "Change record";
    case "clickhouse:corr_current":
      return "Incident store";
    case "rca_report":
      return "Root-cause report";
    default:
      return "Other source";
  }
}

export function sourceLabels(source: string): string[] {
  const out: string[] = [];
  for (const s of source.split("+").map((x) => x.trim()).filter(Boolean)) {
    const l = sourceLabel(s);
    if (!out.includes(l)) out.push(l);
  }
  return out;
}

/** The accent a row earns under the plan's highlights, if any. */
export function highlightFor(plan: PresentationPlan, ids: (string | undefined)[]): HighlightKind | undefined {
  for (const h of plan.highlight ?? []) {
    if (ids.some((id) => id !== undefined && h.ids.includes(id))) return h.kind;
  }
  return undefined;
}

/** A stable id for a row, from the fields the planner stamps. */
export function rowId(r: Row, i: number): string {
  for (const k of ["change_id", "incident_id", "id"]) {
    const v = r[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return `row-${i}`;
}
