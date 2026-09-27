// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// presentation.test.ts — the client half of the Iris presentation contract:
// validatePlan (closed enum, fallback, clipping), normalizeResult (bounded copy,
// physical query never read), defaultPlanFor (view chosen by question shape)
// and the text helpers (unmeasured is never 0).

import { describe, it, expect } from "vitest";
import {
  LIMITS,
  VIEW_TYPES,
  cellText,
  clip,
  defaultPlanFor,
  entityLabel,
  fmtNumber,
  highlightFor,
  humanize,
  isEmptyResult,
  isViewType,
  normalizeResult,
  rowId,
  sourceLabels,
  validatePlan,
  type ResultSet,
} from "./presentation";
import { HOSTILE, baseResult, changeRow, compareResult, incidentResult, seriesResult } from "../test/irisFixtures";

function norm(v: unknown): ResultSet {
  const n = normalizeResult(v);
  if (!n.ok) throw new Error(n.reason);
  return n.result;
}

describe("validatePlan — the closed view enum", () => {
  it("accepts every enum member as the primary view", () => {
    for (const v of VIEW_TYPES) {
      const p = validatePlan({ primary_view: v, title: "t" });
      expect(p.primary_view).toBe(v);
      expect(p.fallback).toBeUndefined();
    }
  });

  it.each([null, undefined, 42, "TABLE", [], true])("falls back to SUMMARY for a non-object plan %p", (input) => {
    const p = validatePlan(input);
    expect(p.primary_view).toBe("SUMMARY");
    expect(p.fallback).toBe("malformed");
    expect(p.title).toBe("Answer");
  });

  it("turns an unknown view into SUMMARY and says why", () => {
    const p = validatePlan({ primary_view: "HTML_WIDGET", title: "x" });
    expect(p.primary_view).toBe("SUMMARY");
    expect(p.fallback).toBe("unknown_view");
  });

  it("is case-sensitive: 'table' is not TABLE", () => {
    expect(validatePlan({ primary_view: "table" }).primary_view).toBe("SUMMARY");
    expect(isViewType("table")).toBe(false);
  });

  it("drops an unknown secondary view and one equal to the primary", () => {
    expect(validatePlan({ primary_view: "TABLE", secondary_view: "IFRAME" }).secondary_view).toBeUndefined();
    expect(validatePlan({ primary_view: "TABLE", secondary_view: "TABLE" }).secondary_view).toBeUndefined();
    expect(validatePlan({ primary_view: "TABLE", secondary_view: "BAR" }).secondary_view).toBe("BAR");
  });

  it("ignores unknown fields entirely", () => {
    const p = validatePlan({ primary_view: "BAR", title: "t", html: HOSTILE, onClick: "alert(1)", __proto__: { x: 1 } });
    expect(Object.keys(p).sort()).toEqual(["primary_view", "title"]);
  });

  it("clips an oversize title and keeps a hostile title as plain data", () => {
    const p = validatePlan({ primary_view: "TABLE", title: "a".repeat(5000) });
    expect(Array.from(p.title).length).toBeLessThanOrEqual(LIMITS.title + 1);
    expect(p.title.endsWith("…")).toBe(true);
    expect(validatePlan({ primary_view: "TABLE", title: HOSTILE }).title).toBe(HOSTILE);
  });

  it("replaces a blank or non-string title", () => {
    expect(validatePlan({ primary_view: "TABLE", title: "   " }).title).toBe("Answer");
    expect(validatePlan({ primary_view: "TABLE", title: { a: 1 } }).title).toBe("Answer");
  });

  it("keeps only well-formed, bounded, de-duplicated table columns", () => {
    const cols = ["actor", "Actor", "site", "site", "a b", "<x>", 7, "x".repeat(80), ...Array.from({ length: 40 }, (_, i) => `c${i}`)];
    const p = validatePlan({ primary_view: "TABLE", table_columns: cols });
    expect(p.table_columns?.[0]).toBe("actor");
    expect(p.table_columns?.[1]).toBe("site");
    expect(p.table_columns).not.toContain("Actor");
    expect(p.table_columns).not.toContain("<x>");
    expect(p.table_columns!.length).toBeLessThanOrEqual(LIMITS.columns);
  });

  it("keeps only highlights of a known kind with ids", () => {
    const p = validatePlan({
      primary_view: "TIMELINE",
      highlight: [
        { kind: "root_cause", ids: ["a", 3, ""] },
        { kind: "make_it_red", ids: ["b"] },
        { kind: "recovery", ids: [] },
        "junk",
      ],
    });
    expect(p.highlight).toEqual([{ kind: "root_cause", ids: ["a"] }]);
  });
});

describe("normalizeResult — a bounded copy of an untrusted ResultSet", () => {
  it.each([null, "x", 3, []])("refuses a non-object %p with an honest reason", (v) => {
    const n = normalizeResult(v);
    expect(n.ok).toBe(false);
  });

  it("never carries the physical query, even if one is sent", () => {
    const r = norm(baseResult({ provenance: { source: "change_ledger", physical: ["SELECT * FROM secret"], executed_at: "", entities: [] } }));
    expect(JSON.stringify(r)).not.toContain("SELECT");
    expect(Object.keys(r.provenance)).not.toContain("physical");
  });

  it("degrades missing fields to honest empties", () => {
    const r = norm({});
    expect(r.rows).toEqual([]);
    expect(r.series).toEqual([]);
    expect(r.query_type).toBeNull();
    expect(r.provenance.duration_ms).toBeNull();
    expect(r.window).toEqual({ from: "", to: "" });
  });

  it("keeps an unmeasured sample as null, not 0, and drops points without a time", () => {
    const r = norm(seriesResult({ series: [{ entity: { device: "d" }, points: [{ t: 1, v: "NaN" }, { t: 2, v: 5 }, { v: 3 }, { t: 3 }] }] }));
    expect(r.series[0].points).toEqual([{ t: 1, v: null }, { t: 2, v: 5 }, { t: 3, v: null }]);
  });

  it("drops rows that are not objects and keys that are not catalog names", () => {
    const r = norm(baseResult({ rows: [changeRow({ "<b>": "x", "Bad Key": 1 }), "row", null, 5] }));
    expect(r.rows).toHaveLength(1);
    expect(Object.keys(r.rows[0])).not.toContain("<b>");
    expect(Object.keys(r.rows[0])).not.toContain("Bad Key");
  });

  it("bounds rows and marks the answer truncated when it clips", () => {
    const rows = Array.from({ length: LIMITS.rows + 5 }, (_, i) => changeRow({ change_id: `c${i}` }));
    const r = norm(baseResult({ rows }));
    expect(r.rows).toHaveLength(LIMITS.rows);
    expect(r.truncated).toBe(true);
  });

  it("bounds the total number of points", () => {
    const pts = Array.from({ length: LIMITS.points + 100 }, (_, i) => ({ t: i + 1, v: i }));
    const r = norm(seriesResult({ series: [{ entity: {}, points: pts }, { entity: {}, points: pts }] }));
    const total = r.series.reduce((a, s) => a + s.points.length, 0);
    expect(total).toBeLessThanOrEqual(LIMITS.points);
  });

  it("rejects an unknown query type rather than trusting it", () => {
    expect(norm(baseResult({ query_type: "drop_tables" })).query_type).toBeNull();
  });

  it("only sets truncated from a literal true", () => {
    expect(norm(baseResult({ truncated: "yes" })).truncated).toBe(false);
    expect(norm(baseResult({ truncated: true })).truncated).toBe(true);
  });
});

describe("defaultPlanFor — view by question semantics", () => {
  it("'how did X change' → TIME_SERIES", () => {
    expect(defaultPlanFor(norm(seriesResult())).primary_view).toBe("TIME_SERIES");
  });

  it("'who made the most changes' → BAR", () => {
    const r = norm(baseResult({ rows: [changeRow(), changeRow({ change_id: "c2" })] }));
    const p = defaultPlanFor(r, { group_by: ["actor"] });
    expect(p.primary_view).toBe("BAR");
    expect(p.title).toBe("Changes by Actor");
  });

  it("a change list → TIMELINE + TABLE", () => {
    const r = norm(baseResult({ rows: [changeRow(), changeRow({ change_id: "c2" })] }));
    const p = defaultPlanFor(r);
    expect(p.primary_view).toBe("TIMELINE");
    expect(p.secondary_view).toBe("TABLE");
  });

  it("'show exactly what changed' → DIFF when the change has before/after", () => {
    const r = norm(baseResult({ rows: [changeRow({ before: "a", after: "b" })] }));
    expect(defaultPlanFor(r, { wants_diff: true }).primary_view).toBe("DIFF");
    expect(defaultPlanFor(r).primary_view).toBe("DIFF");
  });

  it("asked for the diff of a change with none recorded → CHANGE_CARD, not an empty diff", () => {
    const r = norm(baseResult({ rows: [changeRow()] }));
    expect(defaultPlanFor(r, { wants_diff: true }).primary_view).toBe("CHANGE_CARD");
  });

  it("incident_explain → INCIDENT_CARD", () => {
    expect(defaultPlanFor(norm(incidentResult())).primary_view).toBe("INCIDENT_CARD");
  });

  it("compare_windows → BAR with the table beside it", () => {
    const p = defaultPlanFor(norm(compareResult()));
    expect(p.primary_view).toBe("BAR");
    expect(p.secondary_view).toBe("TABLE");
  });

  it("an unknown/absent query type → SUMMARY", () => {
    expect(defaultPlanFor(norm({})).primary_view).toBe("SUMMARY");
  });

  it("ignores a hostile group_by name", () => {
    const r = norm(baseResult({ rows: [changeRow(), changeRow({ change_id: "c2" })] }));
    expect(defaultPlanFor(r, { group_by: ["<script>"] }).primary_view).toBe("TIMELINE");
  });
});

describe("text helpers", () => {
  it("fmtNumber: unmeasured is null, never 0", () => {
    expect(fmtNumber(null)).toBeNull();
    expect(fmtNumber(undefined)).toBeNull();
    expect(fmtNumber(NaN)).toBeNull();
    expect(fmtNumber(Infinity)).toBeNull();
    expect(fmtNumber("5")).toBeNull();
    expect(fmtNumber(0)).toBe("0");
    expect(fmtNumber(12.345, "ms")).toBe("12.35 ms");
  });

  it("cellText renders every value type as text", () => {
    expect(cellText(null)).toBeNull();
    expect(cellText("")).toBeNull();
    expect(cellText(true)).toBe("Yes");
    expect(cellText(["a", null, "b"])).toBe("a, b");
    expect(cellText({ a: 1 })).toBe('{"a":1}');
    expect(cellText(HOSTILE)).toBe(HOSTILE); // data, not markup — React escapes it
  });

  it("humanize", () => {
    expect(humanize("object_kind")).toBe("Object kind");
    expect(humanize("bgp_state")).toBe("BGP state");
    expect(humanize("")).toBe("");
  });

  it("entityLabel skips measures", () => {
    expect(entityLabel({ site: "DFW", device: "r1", value: 3 })).toBe("DFW · r1");
    expect(entityLabel({ value: 3 })).toBe("All");
  });

  it("sourceLabels maps known tags and hides unknown ones behind a generic name", () => {
    expect(sourceLabels("change_ledger+clickhouse:corr_current")).toEqual(["Change record", "Incident store"]);
    expect(sourceLabels(HOSTILE)).toEqual(["Other source"]);
  });

  it("clip never splits a surrogate pair", () => {
    expect(clip("😀😀😀", 2)).toBe("😀😀…");
  });

  it("rowId prefers the stamped ids", () => {
    expect(rowId({ change_id: "c", incident_id: "i" }, 0)).toBe("c");
    expect(rowId({ incident_id: "i" }, 0)).toBe("i");
    expect(rowId({}, 3)).toBe("row-3");
  });

  it("highlightFor matches only listed ids", () => {
    const plan = validatePlan({ primary_view: "TIMELINE", highlight: [{ kind: "critical_change", ids: ["c1"] }] });
    expect(highlightFor(plan, ["c1"])).toBe("critical_change");
    expect(highlightFor(plan, ["c2", undefined])).toBeUndefined();
  });

  it("isEmptyResult: series with only unmeasured points is empty; an explained incident is not", () => {
    expect(isEmptyResult(norm(seriesResult({ series: [{ entity: {}, points: [{ t: 1, v: null }] }] })))).toBe(true);
    expect(isEmptyResult(norm(incidentResult({ rows: [] })))).toBe(false);
    expect(isEmptyResult(norm(baseResult()))).toBe(true);
  });
});
