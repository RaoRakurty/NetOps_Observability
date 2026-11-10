// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import {
  GROUP_WORDS, PAGE_WINDOW, fieldClause, optionsFrom, pager, severityGroupClause, severityGroupOf, tilesFrom, withClauses,
} from "./logFilters";
import { severityKey } from "../theme/severity";

describe("severity tiles come from the store's counts", () => {
  it("map stored words through the one severity map, every group shown", () => {
    const t = tilesFrom({
      signal: "", total: 40, unrated: 5, other: 2,
      counts: [
        { field: "severity", value: "crit", count: 3 }, { field: "severity", value: "2", count: 1 },
        { field: "severity", value: "warning", count: 20 }, { field: "level", value: "error", count: 7 },
        { field: "severity", value: "notice", count: 1 }, { field: "severity", value: "cleared", count: 1 },
      ],
    })!;
    expect(t.tiles.map((x) => [x.label, x.count])).toEqual([
      ["Critical", 4], ["Error", 7], ["Warning", 20], ["Info", 1], ["Healthy", 1],
    ]);
    expect([t.total, t.unrated, t.other, t.sampled]).toEqual([40, 5, 2, false]);
  });
  it("no answer, no tiles: nothing is guessed from the loaded rows", () => {
    expect(tilesFrom(null)).toBeNull();
    expect(tilesFrom(undefined)).toBeNull();
  });
  it("a sampled store says so", () => {
    expect(tilesFrom({ signal: "flows", total: 7, unrated: 7, other: 0, counts: [], sampling: { rate: 50 } })!.sampled).toBe(true);
  });
});

describe("a severity filter matches exactly the words the tiles counted", () => {
  it("every word in a group belongs to that group in the one map", () => {
    for (const [group, words] of Object.entries(GROUP_WORDS)) {
      for (const w of words) expect(severityGroupOf(w), `${w}`).toBe(group);
    }
  });
  it("quotes every word and picks the store's field", () => {
    expect(severityGroupClause("error", "syslog")).toBe('severity:("err" OR "error" OR "major" OR "3")');
    expect(severityGroupClause("error", "applogs")).toBe('level:("err" OR "error" OR "major" OR "3")');
    expect(severityGroupClause("error", "")).toBe('(severity:("err" OR "error" OR "major" OR "3") OR level:("err" OR "error" OR "major" OR "3"))');
    expect(severityGroupClause("critical", "flows")).toBe("");
  });
  it("the Info tile covers notice, info and debug", () => {
    for (const w of ["notice", "info", "debug"]) expect(severityGroupOf(w)).toBe("info");
    expect(severityKey("notice")).toBe("notice");
  });
});

describe("dropdown clauses", () => {
  it("quote a hostile value so it cannot break out", () => {
    expect(fieldClause("event_type", 'x" OR tenant_id:"other')).toBe('event_type:"x\\" OR tenant_id:\\"other"');
  });
  it("AND onto the operator's query without changing what it means", () => {
    expect(withClauses("*", [])).toBe("*");
    expect(withClauses("*", ['family:"cpu"'])).toBe('(family:"cpu")');
    expect(withClauses("a OR b", ['family:"cpu"', ""])).toBe('(a OR b) AND (family:"cpu")');
    expect(withClauses("", ['(severity:("err") OR level:("err"))'])).toBe('(severity:("err") OR level:("err"))');
  });
  it("options come from the loaded rows, most common first, with counts", () => {
    expect(optionsFrom(["a", "b", "a", "", "c", "a", "b"])).toEqual([
      { value: "a", count: 3 }, { value: "b", count: 2 }, { value: "c", count: 1 },
    ]);
  });
});

describe("the pager", () => {
  it("says which rows are on screen out of the exact total", () => {
    const p = pager(7547, 10, 1, 10);
    expect([p.first, p.last, p.total, p.pages, p.capped]).toEqual([1, 10, 7547, 755, false]);
    expect(p.items).toEqual([1, 2, 3, 4, 5, null, 755]);
  });
  it("draws a window around the current page", () => {
    expect(pager(7547, 10, 300, 10).items).toEqual([1, null, 299, 300, 301, null, 755]);
    expect(pager(7547, 10, 755, 7).items).toEqual([1, null, 751, 752, 753, 754, 755]);
    expect(pager(7547, 10, 755, 7).last).toBe(7547);
  });
  it("pages only inside the engine's window, and says it is capped", () => {
    const p = pager(48211, 200, 1, 200);
    expect(p.pages).toBe(PAGE_WINDOW / 200);
    expect(p.capped).toBe(true);
  });
  it("an empty result shows nothing to page", () => {
    const p = pager(0, 200, 1, 0);
    expect([p.first, p.last, p.pages, p.items]).toEqual([0, 0, 1, [1]]);
  });
});
