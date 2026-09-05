// flowsAppViews.test.ts — the honesty rules of Explore → Flows' APP and SERVICE
// views, tested where they live (pure functions), not through the DOM.
//
// Each block below pins one claim the screen makes about partial knowledge. If
// a future change makes "unknown" disappear into an empty state, lets an
// unattributed service sort as a zero, or drops the coverage/filter caveat,
// one of these fails.

import { describe, it, expect } from "vitest";
import type { FlowAppRow, FlowServiceRow } from "../services/api";
import {
  UNKNOWN_APP,
  UNKNOWN_MEANING,
  UNMEASURED_LABEL,
  DRILL_ACTION,
  isUnknownApp,
  appLabel,
  sourceSide,
  tierView,
  sortAppRows,
  appRowKey,
  appTotals,
  appShare,
  groupServiceRows,
  sortServiceRows,
  serviceMeasuredBytes,
  serviceShare,
  windowPhrase,
  coverageSentence,
  filterFieldPhrase,
  windowScopeCaveat,
  windowScopeNote,
  drillNote,
} from "./flowsAppViews";

const app = (over: Partial<FlowAppRow>): FlowAppRow => ({
  app: "unknown", src_app: "", tier: "undetermined", bytes: 0, flows: 0, dests: 0, ...over,
});
const svc = (over: Partial<FlowServiceRow>): FlowServiceRow => ({
  service_id: "s1", name: "Service", criticality: "medium", attributed: true, bytes: 0, flows: 0, ...over,
});

describe("the unknown bucket is first class", () => {
  it("recognises the engine's bucket and an absent name alike", () => {
    expect(isUnknownApp("unknown")).toBe(true);
    expect(isUnknownApp("UNKNOWN")).toBe(true);
    expect(isUnknownApp("")).toBe(true);
    expect(isUnknownApp(undefined)).toBe(true);
    expect(isUnknownApp("payroll")).toBe(false);
  });

  it("labels it as a bucket and keeps a sentence saying what it means", () => {
    expect(appLabel("unknown")).toBe("Unknown");
    expect(appLabel("  payroll ")).toBe("payroll");
    expect(UNKNOWN_MEANING).toMatch(/uncatalogued or internal/i);
    expect(UNKNOWN_MEANING).toMatch(/not missing/i);
    expect(UNKNOWN_APP).toBe("unknown");
  });

  it("ranks and totals the unknown row exactly like a named one (all-unknown input)", () => {
    const rows = [
      app({ app: "unknown", src_app: "unknown", bytes: 10, flows: 1 }),
      app({ app: "unknown", src_app: "payroll", bytes: 90, flows: 9 }),
    ];
    const sorted = sortAppRows(rows);
    expect(sorted.map((r) => r.bytes)).toEqual([90, 10]);

    const t = appTotals(rows);
    expect(t).toEqual({ bytes: 100, flows: 10, unknownBytes: 100, unknownRows: 2 });
    // the bucket is 100% of the window, and the share maths says so rather
    // than treating it as an absence
    expect(appShare(sorted[0], t.bytes)).toBeCloseTo(90);
    expect(appShare(sorted[1], t.bytes)).toBeCloseTo(10);
  });
});

describe("a legacy row with no source column is UNRESOLVED, not unknown", () => {
  it('separates src_app "" from src_app "unknown"', () => {
    expect(sourceSide("")).toEqual({ kind: "unresolved", label: "Source not resolved" });
    expect(sourceSide(undefined)).toEqual({ kind: "unresolved", label: "Source not resolved" });
    expect(sourceSide("unknown").kind).toBe("unknown");
    expect(sourceSide("payroll")).toEqual({ kind: "named", label: "payroll" });
  });

  it("keeps a legacy row rankable and keyed without inventing a source", () => {
    const legacy = app({ app: "AWS S3", src_app: "", bytes: 500, flows: 5, tier: "confirmed" });
    const modern = app({ app: "AWS S3", src_app: "payroll", bytes: 400, flows: 4, tier: "confirmed" });
    const sorted = sortAppRows([modern, legacy]);
    expect(sorted[0]).toBe(legacy);
    expect(appRowKey(legacy)).toBe("→AWS S3");
    expect(appRowKey(modern)).toBe("payroll→AWS S3");
    expect(appRowKey(legacy)).not.toBe(appRowKey(modern));
  });
});

describe("tier reuses the one attribution vocabulary", () => {
  it("maps the engine's three verdicts to the wording the app views already use", () => {
    expect(tierView("confirmed").label).toBe("Confirmed");
    expect(tierView("suspected").label).toBe("Suspected · not confirmed");
    expect(tierView("undetermined").label).toBe("Under review");
    expect(tierView("CONFIRMED").label).toBe("Confirmed");
  });

  it("gives each verdict a distinct tone and a meaning to show", () => {
    expect(tierView("confirmed").tone).not.toBe(tierView("suspected").tone);
    expect(tierView("confirmed").meaning.length).toBeGreaterThan(10);
  });

  it("shows an unrecognised verdict verbatim instead of a friendlier lie", () => {
    expect(tierView("recovered").label).toBe("recovered");
    expect(tierView("").label).toBe("Not stated");
  });
});

describe("application ordering", () => {
  it("sorts by bytes desc with a stable, deterministic tie-break", () => {
    const rows = [
      app({ app: "beta", src_app: "x", bytes: 100 }),
      app({ app: "alpha", src_app: "x", bytes: 100 }),
      app({ app: "gamma", src_app: "x", bytes: 900 }),
    ];
    expect(sortAppRows(rows).map((r) => r.app)).toEqual(["gamma", "alpha", "beta"]);
    // pure: the caller's array is untouched
    expect(rows.map((r) => r.app)).toEqual(["beta", "alpha", "gamma"]);
  });

  it("survives empty and absent input", () => {
    expect(sortAppRows([])).toEqual([]);
    expect(sortAppRows(undefined)).toEqual([]);
    expect(appTotals([])).toEqual({ bytes: 0, flows: 0, unknownBytes: 0, unknownRows: 0 });
    expect(appShare(app({ bytes: 5 }), 0)).toBeNull();
  });

  it("ignores junk numbers off the wire rather than producing NaN", () => {
    const rows = [app({ app: "a", bytes: NaN as unknown as number }), app({ app: "b", bytes: 10 })];
    const t = appTotals(rows);
    expect(t.bytes).toBe(10);
    expect(appShare(rows[1], t.bytes)).toBeCloseTo(100);
  });
});

describe("an unattributed service is UNMEASURED, never idle", () => {
  it("groups unattributed rows apart instead of sorting them as zeroes", () => {
    const rows = [
      svc({ service_id: "u2", name: "Zeta", attributed: false }),
      svc({ service_id: "m1", name: "Payroll", attributed: true, bytes: 10 }),
      svc({ service_id: "u1", name: "Alpha", attributed: false }),
      svc({ service_id: "m2", name: "Billing", attributed: true, bytes: 900 }),
    ];
    const g = groupServiceRows(rows);
    expect(g.measured.map((r) => r.name)).toEqual(["Billing", "Payroll"]);
    expect(g.unmeasured.map((r) => r.name)).toEqual(["Alpha", "Zeta"]);
    // the flat order keeps every measurement above the unmeasured group
    expect(sortServiceRows(rows).map((r) => r.name)).toEqual(["Billing", "Payroll", "Alpha", "Zeta"]);
  });

  it("never gives an unattributed row a share, not even 0%", () => {
    const rows = [
      svc({ service_id: "m", name: "Billing", attributed: true, bytes: 300 }),
      svc({ service_id: "u", name: "Unwired", attributed: false, bytes: 0 }),
    ];
    const total = serviceMeasuredBytes(rows);
    expect(total).toBe(300);
    expect(serviceShare(rows[0], total)).toBeCloseTo(100);
    expect(serviceShare(rows[1], total)).toBeNull();
    expect(UNMEASURED_LABEL).toBe("Not measured");
  });

  it("excludes unmeasured rows from the denominator (share-of-total with them present)", () => {
    const rows = [
      svc({ service_id: "a", name: "A", attributed: true, bytes: 75 }),
      svc({ service_id: "b", name: "B", attributed: true, bytes: 25 }),
      // three unattributed services with a zero that must not dilute the split
      svc({ service_id: "c", name: "C", attributed: false, bytes: 0 }),
      svc({ service_id: "d", name: "D", attributed: false, bytes: 0 }),
      svc({ service_id: "e", name: "E", attributed: false, bytes: 0 }),
    ];
    const total = serviceMeasuredBytes(rows);
    expect(total).toBe(100);
    expect(serviceShare(rows[0], total)).toBeCloseTo(75);
    expect(serviceShare(rows[1], total)).toBeCloseTo(25);
  });

  it("handles an unattributed-only catalog without dividing by zero", () => {
    const rows = [
      svc({ service_id: "u1", name: "Alpha", attributed: false }),
      svc({ service_id: "u2", name: "Beta", attributed: false }),
    ];
    expect(serviceMeasuredBytes(rows)).toBe(0);
    expect(groupServiceRows(rows).measured).toEqual([]);
    expect(serviceShare(rows[0], 0)).toBeNull();
    expect(sortServiceRows(rows).map((r) => r.name)).toEqual(["Alpha", "Beta"]);
  });

  it("survives empty and absent input", () => {
    expect(sortServiceRows([])).toEqual([]);
    expect(sortServiceRows(undefined)).toEqual([]);
    expect(serviceMeasuredBytes(null)).toBe(0);
  });
});

describe("the coverage statement", () => {
  it("says which slice of the window was named, and with what", () => {
    const s = coverageSentence({ top_pairs: 200, window_seconds: 3600, catalog_prefixes: 1240 });
    expect(s).toContain("200");
    expect(s).toContain("the last hour");
    expect(s).toContain("1,240");
    expect(s).toMatch(/not every flow/i);
  });

  it("says so when nothing named the traffic from a catalog", () => {
    const s = coverageSentence({ top_pairs: 50, window_seconds: 900, catalog_prefixes: 0 });
    expect(s).toContain("the last 15 minutes");
    expect(s).toMatch(/No catalogued address ranges/i);
  });

  it("still speaks when the endpoint reported no coverage at all", () => {
    for (const c of [undefined, null, { top_pairs: 0, window_seconds: 0, catalog_prefixes: 0 }]) {
      const s = coverageSentence(c);
      expect(s).toMatch(/sample/i);
      expect(s.length).toBeGreaterThan(20);
    }
  });

  it("phrases the window the way an operator says it", () => {
    expect(windowPhrase(900)).toBe("the last 15 minutes");
    expect(windowPhrase(3600)).toBe("the last hour");
    expect(windowPhrase(21600)).toBe("the last 6 hours");
    expect(windowPhrase(86400)).toBe("the last 24 hours");
    expect(windowPhrase(172800)).toBe("the last 2 days");
    expect(windowPhrase(0)).toBe("this window");
  });
});

describe("the window-only caveat", () => {
  it("stays silent with no filters set", () => {
    expect(windowScopeCaveat([], "Applications")).toBeNull();
  });

  it("names the set fields and says they do not narrow the numbers", () => {
    const s = windowScopeCaveat(["src", "dst"], "Applications") as string;
    expect(s).toContain("Applications");
    expect(s).toContain("source and destination");
    expect(s).toMatch(/do not narrow/i);
  });

  it("translates every wire field name into the operator's word", () => {
    expect(filterFieldPhrase(["device"])).toBe("device");
    expect(filterFieldPhrase(["in_if", "out_if"])).toBe("ingress interface and egress interface");
    expect(filterFieldPhrase(["src", "dst", "device"])).toBe("source, destination and device");
    expect(filterFieldPhrase([])).toBe("");
  });

  it("states the same scope fact even when nothing is filtered", () => {
    expect(windowScopeNote("Services")).toMatch(/^Services answer over the selected time window only/);
  });
});

describe("the drill is honest about what it cannot do", () => {
  it("promises a section switch for the same window, not an app filter", () => {
    const n = drillNote("payroll");
    expect(n).toContain("payroll");
    expect(n).toMatch(/not narrowed/i);
    expect(n).toMatch(/address-level/i);
    expect(DRILL_ACTION).toMatch(/Conversations/);
  });
});
