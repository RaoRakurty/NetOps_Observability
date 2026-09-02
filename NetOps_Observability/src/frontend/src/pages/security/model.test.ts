// model.test.ts — the Security section's data adapters. These are the numbers
// an operator makes a remediation decision on, so every honesty rule the design
// of record demands is pinned here rather than trusted to a component.

import { describe, it, expect } from "vitest";
import {
  appendPage, coverageOf, EMPTY_PAGE, evidenceClassLabel, facetTotal, frameworkScore,
  funnelStages, groupByNative, historyQuery, isThreatLane, mapFacetRows, rulesPutPayload,
  seamCards, severityFacetRows, severityRank, statusFacetRows, storyConfidence, storyList,
  subjectLine, topExposures, trendPoints, verdictOf, verdictTone,
} from "./model";
import { secFindingParams } from "../../services/api";
import {
  FACETS, FINDINGS, PAGE_1, PAGE_2, POSTURE, POSTURE_UNASSESSED, RULES, SEAMS, STORY, TREND, finding,
} from "./fixtures";

describe("verdict mapping (OCSF status_id)", () => {
  it("maps 1/2/3 to pass/warn/fail", () => {
    expect(verdictOf({ status_id: 1 })).toBe("pass");
    expect(verdictOf({ status_id: 2 })).toBe("warn");
    expect(verdictOf({ status_id: 3 })).toBe("fail");
  });

  it("NotApplicable (4) and Error (5) are UNASSESSED, never a pass", () => {
    expect(verdictOf({ status_id: 4 })).toBe("unassessed");
    expect(verdictOf({ status_id: 5 })).toBe("unassessed");
    // and they must not be able to paint a screen green
    expect(verdictTone(verdictOf({ status_id: 4 }))).toBe("");
    expect(verdictTone(verdictOf({ status_id: 5 }))).toBe("");
    expect(verdictTone("pass")).toBe("good");
  });

  it("an unknown status id degrades to unassessed rather than guessing", () => {
    expect(verdictOf({ status_id: 99 })).toBe("unassessed");
  });
});

describe("CTEM funnel arithmetic", () => {
  const stages = funnelStages(POSTURE);

  it("renders the five CTEM stages in pipeline order", () => {
    expect(stages.map((s) => s.key)).toEqual(["scope", "discover", "prioritize", "validate", "mobilize"]);
    expect(stages.map((s) => s.value)).toEqual([2547, 1284, 47, 12, 5]);
  });

  it("each stage carries its share of the PREVIOUS stage (the only honest ratio)", () => {
    expect(stages[0].ofPrevious).toBeNull();            // nothing precedes Scope
    expect(stages[1].ofPrevious).toBe(50);              // 1284/2547
    expect(stages[2].ofPrevious).toBe(4);               // 47/1284
    expect(stages[3].ofPrevious).toBe(26);              // 12/47
    expect(stages[4].ofPrevious).toBe(42);              // 5/12
  });

  it("badges Validate as the live-confirmation stage", () => {
    expect(stages.find((s) => s.key === "validate")?.correlix).toBe(true);
  });

  it("a zero predecessor yields null, never a 0% that reads as 'nothing got through'", () => {
    const s = funnelStages(POSTURE_UNASSESSED);
    expect(s[1].ofPrevious).toBe(0);   // 0/120 is a real 0%
    expect(s[2].ofPrevious).toBeNull(); // 0/0 has no denominator
  });

  it("survives a null posture and negative/garbage counts without inventing numbers", () => {
    expect(funnelStages(null).every((s) => s.value === 0 && s.ofPrevious === null)).toBe(true);
    const junk = funnelStages({ ...POSTURE, funnel: { ...POSTURE.funnel, discover: -5 } });
    expect(junk[1].value).toBe(0);
  });
});

describe("coverage honesty", () => {
  it("states assessed / total / unassessed and never calls the gap clear", () => {
    const c = coverageOf(POSTURE);
    expect(c).toMatchObject({ assessed: 1900, total: 2547, unassessed: 647, pct: 75, hasGap: true, nothingAssessed: false });
    expect(c.label).toContain("647 unassessed");
    expect(c.label).toContain("unknown, not clear");
  });

  it("a wholly unassessed estate says so explicitly", () => {
    const c = coverageOf(POSTURE_UNASSESSED);
    expect(c.nothingAssessed).toBe(true);
    expect(c.pct).toBe(0);
    expect(c.label).toContain("posture is unknown, not clear");
  });

  it("derives the gap when the payload omits `unassessed`", () => {
    const c = coverageOf({ ...POSTURE, coverage: { assessed_assets: 10, total_assets: 40, unassessed: undefined as unknown as number } });
    expect(c.unassessed).toBe(30);
    expect(c.hasGap).toBe(true);
  });

  it("an empty estate has no percentage at all (no divide-by-zero 0%)", () => {
    const c = coverageOf({ ...POSTURE, coverage: { assessed_assets: 0, total_assets: 0, unassessed: 0 } });
    expect(c.pct).toBeNull();
    expect(c.label).toContain("No assets in scope");
  });
});

describe("facet rendering counts", () => {
  it("expands the severity facet's short keys in ramp order", () => {
    const rows = severityFacetRows(FACETS, "high");
    expect(rows.map((r) => r.key)).toEqual(["critical", "high", "medium", "low", "info"]);
    expect(rows.map((r) => r.count)).toEqual([2, 2, 1, 0, 0]);
    expect(rows.find((r) => r.key === "high")?.selected).toBe(true);
  });

  it("orders the verdict facet worst-first", () => {
    expect(statusFacetRows(FACETS).map((r) => [r.key, r.count])).toEqual([["fail", 4], ["warn", 1], ["pass", 1]]);
  });

  it("sorts free-keyed facets by count then key, and labels them when asked", () => {
    expect(mapFacetRows(FACETS.framework).map((r) => r.key)).toEqual(["CIS", "NIST-CSF", "PCI-DSS"]);
    expect(mapFacetRows(FACETS.evidence_class, undefined, evidenceClassLabel).map((r) => r.label))
      .toEqual(["Hardening & posture", "Seam exposure", "Threat detections"]);
  });

  it("totals a facet map for the 'n of m' copy, and treats a missing map as 0", () => {
    expect(facetTotal(FACETS.severity)).toBe(5);
    expect(facetTotal(undefined)).toBe(0);
  });

  it("a null facet payload yields all-zero rows rather than a crash", () => {
    expect(severityFacetRows(null).every((r) => r.count === 0)).toBe(true);
    expect(mapFacetRows(null)).toEqual([]);
  });
});

describe("current-vs-history toggle", () => {
  it("sends current=true / current=false EXPLICITLY in both directions", () => {
    expect(historyQuery("current")).toEqual({ current: true });
    expect(historyQuery("history")).toEqual({ current: false });
    expect(secFindingParams(historyQuery("current", { severity: "high" }))).toBe("severity=high&current=true");
    expect(secFindingParams(historyQuery("history"))).toBe("current=false");
  });

  it("drops unset filters instead of sending them blank", () => {
    expect(secFindingParams({ q: "", severity: undefined, limit: 50 })).toBe("limit=50");
  });

  it("URL-encodes every filter value (no injection surface)", () => {
    expect(secFindingParams({ q: "a b&c=d" })).toBe("q=a+b%26c%3Dd");
  });

  it("history groups every verdict of one native_id newest-first", () => {
    const groups = groupByNative(FINDINGS);
    const nat1 = groups.find((g) => g.native_id === "nat-1");
    expect(nat1?.versions.map((v) => v.id)).toEqual(["doc-1", "doc-6"]);
    expect(groups.length).toBe(5); // 6 findings, two of them share nat-1
  });
});

describe("cursor pagination", () => {
  it("first page replaces, later pages append, and the cursor is carried", () => {
    const p1 = appendPage(EMPTY_PAGE, PAGE_1, false);
    expect(p1.items.map((f) => f.id)).toEqual(["doc-1", "doc-2", "doc-3"]);
    expect(p1).toMatchObject({ cursor: "cur-2", hasMore: true, total: 6 });

    const p2 = appendPage(p1, PAGE_2, true);
    expect(p2.items.map((f) => f.id)).toEqual(["doc-1", "doc-2", "doc-3", "doc-4", "doc-5", "doc-6"]);
    expect(p2).toMatchObject({ cursor: null, hasMore: false });
  });

  it("a filter change REPLACES — a narrowed filter never leaves wider rows on screen", () => {
    const p1 = appendPage(EMPTY_PAGE, PAGE_1, false);
    const narrowed = appendPage(p1, { items: [FINDINGS[0]], next_cursor: null, total: 1 }, false);
    expect(narrowed.items.map((f) => f.id)).toEqual(["doc-1"]);
    expect(narrowed.total).toBe(1);
  });

  it("an overlapping resumed cursor never double-counts a doc id", () => {
    const p1 = appendPage(EMPTY_PAGE, PAGE_1, false);
    const overlap = appendPage(p1, PAGE_1, true);
    expect(overlap.items).toHaveLength(3);
  });

  it("a null page yields an empty, honest state (no stale rows, no fake total)", () => {
    expect(appendPage(EMPTY_PAGE, null, false)).toEqual(EMPTY_PAGE);
  });
});

describe("seam map", () => {
  const cards = seamCards(FACETS, SEAMS);

  it("scores the seams the facets cover and orders them worst-first", () => {
    expect(cards.map((c) => c.seam)).toEqual(["ISP", "internet", "SaaS"]);
    expect(cards[0]).toMatchObject({ count: 2, assessed: true, owner: "isp" });
  });

  it("a seam the findings store never scored is UNASSESSED (null), never 0", () => {
    const saas = cards.find((c) => c.seam === "SaaS")!;
    expect(saas.assessed).toBe(false);
    expect(saas.count).toBeNull();
  });

  it("a scored seam with no findings is a real 0 (assessed AND clean)", () => {
    const c = seamCards({ ...FACETS, seam: { ...FACETS.seam, SaaS: 0 } }, SEAMS);
    expect(c.find((x) => x.seam === "SaaS")).toMatchObject({ assessed: true, count: 0 });
  });

  it("a seam in the facets but absent from the inventory still renders", () => {
    const c = seamCards({ ...FACETS, seam: { mgmt: 4 } }, []);
    expect(c).toEqual([{ seam: "mgmt", label: "mgmt", count: 4, owner: "", assessed: true }]);
  });
});

describe("compliance — hardening findings on the tagged control set", () => {
  it("scores passing verdicts over the TAGGED set only", () => {
    const s = frameworkScore("CIS", 3, { ...FACETS, status: { pass: 6, warn: 2, fail: 2 } });
    expect(s).toMatchObject({ framework: "CIS", pass: 6, warn: 2, fail: 2, pct: 60, tagged: 3, tone: "bad" });
  });

  it("nothing scored ⇒ no percentage at all (never 0%, never 100%)", () => {
    const s = frameworkScore("HIPAA", 0, { ...FACETS, status: { pass: 0, warn: 0, fail: 0 } });
    expect(s.pct).toBeNull();
    expect(s.tone).toBe("");
  });

  it("tones the ring on the passing share", () => {
    expect(frameworkScore("x", 1, { ...FACETS, status: { pass: 95, warn: 0, fail: 5 } }).tone).toBe("good");
    expect(frameworkScore("x", 1, { ...FACETS, status: { pass: 75, warn: 0, fail: 25 } }).tone).toBe("warn");
  });
});

describe("rules PUT payload", () => {
  it("sends {rule_id, enabled} for CHANGED rules only, id-ordered", () => {
    const payload = rulesPutPayload(RULES, { "netrule.beacon": true, "netrule.telnet_vty": true });
    expect(payload).toEqual([{ rule_id: "netrule.beacon", enabled: true }]);
  });

  it("carries no server-owned field (family / fidelity / mitre / seam_aware)", () => {
    const payload = rulesPutPayload(RULES, { "netrule.telnet_vty": false });
    expect(Object.keys(payload[0]).sort()).toEqual(["enabled", "rule_id"]);
  });

  it("ignores an unknown rule id — a client cannot create a rule by toggling one", () => {
    expect(rulesPutPayload(RULES, { "netrule.does-not-exist": true })).toEqual([]);
  });

  it("no change ⇒ empty payload, so the caller can skip the request entirely", () => {
    expect(rulesPutPayload(RULES, { "netrule.telnet_vty": true })).toEqual([]);
  });

  it("orders multiple changes deterministically", () => {
    const p = rulesPutPayload(RULES, { "netrule.logging_disabled": false, "netrule.beacon": true });
    expect(p.map((x) => x.rule_id)).toEqual(["netrule.beacon", "netrule.logging_disabled"]);
  });
});

describe("exposure stories", () => {
  it("accepts the contract's bare array and drops malformed entries", () => {
    expect(storyList([STORY]).map((s) => s.correlation_id)).toEqual(["corr-9"]);
    expect(storyList([STORY, null, { nope: 1 }])).toHaveLength(1);
  });

  it("tolerates an {items:[…]} envelope and refuses anything else", () => {
    expect(storyList({ items: [STORY] })).toHaveLength(1);
    expect(storyList("boom")).toEqual([]);
    expect(storyList(undefined)).toEqual([]);
  });

  it("states confidence as a percentage, or null when the object states none", () => {
    expect(storyConfidence(STORY)).toBe(72);
    expect(storyConfidence({ ...STORY, top_confidence: 84 })).toBe(84);
    expect(storyConfidence({ ...STORY, top_confidence: 0 })).toBeNull();
  });
});

describe("trend + top exposures", () => {
  it("orders buckets oldest-first and totals each one", () => {
    const pts = trendPoints(TREND);
    expect(pts.map((p) => p.t)).toEqual(["2026-08-30", "2026-08-31", "2026-09-01"]);
    expect(pts[0].total).toBe(37);
  });

  it("drops malformed buckets instead of charting them as zero", () => {
    expect(trendPoints({ buckets: [{ t: "", fail: 1, warn: 0, pass: 0 }] })).toEqual([]);
    expect(trendPoints(null)).toEqual([]);
  });

  it("ranks the worst open findings first and excludes passes and unassessed", () => {
    const top = topExposures(FINDINGS, 10);
    expect(top.map((f) => f.id)).toEqual(["doc-1", "doc-5", "doc-2", "doc-3"]);
    expect(top.some((f) => f.status_id === 1 || f.status_id === 4)).toBe(false);
  });

  it("ranks severity before recency", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank(undefined)).toBe(0);
  });
});

describe("labels", () => {
  it("names each evidence lane in operator words", () => {
    expect(evidenceClassLabel("posture")).toBe("Hardening & posture");
    expect(evidenceClassLabel("exposure")).toBe("Seam exposure");
    expect(evidenceClassLabel("threat")).toBe("Threat detections");
    expect(evidenceClassLabel("")).toBe("Unclassified");
  });

  it("treats the store's 'signal' and the contract's 'threat' as one lane", () => {
    expect(isThreatLane("signal")).toBe(true);
    expect(isThreatLane("threat")).toBe(true);
    expect(isThreatLane("posture")).toBe(false);
    expect(evidenceClassLabel("signal")).toBe(evidenceClassLabel("threat"));
  });

  it("names a finding's subject, falling back through hostname and uid", () => {
    expect(subjectLine(FINDINGS[0])).toBe("core-01 · Cisco IOS-XE 17.9");
    expect(subjectLine(finding({ resource: { hostname: "h1" } }))).toBe("h1");
    expect(subjectLine(finding({ resource: {} }))).toBe("unknown asset");
  });
});
