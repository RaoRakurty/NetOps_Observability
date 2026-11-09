// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// coverageModel.test.ts — the honesty rules of the Telemetry coverage adapters.
// The wording assertions are deliberate: "No lines yet" and "0.0%" are
// different facts, and a 403 on the platform stats endpoint is an ANSWER.

import { describe, it, expect } from "vitest";
import {
  CATALOG_DOCS_URL,
  fidelityBadgeClass,
  fidelityLabel,
  fidelityRank,
  fidelityTitle,
  isForbidden,
  laneCapability,
  liveReading,
  NOT_COVERED,
  promotionDisplay,
  ruleRows,
  ruleSummary,
  ruleSummaryOf,
  severityBadgeClass,
  severityLabel,
  unrecognizedItems,
  unrecognizedNote,
  vendorRows,
} from "./coverageModel";
import type { ParserStats, VendorLaneStats, VendorScore } from "../../services/api";
import {
  parserStatsFixture,
  parserStatsNoLinesFixture,
  unrecognizedFixture,
  unrecognizedNotMinedFixture,
} from "./fixtures";

describe("vendor scorecard wording", () => {
  const lane = (over: Partial<VendorLaneStats> = {}): VendorLaneStats => ({
    grammars: 0, mib_nodes: 0, mibs: 0, trap_definitions: 0, fixtures: 0, rules: {}, live: { total: 0, read: 0 }, ...over,
  });
  const row = (syslog: VendorLaneStats, extra: Partial<VendorScore> = {}): VendorScore => ({
    vendor: "x", display_name: "X", lanes: { syslog, snmptrap: lane() }, ...extra,
  });

  it("no tested sample is not covered, whatever else exists for the lane", () => {
    expect(laneCapability(lane(), "syslog")).toBe(NOT_COVERED);
    expect(laneCapability(lane({ grammars: 3 }), "syslog")).toBe(NOT_COVERED);
    expect(laneCapability(lane({ mib_nodes: 3061, mibs: 5 }), "snmptrap")).toBe(NOT_COVERED);
    expect(laneCapability(undefined, "syslog")).toBe(NOT_COVERED);
  });

  it("states what a lane with tested samples can read", () => {
    expect(laneCapability(lane({ grammars: 1, fixtures: 1 }), "syslog")).toBe("1 format, 1 tested");
    expect(laneCapability(lane({ mib_nodes: 1099, fixtures: 12 }), "snmptrap")).toBe("1,099 names, 12 tested");
  });

  it("keeps no reading, no lines, not covered and a real rate apart", () => {
    expect(liveReading(row(lane({ fixtures: 3, live: null })), "syslog")).toBe("No reading");
    expect(liveReading(row(lane({ fixtures: 3 })), "syslog")).toBe("No lines yet");
    expect(liveReading(row(lane({ fixtures: 3 })), "snmptrap")).toBe("No traps yet");
    expect(liveReading(row(lane({ live: { total: 900, read: 0 } })), "syslog")).toBe("900 lines, not covered yet");
    expect(liveReading(row(lane({ fixtures: 3, live: { total: 900, read: 0 } })), "syslog")).toBe("0% read of 900 lines");
    expect(liveReading(row(lane({ fixtures: 3, live: { total: 1, read: 1 } })), "syslog")).toBe("100% read of 1 line");
  });

  it("never rounds up to a clean 100%, and never a working lane down to a flat 0%", () => {
    expect(liveReading(row(lane({ fixtures: 3, live: { total: 10000, read: 9999 } })), "syslog")).toBe("99.9% read of 10,000 lines");
    expect(liveReading(row(lane({ fixtures: 3, live: { total: 10000, read: 9990 } })), "syslog")).toBe("99.9% read of 10,000 lines");
    expect(liveReading(row(lane({ fixtures: 3, live: { total: 10000, read: 1 } })), "syslog")).toBe("0.0% read of 10,000 lines");
  });

  it("an unidentified sender shows its real rate: there is no vendor to be not covered", () => {
    expect(liveReading(row(lane({ live: { total: 119000, read: 0 } }), { unidentified: true }), "syslog")).toBe("0% read of 119,000 lines");
  });

  it("counts rules across both lanes and only calls validated ones proven", () => {
    const r = row(lane({ rules: { lab_validated: 2, doc_claimed: 3 } }));
    r.lanes.snmptrap = lane({ rules: { live_validated: 1, unrated: 4 } });
    expect(ruleSummaryOf(r)).toBe("10, 3 proven on a device");
    expect(ruleSummaryOf(row(lane({ rules: { doc_claimed: 2 } })))).toBe("2, none proven yet");
    expect(ruleSummaryOf(row(lane()))).toBe("None yet");
  });

  it("unwraps a missing or malformed list", () => {
    expect(vendorRows(null)).toEqual([]);
    expect(vendorRows({ vendors: "nope" } as unknown as ParserStats)).toEqual([]);
  });
});

describe("promotionDisplay", () => {
  it("renders a rate as one-decimal percent with the admitted-lines caption", () => {
    expect(promotionDisplay(parserStatsFixture)).toEqual({
      value: "81.3%",
      caption: "240,000 lines",
      unknown: false,
    });
  });

  it("says 'No lines yet' for a null rate — never 0%", () => {
    const d = promotionDisplay(parserStatsNoLinesFixture);
    expect(d.value).toBe("—");
    expect(d.caption).toBe("No lines yet");
    expect(d.unknown).toBe(true);
    expect(d.value).not.toBe("0.0%");
  });

  it("distinguishes a genuine zero rate from no data", () => {
    const zero = promotionDisplay({ promotion_rate: 0, window_lines: 1200 });
    expect(zero.value).toBe("0.0%");
    expect(zero.caption).toBe("1,200 lines");
    expect(zero.unknown).toBe(false);
  });

  it("singularizes the caption for a one-line window and clamps out-of-range rates", () => {
    expect(promotionDisplay({ promotion_rate: 1, window_lines: 1 }).caption).toBe("1 line");
    expect(promotionDisplay({ promotion_rate: 1.4, window_lines: 10 }).value).toBe("100.0%");
    expect(promotionDisplay({ promotion_rate: -0.2, window_lines: 10 }).value).toBe("0.0%");
  });
});

describe("fidelity badge mapping", () => {
  it("gives each of the four contract values a distinct tier class", () => {
    const classes = ["code", "doc_claimed", "lab_validated", "live_validated"].map(fidelityBadgeClass);
    expect(classes).toEqual(["badge tier-t5", "badge tier-t4", "badge tier-t3", "badge tier-t1"]);
    expect(new Set(classes).size).toBe(4);
  });

  it("labels and explains each tier in operator words", () => {
    expect(fidelityLabel("live_validated")).toBe("live validated");
    expect(fidelityLabel("doc_claimed")).toBe("doc claimed");
    expect(fidelityTitle("doc_claimed")).toMatch(/unconfirmed on the wire/i);
    expect(fidelityTitle("code")).toMatch(/not yet confirmed against a device/i);
  });

  it("orders the evidence ladder strongest-first for sorting", () => {
    expect(fidelityRank("live_validated")).toBeGreaterThan(fidelityRank("lab_validated"));
    expect(fidelityRank("lab_validated")).toBeGreaterThan(fidelityRank("doc_claimed"));
    expect(fidelityRank("doc_claimed")).toBeGreaterThan(fidelityRank("code"));
  });

  it("degrades an unknown value to a neutral badge rather than hiding it", () => {
    expect(fidelityBadgeClass("wishful")).toBe("badge tier-t5");
    expect(fidelityLabel("wishful")).toBe("wishful");
    expect(fidelityLabel("")).toBe("unrated");
    expect(fidelityRank("wishful")).toBe(0);
  });
});

describe("isForbidden", () => {
  it("recognizes the api layer's 403 error shape", () => {
    expect(isForbidden("403 Forbidden: platform admin required")).toBe(true);
    expect(isForbidden("Request failed: 403")).toBe(true);
    expect(isForbidden("forbidden")).toBe(true);
  });

  it("does not mistake other failures (or a 4030-style number) for a permission answer", () => {
    expect(isForbidden("500 Internal Server Error: boom")).toBe(false);
    expect(isForbidden("503 Service Unavailable: 4031 lines lost")).toBe(false);
    expect(isForbidden(null)).toBe(false);
    expect(isForbidden("")).toBe(false);
  });
});

describe("rule inventory summary", () => {
  it("counts shadow and validated rules separately from the total", () => {
    expect(ruleSummary(ruleRows(parserStatsFixture))).toEqual({ total: 5, shadow: 2, validated: 3 });
  });

  it("survives a malformed payload without crashing", () => {
    expect(ruleRows(null)).toEqual([]);
    expect(ruleRows({ ...parserStatsFixture, rules: undefined as never })).toEqual([]);
    expect(ruleSummary([])).toEqual({ total: 0, shadow: 0, validated: 0 });
  });
});

describe("unrecognizedNote", () => {
  it("prefers the backend's honest note verbatim", () => {
    expect(unrecognizedNote(unrecognizedNotMinedFixture)).toBe("analysis has not run yet");
  });

  it("says the window is clean when the list is empty with no note", () => {
    expect(unrecognizedNote({ ...unrecognizedNotMinedFixture, note: undefined }))
      .toBe("No unrecognized message shapes in the last 7 days.");
  });

  it("counts shown-of-total when the list is truncated", () => {
    expect(unrecognizedNote(unrecognizedFixture)).toBe("2 shapes over the last 7 days.");
    expect(unrecognizedNote({ ...unrecognizedFixture, total: 91 })).toBe("2 of 91 shapes over the last 7 days.");
  });

  it("returns nothing for a missing page and unwraps items defensively", () => {
    expect(unrecognizedNote(null)).toBe("");
    expect(unrecognizedItems(null)).toEqual([]);
    expect(unrecognizedItems({ ...unrecognizedFixture, items: undefined as never })).toEqual([]);
  });
});

describe("severity mapping", () => {
  it("names syslog numeric severities and colors them on the shared ramp", () => {
    expect(severityLabel(3)).toBe("error");
    expect(severityLabel(5)).toBe("notice");
    expect(severityBadgeClass(0)).toBe("badge sev-critical");
    expect(severityBadgeClass(4)).toBe("badge sev-warning");
  });

  it("falls back neutrally for an out-of-range severity", () => {
    expect(severityLabel(99)).toBe("99");
    expect(severityBadgeClass(99)).toBe("badge sev-info");
  });
});

describe("catalog docs link", () => {
  it("is a single https constant so the PR workflow is one line to move", () => {
    expect(CATALOG_DOCS_URL).toMatch(/^https:\/\//);
  });
});
