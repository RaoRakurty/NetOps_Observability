// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// commandCenter.model.test.ts — regression for the Command Center's PRODUCT decision
// logic (gap-report step 2: the operator decision surface was untested). Pins the
// non-negotiables: the single-stream confirm guard, internal-stack exclusion (#76),
// ticket gating, the severity sort, and defensive JSON parsing.

import { describe, it, expect } from "vitest";
import { corrObject } from "../test/factories";
import {
  fmtAge, parseAffected, parseMissing, deriveRca, deriveEvidence, deriveFault,
  deriveOwner, deriveTicket, deriveSev, buildItem, isActionableCorr, bySeverityThenAge,
  filterItems, needsAction, activeFilterCount, isUntriaged,
  startedAt, sevRank, rcaRank, evidenceRank, ownerRank, ticketRank,
  type ActionItem,
} from "./commandCenter.model";

const NOW = Date.parse("2026-06-22T12:00:00Z");

describe("RCA state derivation — honesty rules", () => {
  it("never reports Confirmed unless verdict_tier says so (≥2-stream rule upstream)", () => {
    // A high-confidence, multi-signal object that the engine left 'suspected' must
    // NOT be promoted to Confirmed by the view layer.
    const c = corrObject({ verdict_tier: "suspected", top_confidence: 0.99, signal_count: 9 });
    expect(deriveRca(c, [])).toBe("Suspected");
  });

  it("maps confirmed verdict → Confirmed", () => {
    expect(deriveRca(corrObject({ verdict_tier: "confirmed" }), [])).toBe("Confirmed");
  });

  it("recovered/closed lifecycle → Resolved regardless of tier", () => {
    expect(deriveRca(corrObject({ state: "recovered", verdict_tier: "confirmed" }), [])).toBe("Resolved");
    expect(deriveRca(corrObject({ state: "closed" }), [])).toBe("Resolved");
  });

  it("suspected with ≥3 missing streams → Blocked", () => {
    const c = corrObject({ verdict_tier: "suspected" });
    expect(deriveRca(c, ["a", "b", "c"])).toBe("Blocked");
    expect(deriveRca(c, ["a", "b"])).toBe("Suspected");
  });

  it("undetermined splits on correlation breadth", () => {
    expect(deriveRca(corrObject({ verdict_tier: "undetermined", signal_count: 4 }), [])).toBe("Correlated");
    expect(deriveRca(corrObject({ verdict_tier: "undetermined", signal_count: 1 }), [])).toBe("RCA running");
  });
});

describe("evidence + ticket gating", () => {
  it("single-signal object is Single-stream (never Complete)", () => {
    expect(deriveEvidence(corrObject({ signal_count: 1 }), [])).toBe("Single-stream");
  });

  it("multi-signal: Complete iff nothing missing", () => {
    const c = corrObject({ signal_count: 3 });
    expect(deriveEvidence(c, [])).toBe("Complete");
    expect(deriveEvidence(c, ["probe"])).toBe("Partial");
  });

  it("a ticket is only NEEDED once RCA is Confirmed (no premature ITSM churn)", () => {
    expect(deriveTicket("Confirmed")).toBe("Ticket needed");
    expect(deriveTicket("Suspected")).toBe("Not eligible");
    expect(deriveTicket("Correlated")).toBe("Not eligible");
    expect(deriveTicket("Resolved")).toBe("Not eligible");
  });
});

describe("fault domain + owner", () => {
  it("owner field wins over topology heuristics", () => {
    expect(deriveFault(corrObject({ owner: "isp" }), parseAffected("{}"))).toBe("ISP / Carrier");
    expect(deriveFault(corrObject({ owner: "secops" }), parseAffected("{}"))).toBe("Security");
  });

  it("falls back to entity-name heuristics", () => {
    const aff = parseAffected('{"devices":["spine-1","leaf-2"]}');
    expect(deriveFault(corrObject({}), aff)).toBe("Data Center");
  });

  it("missing owner → Missing/Unassigned, present owner → recommendation", () => {
    expect(deriveOwner(corrObject({ owner: "" }))).toEqual({ state: "Missing", name: "Unassigned" });
    expect(deriveOwner(corrObject({ owner: "unknown" })).state).toBe("Missing");
    expect(deriveOwner(corrObject({ owner: "isp" })).state).toBe("Recommended");
  });
});

describe("severity + sort", () => {
  it("Confirmed → crit; suspect/blocked → major; confidence splits the rest", () => {
    expect(deriveSev(corrObject({}), "Confirmed")).toBe("crit");
    expect(deriveSev(corrObject({}), "Suspected")).toBe("major");
    expect(deriveSev(corrObject({ top_confidence: 0.7 }), "Correlated")).toBe("warn");
    expect(deriveSev(corrObject({ top_confidence: 0.2 }), "Correlated")).toBe("ok");
  });

  it("sorts critical first, then newest within a severity", () => {
    const mk = (sev: ActionItem["sev"], ageMs: number) => ({ sev, ageMs } as ActionItem);
    const rows = [mk("ok", 10), mk("crit", 1_000), mk("crit", 9_000), mk("major", 5)];
    const sorted = [...rows].sort(bySeverityThenAge);
    expect(sorted.map((r) => r.sev)).toEqual(["crit", "crit", "major", "ok"]);
    // within crit, the OLDER (larger ageMs) comes first
    expect(sorted[0].ageMs).toBe(9_000);
  });
});

describe("triage ladders — the queue's semantic sort ranks", () => {
  // These back the Action Queue's sortable columns. The contract is ORDERING
  // (ascending = work-this-first), not the specific integers.
  const asc = (xs: number[]) => xs.every((v, i) => i === 0 || xs[i - 1] < v);

  it("severity ranks crit → major → warn → ok (NOT alphabetical)", () => {
    expect(asc([sevRank("crit"), sevRank("major"), sevRank("warn"), sevRank("ok")])).toBe(true);
    // The alphabetical trap: "ok" sorts before "warn" as a string, but a warning
    // must always outrank a benign row in the queue.
    expect(sevRank("warn")).toBeLessThan(sevRank("ok"));
  });

  it("RCA state ranks by triage urgency (NOT alphabetical)", () => {
    expect(asc([rcaRank("Confirmed"), rcaRank("Suspected"), rcaRank("Blocked"),
      rcaRank("Correlated"), rcaRank("RCA running"), rcaRank("New"), rcaRank("Resolved")])).toBe(true);
    // Lexically "Correlated" < "Suspected"; semantically it must not outrank it.
    expect(rcaRank("Suspected")).toBeLessThan(rcaRank("Correlated"));
    // A resolved incident never sits above live work.
    expect(rcaRank("Resolved")).toBeGreaterThan(rcaRank("Confirmed"));
  });

  it("evidence ranks weakest-first — the groups needing corroboration surface", () => {
    expect(asc([evidenceRank("Single-stream"), evidenceRank("Partial"), evidenceRank("Complete")])).toBe(true);
  });

  it("owner ranks the biggest gap first", () => {
    expect(asc([ownerRank("Missing"), ownerRank("Escalated"), ownerRank("Recommended"), ownerRank("Assigned")])).toBe(true);
  });

  it("ticket ranks the most ITSM-urgent first", () => {
    expect(asc([ticketRank("Sync failed"), ticketRank("Ticket needed"), ticketRank("Eligible"),
      ticketRank("Ticketed"), ticketRank("Not eligible")])).toBe(true);
  });

  it("bySeverityThenAge agrees with sevRank (one ladder, no disagreement)", () => {
    const mk = (sev: ActionItem["sev"]) => ({ sev, ageMs: 0 } as ActionItem);
    const sorted = [mk("ok"), mk("warn"), mk("crit"), mk("major")].sort(bySeverityThenAge);
    expect(sorted.map((r) => r.sev)).toEqual(["crit", "major", "warn", "ok"]);
  });
});

describe("startedAt — one timestamp source for both age and the date column", () => {
  it("prefers window_start, falls back to created_at, else empty", () => {
    expect(startedAt(corrObject({ window_start: "2026-06-22T11:00:00Z", created_at: "2026-06-01T00:00:00Z" })))
      .toBe("2026-06-22T11:00:00Z");
    expect(startedAt(corrObject({ window_start: "", created_at: "2026-06-01T00:00:00Z" })))
      .toBe("2026-06-01T00:00:00Z");
    expect(startedAt(corrObject({ window_start: "", created_at: "" }))).toBe("");
  });

  it("is the SAME instant ageMs is derived from (they can never disagree)", () => {
    const c = corrObject({ window_start: "", created_at: "2026-06-22T11:00:00Z" });
    expect(buildItem(c, NOW).ageMs).toBe(NOW - Date.parse(startedAt(c)));
  });
});

describe("isActionableCorr — the customer-facing queue filter", () => {
  it("drops un-correlated single-signal noise", () => {
    expect(isActionableCorr(corrObject({ verdict_tier: "undetermined", signal_count: 1 }))).toBe(false);
    expect(isActionableCorr(corrObject({ verdict_tier: "undetermined", signal_count: 2 }))).toBe(true);
  });

  it("EXCLUDES internal-stack objects (#76 — RCA is scoped to customer networks)", () => {
    const internal = corrObject({
      verdict_tier: "confirmed", signal_count: 5,
      affected: JSON.stringify({ devices: ["clickhouse", "redpanda", "vector"] }),
    });
    expect(isActionableCorr(internal)).toBe(false);
  });

  it("keeps a real customer-network confirmed incident", () => {
    const real = corrObject({
      verdict_tier: "confirmed", signal_count: 5,
      affected: JSON.stringify({ devices: ["leaf-1", "spine-2"] }),
    });
    expect(isActionableCorr(real)).toBe(true);
  });
});

describe("Action Queue filters", () => {
  // A small mixed queue.
  const mk = (over: Partial<ActionItem>): ActionItem => ({
    corr: {} as never, affected: { devices: [], paths: [], interfaces: [], sites: [] }, missing: [],
    sev: "warn", rca: "Correlated", evidence: "Partial", fault: "Unknown",
    owner: "Recommended", ownerName: "x", ticket: "Not eligible", nextAction: "", ageMs: 0,
    ...over,
  });
  const items = [
    mk({ rca: "Confirmed", sev: "crit", fault: "ISP / Carrier", evidence: "Complete", owner: "Missing", ticket: "Ticket needed" }),
    mk({ rca: "Suspected", sev: "major", fault: "SD-WAN", evidence: "Partial", owner: "Recommended" }),
    mk({ rca: "Correlated", sev: "ok", fault: "LAN", evidence: "Single-stream", owner: "Recommended" }),
  ];

  it("no constraints returns everything", () => {
    expect(filterItems(items, {})).toHaveLength(3);
    expect(filterItems(items, { rca: "all", sev: "all" })).toHaveLength(3);
  });

  it("filters by a single facet", () => {
    expect(filterItems(items, { rca: "Confirmed" })).toHaveLength(1);
    expect(filterItems(items, { sev: "ok" }).map((i) => i.fault)).toEqual(["LAN"]);
    expect(filterItems(items, { fault: "SD-WAN" })).toHaveLength(1);
    expect(filterItems(items, { evidence: "Single-stream" })).toHaveLength(1);
  });

  it("combines facets (AND)", () => {
    expect(filterItems(items, { rca: "Confirmed", fault: "SD-WAN" })).toHaveLength(0);
    expect(filterItems(items, { sev: "crit", evidence: "Complete" })).toHaveLength(1);
  });

  it("owner facet + untriaged match their KPIs exactly", () => {
    expect(filterItems(items, { owner: "Missing" })).toHaveLength(1);
    // Untriaged = Correlated / RCA running / New — the 'Correlated' row qualifies.
    expect(filterItems(items, { untriaged: true })).toHaveLength(1);
    expect(isUntriaged(mk({ rca: "Correlated" }))).toBe(true);
    expect(isUntriaged(mk({ rca: "RCA running" }))).toBe(true);
    expect(isUntriaged(mk({ rca: "Confirmed" }))).toBe(false);
    expect(activeFilterCount({ owner: "Missing", untriaged: true })).toBe(2);
  });

  it("needsAction selects missing-owner / ticket-needed / blocked", () => {
    expect(filterItems(items, { needsAction: true })).toHaveLength(1); // the Confirmed/Missing/Ticket one
    expect(needsAction(items[0])).toBe(true);
    expect(needsAction(items[1])).toBe(false);
    expect(needsAction(mk({ rca: "Blocked" }))).toBe(true);
  });

  it("activeFilterCount counts only constraining facets", () => {
    expect(activeFilterCount({})).toBe(0);
    expect(activeFilterCount({ rca: "all", sev: "all" })).toBe(0);
    expect(activeFilterCount({ rca: "Confirmed", needsAction: true })).toBe(2);
  });
});

describe("defensive parsing + buildItem", () => {
  it("malformed JSON never throws — degrades to empty", () => {
    expect(parseAffected("{not json")).toEqual({ devices: [], paths: [], interfaces: [], sites: [] });
    expect(parseMissing("nope")).toEqual([]);
    // non-string array members are filtered out
    expect(parseAffected('{"devices":["ok",5,null]}').devices).toEqual(["ok"]);
  });

  it("fmtAge is bounded and never negative/NaN", () => {
    expect(fmtAge(undefined, NOW)).toBe("—");
    expect(fmtAge("2026-06-22T11:30:00Z", NOW)).toBe("30m");
    expect(fmtAge("2026-06-22T13:00:00Z", NOW)).toBe("—"); // future → guarded
    expect(fmtAge("garbage", NOW)).toBe("—");
  });

  it("buildItem assembles a coherent confirmed item with a sensible next action", () => {
    const c = corrObject({
      verdict_tier: "confirmed", signal_count: 4, owner: "",
      affected: JSON.stringify({ devices: ["spine-1"] }),
      window_start: "2026-06-22T11:00:00Z",
    });
    const it = buildItem(c, NOW);
    expect(it.rca).toBe("Confirmed");
    expect(it.sev).toBe("crit");
    expect(it.owner).toBe("Missing");
    expect(it.ticket).toBe("Ticket needed");
    expect(it.nextAction).toBe("Assign owner · escalate");
    expect(it.ageMs).toBe(60 * 60 * 1000);
  });
});
