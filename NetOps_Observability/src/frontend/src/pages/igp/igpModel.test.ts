// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// igpModel tests — the pure half of the OSPF / IS-IS view. These lock in the
// one property the panel exists for: a source that was never collected must
// never be presentable as a zero, and "wired but quiet" must never be
// presentable as "not wired".

import { describe, expect, it } from "vitest";
import type {
  IgpAdjacenciesResponse,
  IgpAdjacency,
  IgpCoverage,
  IgpHealthResponse,
  IgpSummaryResponse,
} from "../../services/api";
import {
  adjCounts,
  adjKey,
  adjTone,
  areasCell,
  areasView,
  holdLabel,
  lsdbView,
  scopeLabelText,
  spfView,
  timerCell,
  timersView,
  classifyAdjacencies,
  classifyHealth,
  classifySummary,
  countOrNotCollected,
  coverageChips,
  currentStateLabel,
  igpError,
  igpLoading,
  isMeasured,
  stateSourceLabel,
  timelineTicks,
  windowLabel,
  worstFirst,
} from "./igpModel";

/** The default fixture coverage: the two adjacency sources answered and NONE
 *  of the four depth sources did — the honest baseline for a deployment that
 *  has not wired the LSDB/area/SPF/timer collectors. */
const NO_DEPTH_COVERAGE: IgpCoverage = {
  events: true,
  live_series: true,
  lsdb: false,
  areas: false,
  spf_runs: false,
  timers: false,
};

const adjacency = (over: Partial<IgpAdjacency> = {}): IgpAdjacency => ({
  device: "leaf1",
  peer: "0000.0000.0002",
  ifname: "ethernet-1/1",
  current_state: "up",
  state_source: "live_series",
  up: true,
  flaps: 0,
  changes: 0,
  up_events: 0,
  down_events: 0,
  hold_seconds: null,
  timeline: [],
  ...over,
});

const adjResponse = (over: Partial<IgpAdjacenciesResponse> = {}): IgpAdjacenciesResponse => ({
  protocol: "isis",
  device: "",
  window_seconds: 86400,
  since: "2026-09-01T12:00:00Z",
  now: "2026-09-02T12:00:00Z",
  adjacencies: [],
  event_count: 0,
  lsdb: { lsp_count: null },
  areas: { areas: null },
  spf_runs: { runs: null },
  timers: { rows: null },
  coverage: NO_DEPTH_COVERAGE,
  source: "events+live_series",
  notes: [],
  limit: 200,
  truncated: false,
  next_cursor: "",
  ...over,
});

describe("countOrNotCollected — the anti-zero rule", () => {
  it("renders a real measurement, including a real zero", () => {
    expect(countOrNotCollected(0)).toBe("0");
    expect(countOrNotCollected(7)).toBe("7");
  });
  it("renders an ABSENT measurement as a phrase, never as a digit", () => {
    expect(countOrNotCollected(null)).toBe("not collected");
    expect(countOrNotCollected(undefined)).toBe("not collected");
    expect(countOrNotCollected(null)).not.toMatch(/\d/);
  });
  it("only a real measurement is `measured`, so only it can be coloured", () => {
    expect(isMeasured(0)).toBe(true);
    expect(isMeasured(null)).toBe(false);
    expect(isMeasured(undefined)).toBe(false);
  });
});

describe("coverageChips", () => {
  it("reports each class and carries the SERVER's reason for an absent one", () => {
    const chips = coverageChips(
      { ...NO_DEPTH_COVERAGE, live_series: false },
      [
        "no live series collected for this device; adjacency history is from syslog/trap events only",
        "no LSDB/LSP-count series is collected for these devices (device_isis_lsp_count …)",
        "IS-IS area addresses are not collected for these devices (device_isis_area …)",
        "no SPF-run counter is collected for these devices (device_isis_spf_runs_total …)",
        "no IS-IS timer series is collected for these devices (device_isis_adj_hold_seconds …)",
      ],
    );
    // Six chips, because the four depth sources are probed and reported
    // independently: one flag for all of them would say something is missing
    // without saying what.
    expect(chips.map((c) => [c.id, c.collected])).toEqual([
      ["events", true],
      ["live_series", false],
      ["lsdb", false],
      ["areas", false],
      ["spf_runs", false],
      ["timers", false],
    ]);
    expect(chips[1].detail).toContain("syslog/trap events only");
    expect(chips[2].detail).toContain("device_isis_lsp_count");
    expect(chips[3].detail).toContain("device_isis_area");
    expect(chips[4].detail).toContain("device_isis_spf_runs_total");
    expect(chips[5].detail).toContain("device_isis_adj_hold_seconds");
  });
  it("falls back to an honest sentence when the server sent no note", () => {
    const chips = coverageChips({ ...NO_DEPTH_COVERAGE, events: false, live_series: false }, []);
    for (const c of chips) {
      expect(c.collected).toBe(false);
      expect(c.detail.length).toBeGreaterThan(0);
      expect(c.detail).not.toMatch(/healthy|all clear/i);
    }
  });
  it("treats a missing coverage block as nothing collected — never as everything fine", () => {
    const chips = coverageChips(undefined, undefined);
    expect(chips.every((c) => !c.collected)).toBe(true);
  });
});

describe("classifyAdjacencies", () => {
  it("is not_connected when NEITHER evidence class answered", () => {
    const r = classifyAdjacencies(adjResponse({
      coverage: { events: false, live_series: false, lsdb: false },
      notes: ["no live series collected for this device"],
    }));
    expect(r.state).toBe("not_connected");
    expect(r.note).toContain("not observed on this deployment");
    expect(r.note).toContain("no live series collected");
  });
  it("is EMPTY — not not_connected — when a source answered and the window was quiet", () => {
    const r = classifyAdjacencies(adjResponse({ adjacencies: [] }));
    expect(r.state).toBe("empty");
    expect(r.note).toContain("The sources answered");
    expect(r.data).toBeDefined(); // the coverage strip still renders
  });
  it("is ready with rows", () => {
    const r = classifyAdjacencies(adjResponse({ adjacencies: [adjacency()] }));
    expect(r.state).toBe("ready");
    expect(r.data?.adjacencies).toHaveLength(1);
  });
  it("a missing payload is an error, never an empty list", () => {
    expect(classifyAdjacencies(undefined).state).toBe("error");
  });
});

describe("classifySummary / classifyHealth", () => {
  const summary = (over: Partial<IgpSummaryResponse> = {}): IgpSummaryResponse => ({
    protocol: "ospf",
    window_seconds: 3600,
    since: "s",
    now: "n",
    devices: [],
    event_count: 0,
    coverage: { ...NO_DEPTH_COVERAGE, live_series: false },
    source: "events",
    notes: [],
    limit: 100,
    truncated: false,
    ...over,
  });
  const health = (over: Partial<IgpHealthResponse> = {}): IgpHealthResponse => ({
    protocol: "ospf",
    device: "r1",
    device_name: "r1",
    window_seconds: 3600,
    since: "s",
    now: "n",
    levels: null,
    neighbor_count: null,
    adjacencies_up: null,
    adjacencies_down: null,
    adjacency_changes: 0,
    flaps: 0,
    last_change: "",
    stability: { flaps_per_hour: 0, score: 100, basis: "0 adjacency down-transitions over 1h" },
    lsdb: { lsp_count: null, note: "no LSDB series" },
    areas: { areas: null, note: "no area series" },
    spf_runs: { runs: null, note: "no SPF series" },
    timers: { rows: null, note: "no timer series" },
    coverage: { ...NO_DEPTH_COVERAGE, live_series: false },
    source: "events",
    notes: [],
    ...over,
  });

  it("summary: empty when answered-and-quiet, not_connected when nothing answered", () => {
    expect(classifySummary(summary()).state).toBe("empty");
    expect(classifySummary(summary({ devices: [{ device: "r1", flaps: 1, changes: 1, up_events: 0, down_events: 1, adjacencies: null, down_adjacencies: null } ] })).state).toBe("ready");
    expect(classifySummary(summary({ coverage: { events: false, live_series: false, lsdb: false } })).state).toBe("not_connected");
    expect(classifySummary(undefined).state).toBe("error");
  });

  it("health stays READY with nulls — blanking it would hide exactly what it says", () => {
    const r = classifyHealth(health());
    expect(r.state).toBe("ready");
    expect(r.data?.neighbor_count).toBeNull();
  });
  it("health is not_connected only when no source answered at all", () => {
    expect(classifyHealth(health({ coverage: { events: false, live_series: false, lsdb: false } })).state)
      .toBe("not_connected");
    expect(classifyHealth(undefined).state).toBe("error");
  });
});

describe("igpLoading / igpError", () => {
  it("loading carries no data", () => {
    expect(igpLoading().state).toBe("loading");
    expect(igpLoading().data).toBeUndefined();
  });
  it("a rejected fetch is an ERROR carrying the message — never a reassuring blank", () => {
    const r = igpError(new Error("503 Service Unavailable"));
    expect(r.state).toBe("error");
    expect(r.note).toContain("503 Service Unavailable");
    expect(r.data).toBeUndefined();
    expect(igpError("boom").note).toContain("boom");
    expect(igpError(undefined).state).toBe("error");
  });
});

describe("adjTone / stateSourceLabel / currentStateLabel", () => {
  it("colours ONLY a live verdict", () => {
    expect(adjTone(adjacency({ up: true }))).toBe("good");
    expect(adjTone(adjacency({ up: false }))).toBe("bad");
  });
  it("gives an event-only adjacency NO colour — history is not the state now", () => {
    expect(adjTone(adjacency({ state_source: "events", up: null }))).toBe("");
    expect(adjTone(adjacency({ state_source: "none", up: null }))).toBe("");
    // even if a server ever sent a stale `up` alongside an events source
    expect(adjTone({ state_source: "events", up: true })).toBe("");
  });
  it("names where the state came from", () => {
    expect(stateSourceLabel({ state_source: "live_series" })).toBe("live");
    expect(stateSourceLabel({ state_source: "events", last_change: "2026-09-02T10:00:00Z" })).toBe("last reported");
    expect(stateSourceLabel({ state_source: "events" })).toBe("reported");
    expect(stateSourceLabel({ state_source: "none" })).toBe("not reported");
  });
  it("renders an absent state as a phrase", () => {
    expect(currentStateLabel({ current_state: "full" })).toBe("full");
    expect(currentStateLabel({ current_state: null })).toBe("not reported");
    expect(currentStateLabel({ current_state: "  " })).toBe("not reported");
  });
});

describe("adjCounts", () => {
  const rows = [
    adjacency({ peer: "a", up: true, flaps: 1 }),
    adjacency({ peer: "b", up: false, flaps: 2 }),
    adjacency({ peer: "c", state_source: "events", up: null, flaps: 3 }),
  ];
  it("counts up/down ONLY from live rows when a live series exists", () => {
    const c = adjCounts(rows, true);
    expect(c).toEqual({ reported: 3, live: 2, up: 1, down: 1, flaps: 6 });
  });
  it("returns NULL up/down when no live series backs them — never 0", () => {
    const c = adjCounts(rows, false);
    expect(c.up).toBeNull();
    expect(c.down).toBeNull();
    expect(c.live).toBeNull();
    expect(c.reported).toBe(3); // heard about, which IS measurable
    expect(c.flaps).toBe(6);
  });
  it("tolerates an absent list", () => {
    expect(adjCounts(undefined, true)).toEqual({ reported: 0, live: 0, up: 0, down: 0, flaps: 0 });
    expect(adjCounts(undefined, false).up).toBeNull();
  });
});

describe("worstFirst", () => {
  it("puts live-down adjacencies first, then the most flaps", () => {
    const rows = [
      adjacency({ device: "a", peer: "1", up: true, flaps: 0 }),
      adjacency({ device: "b", peer: "2", up: true, flaps: 5 }),
      adjacency({ device: "c", peer: "3", up: false, flaps: 1 }),
    ];
    expect(worstFirst(rows).map((r) => r.device)).toEqual(["c", "b", "a"]);
  });
  it("is stable on ties and does not mutate the input", () => {
    const rows = [adjacency({ device: "z", peer: "1" }), adjacency({ device: "a", peer: "2" })];
    const out = worstFirst(rows);
    expect(out.map((r) => r.device)).toEqual(["a", "z"]);
    expect(rows[0].device).toBe("z");
    expect(worstFirst([])).toEqual([]);
  });
});

describe("timelineTicks", () => {
  const ev = (id: string, state: "up" | "down") => ({
    ts: `2026-09-02T10:0${id}:00Z`, signal_id: id, device: "leaf1", state,
    severity: "warn", source: "syslog",
  });
  it("reverses the newest-first feed into oldest→newest and caps it", () => {
    const a = adjacency({ timeline: [ev("3", "up"), ev("2", "down"), ev("1", "up")] });
    expect(timelineTicks(a).map((t) => t.key)).toEqual(["1", "2", "3"]);
    expect(timelineTicks(a, 2).map((t) => t.key)).toEqual(["2", "3"]); // the 2 NEWEST, oldest-first
  });
  it("an adjacency with no history has no ticks — not a fabricated one", () => {
    expect(timelineTicks(adjacency({ timeline: [] }))).toEqual([]);
    expect(timelineTicks({ timeline: undefined as never })).toEqual([]);
  });
});

describe("windowLabel / adjKey", () => {
  it("renders the HONORED window the server reported", () => {
    expect(windowLabel(3600)).toBe("1h");
    expect(windowLabel(86400)).toBe("1d");
    expect(windowLabel(604800)).toBe("7d");
    expect(windowLabel(5400)).toBe("90m");
    expect(windowLabel(45)).toBe("45s");
    expect(windowLabel(0)).toBe("—");
    expect(windowLabel(undefined)).toBe("—");
  });
  it("keys a row on (device, peer)", () => {
    expect(adjKey({ device: "a", peer: "b" })).toBe("a b");
    expect(adjKey({ device: "a" })).toBe("a ");
  });
});

// ── the advanced depth views (LSDB · areas · SPF runs · timers) ─────────────
//
// One property, four blocks: a source that was not collected renders the word
// "not collected" and the server's reason — never a number, never a dash that
// could pass for a measurement, and never a green tone.

describe("lsdbView / spfView", () => {
  it("renders a collected count with its per-scope breakdown", () => {
    const v = lsdbView(
      { lsp_count: 8, scope_label: "isis_level", by_scope: [{ scope: "L1", count: 2 }, { scope: "L2", count: 6 }] },
      true,
    );
    expect(v.collected).toBe(true);
    expect(v.value).toBe("8");
    expect(v.scopeLabel).toBe("level");
    expect(v.scopes).toHaveLength(2);
    expect(v.note).toBe("");
  });
  it("a count of ZERO is a measurement and stays a number", () => {
    const v = lsdbView({ lsp_count: 0 }, true);
    expect(v.collected).toBe(true);
    expect(v.value).toBe("0");
  });
  it("an uncollected count is the phrase, never 0, and carries the server's reason", () => {
    const v = lsdbView({ lsp_count: null, note: "no LSDB/LSP-count series (device_ospf_lsdb_count …)" }, false);
    expect(v.collected).toBe(false);
    expect(v.value).toBe("not collected");
    expect(v.value).not.toMatch(/^\d/);
    expect(v.note).toContain("device_ospf_lsdb_count");
    expect(v.scopes).toEqual([]);
  });
  it("a coverage flag that disagrees with the payload resolves to NOT collected", () => {
    // The flag says covered, the value is null. Rendering "null" as a number is
    // the exact failure this view exists to prevent, so the safe reading wins.
    expect(lsdbView({ lsp_count: null }, true).collected).toBe(false);
    // And the reverse: a value with the flag off is not promoted to a fact.
    expect(lsdbView({ lsp_count: 9 }, false).collected).toBe(false);
  });
  it("falls back to its own sentence when the server sent no note", () => {
    expect(lsdbView(undefined, false).note.length).toBeGreaterThan(0);
    expect(spfView(undefined, false).note.length).toBeGreaterThan(0);
  });
  it("SPF runs are reported as the counter value, never converted to a rate", () => {
    const v = spfView({ runs: 10, scope_label: "area", by_scope: [{ scope: "0.0.0.0", count: 10 }] }, true);
    expect(v.value).toBe("10");
    expect(v.scopeLabel).toBe("area");
    expect(v.value).not.toMatch(/\/|per|hour/i);
  });
});

describe("scopeLabelText", () => {
  it("renders the raw series label as the operator's word", () => {
    expect(scopeLabelText("isis_level")).toBe("level");
    expect(scopeLabelText("area")).toBe("area");
  });
  it("passes an unknown label through rather than inventing one", () => {
    expect(scopeLabelText("something_new")).toBe("something_new");
    expect(scopeLabelText(undefined)).toBe("scope");
  });
});

describe("areasView", () => {
  it("lists the collected areas", () => {
    const v = areasView({ areas: ["49.0001", "49.0002"] }, true);
    expect(v.collected).toBe(true);
    expect(v.areas).toEqual(["49.0001", "49.0002"]);
    expect(v.value).toBe("49.0001, 49.0002");
  });
  it("null membership is 'not collected' with the server's reason", () => {
    const v = areasView({ areas: null, note: "OSPF area membership is not collected (device_ospf_area …)" }, false);
    expect(v.collected).toBe(false);
    expect(v.value).toBe("not collected");
    expect(v.note).toContain("device_ospf_area");
  });
  it("an EMPTY list is not 'member of no area' — that is not a state a router can be in", () => {
    const v = areasView({ areas: [] }, true);
    expect(v.collected).toBe(false);
    expect(v.value).toBe("not collected");
  });
});

describe("timersView", () => {
  const isisBlock = {
    scope_kind: "adjacency" as const,
    rows: [{ device: "spine1", scope: "0100.0000.0011", ifname: "ethernet-1/1.0", level: "L2", hold_seconds: 27 }],
  };
  it("IS-IS timers are per adjacency and carry the countdown caveat", () => {
    const v = timersView(isisBlock, true, "isis");
    expect(v.collected).toBe(true);
    expect(v.kind).toBe("adjacency");
    expect(v.scopeHeading).toBe("Neighbour");
    expect(v.rows).toHaveLength(1);
    // The caveat is load-bearing: without it a mid-range countdown reads as a
    // configured interval and a low one reads as an emergency.
    expect(v.caveat).toMatch(/countdown/i);
    expect(v.caveat).toMatch(/not a configured interval/i);
  });
  it("OSPF timers are per interface and carry NO countdown caveat — they are configured intervals", () => {
    const v = timersView(
      { scope_kind: "interface", rows: [{ device: "edge1", scope: "10.0.0.1.0", hello_seconds: 10, dead_seconds: 40 }] },
      true, "ospf",
    );
    expect(v.kind).toBe("interface");
    expect(v.scopeHeading).toBe("Interface");
    expect(v.caveat).toBe("");
  });
  it("absent timers report the server's reason and no rows", () => {
    const v = timersView({ rows: null, note: "no IS-IS timer series (device_isis_adj_hold_seconds …)" }, false, "isis");
    expect(v.collected).toBe(false);
    expect(v.rows).toEqual([]);
    expect(v.note).toContain("device_isis_adj_hold_seconds");
  });
  it("falls back to the protocol's own shape when the server sent no scope_kind", () => {
    expect(timersView({ rows: [] }, true, "isis").kind).toBe("adjacency");
    expect(timersView({ rows: [] }, true, "ospf").kind).toBe("interface");
  });
});

describe("timerCell / holdLabel / areasCell", () => {
  it("a measured timer keeps its unit; an absent one is a dash, never 0", () => {
    expect(timerCell(27)).toBe("27s");
    // 0 IS a measurement — an adjacency genuinely expiring — and must show.
    expect(timerCell(0)).toBe("0s");
    expect(timerCell(null)).toBe("—");
    expect(timerCell(undefined)).toBe("—");
  });
  it("an adjacency with no hold sample says so instead of showing 0", () => {
    expect(holdLabel({ hold_seconds: 27 })).toBe("27s");
    expect(holdLabel({ hold_seconds: null })).toBe("not collected");
  });
  it("a device with no area series says so instead of showing an empty cell", () => {
    expect(areasCell(["0.0.0.0"])).toBe("0.0.0.0");
    expect(areasCell([])).toBe("not collected");
    expect(areasCell(null)).toBe("not collected");
  });
});
