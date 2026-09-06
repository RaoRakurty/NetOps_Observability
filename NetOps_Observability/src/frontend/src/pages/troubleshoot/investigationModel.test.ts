// investigationModel.test.ts — the pure model behind the symptom-first
// Troubleshooting investigation surface (Project 4 §A).
//
// The contract this file exists to defend is HONESTY: a lane classifier must
// never collapse "the source was never wired" (not_connected) into "the source
// is wired and was quiet" (empty). Those are different facts — the first means
// we cannot see, the second means we looked. Every classifier is therefore
// tested with BOTH answers, and a cross-cutting table asserts the two states
// stay distinct with distinct operator sentences.

import { describe, it, expect } from "vitest";
import type { FeedItem, PathHealthItem, ProbePath, PromInstantSeries } from "../../services/api";
import {
  ALL_LANES,
  DEVICE_CONFIG_CHANGE_KIND,
  HOW_IT_WORKS,
  LADDER,
  PLAIN_LADDER,
  LANE_SOURCE,
  LANE_TITLE,
  SYMPTOMS,
  bisectingHeadline,
  buildLadder,
  buildPlainLadder,
  changeLabel,
  classifyChangeLane,
  classifyDemLane,
  classifyEventsLane,
  classifyFlowLane,
  classifyMetricLane,
  classifyPathLane,
  isConfigChangeKind,
  laneError,
  laneIsQuiet,
  laneLoading,
  laneSummary,
  lanesForSymptom,
  parseInvestigationHash,
  plainAnswer,
  plainOwner,
  symptomById,
  type LaneId,
  type LaneState,
  type SymptomId,
} from "./investigationModel";

// ── fixtures ─────────────────────────────────────────────────────────────────

const feed = (over: Partial<FeedItem> = {}): FeedItem => ({
  signal_id: "sig-1", ts: "2026-08-25 10:00:00", source: "lab", kind: "link_down",
  severity: "warning", entity_type: "device", entity_id: "wan-r1", site: "dc1",
  title: "Link down", correlation_id: null, ...over,
});

const pathHealth = (over: Partial<PathHealthItem> = {}): PathHealthItem => ({
  path_id: "p1", agent: "probe-a", dst: "10.0.0.1", health_state: "degraded", score: 40,
  confidence: "medium", severities: {}, baseline_source: "rolling", reason: "loss above baseline",
  likely_fault_domain: "wan", evidence: [],
  current: { latency_p95_5m: 30, jitter_p95_5m: 3, loss_pct_5m: 1 },
  baseline: { source: "rolling", source_label: "7d", window: "7d", sample_count: 100, latency_p50: 20, latency_p99: 40, jitter_p50: 2, jitter_p99: 5 },
  ...over,
});

const probePath = (over: Partial<ProbePath> = {}): ProbePath =>
  ({ dst: "10.0.0.1", method: "icmp", hops: [], reached: true, changed: false, ts: "2026-08-25 10:00:00", ...over });

const series = (device: string): PromInstantSeries => ({ metric: { device }, value: [0, "1"] });

// ── the nine canonical NOC workflows ─────────────────────────────────────────

describe("SYMPTOMS — the nine canonical NOC workflows", () => {
  it("carries exactly nine workflows with unique ids and labels", () => {
    expect(SYMPTOMS).toHaveLength(9);
    expect(new Set(SYMPTOMS.map((s) => s.id)).size).toBe(9);
    expect(new Set(SYMPTOMS.map((s) => s.label)).size).toBe(9);
  });

  it("gives every workflow an operator label and a bisection hint", () => {
    for (const s of SYMPTOMS) {
      expect(s.label.trim().length).toBeGreaterThan(0);
      expect(s.hint.trim().length).toBeGreaterThan(0);
    }
  });

  // The lanes each workflow opens, straight from the design of record
  // (docs/design/research/TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md §a).
  const expected: [SymptomId, LaneId[]][] = [
    ["app_slow", ["dem", "path", "changed", "flows", "health", "events"]],
    ["site_down", ["health", "path", "changed", "events", "routing"]],
    ["link_interface", ["health", "flows", "changed", "events"]],
    ["routing_adjacency", ["routing", "health", "changed", "events"]],
    ["bgp_upstream", ["routing", "path", "changed", "events", "dem"]],
    ["dns", ["dem", "changed", "events", "flows"]],
    ["wireless", ["dem", "health", "events", "changed"]],
    ["cloud_saas", ["dem", "changed", "path", "events", "flows"]],
    ["security_exposure", ["events", "changed", "flows", "health"]],
  ];

  it.each(expected)("%s opens exactly the lanes its workflow needs", (id, lanes) => {
    expect(lanesForSymptom(id)).toEqual(lanes);
  });

  it("never opens a lane twice, and only opens lanes that exist", () => {
    for (const s of SYMPTOMS) {
      expect(new Set(s.lanes).size).toBe(s.lanes.length);
      for (const l of s.lanes) expect(ALL_LANES).toContain(l);
    }
  });

  it("every workflow opens the change lane or the event lane (change awareness)", () => {
    for (const s of SYMPTOMS) {
      expect(s.lanes.some((l) => l === "changed" || l === "events")).toBe(true);
    }
  });

  it("titles and sources are defined for every lane, and each source names an API path", () => {
    for (const l of ALL_LANES) {
      expect(LANE_TITLE[l]?.trim().length).toBeGreaterThan(0);
      expect(LANE_SOURCE[l]).toMatch(/^\/api\//);
    }
  });
});

describe("symptomById / lanesForSymptom", () => {
  it("resolves a known id", () => {
    expect(symptomById("dns")?.label).toBe("DNS, DHCP or authentication is failing");
  });

  it.each([["", null], ["nope", null], [null, null], [undefined, null]] as const)(
    "returns null for %p", (input) => { expect(symptomById(input as string | null)).toBeNull(); },
  );

  it("an unknown symptom opens EVERY lane — never fewer", () => {
    expect(lanesForSymptom(null)).toEqual(ALL_LANES);
    expect(lanesForSymptom("not-a-symptom")).toEqual(ALL_LANES);
    expect(lanesForSymptom(undefined)).toEqual(ALL_LANES);
  });
});

// ── the bisection ladder ─────────────────────────────────────────────────────

describe("buildLadder", () => {
  const byId = (rungs: ReturnType<typeof buildLadder>) =>
    Object.fromEntries(rungs.map((r) => [r.id, r.state]));

  it("keeps the layer order physical → L2 → IGP → BGP → path → application → logs", () => {
    expect(buildLadder(ALL_LANES, {}).map((r) => r.id)).toEqual([
      "physical", "l2", "igp", "bgp", "path", "application", "logs",
    ]);
    expect(LADDER.map((l) => l.id)).toEqual(buildLadder(ALL_LANES, {}).map((r) => r.id));
  });

  it("marks a rung not_opened when the symptom opened none of its lanes", () => {
    // routing_adjacency opens routing/health/changed/events — no path, no dem, no flows.
    const st = byId(buildLadder(lanesForSymptom("routing_adjacency"), {}));
    expect(st.path).toBe("not_opened");
    expect(st.physical).not.toBe("not_opened");
  });

  it("reports checking — never 'nothing observed' — while a lane is in flight", () => {
    const rungs = buildLadder(["routing"], { routing: "loading" });
    expect(rungs.find((r) => r.id === "igp")?.state).toBe("checking");
    // a lane that has not reported at all is equally unmeasured
    expect(buildLadder(["routing"], {})[2].state).toBe("checking");
  });

  it("marks a rung has_data as soon as ONE of its lanes returned rows", () => {
    const st = byId(buildLadder(ALL_LANES, { health: "ready", events: "empty" }));
    expect(st.physical).toBe("has_data");
    expect(st.l2).toBe("has_data"); // health OR events answers L2
  });

  it("marks a rung not_connected only when EVERY opened lane for it is unwired", () => {
    expect(byId(buildLadder(ALL_LANES, { path: "not_connected", dem: "not_connected" })).path)
      .toBe("not_connected");
    // one unwired, one merely quiet → we did look, so it is not "no source"
    expect(byId(buildLadder(ALL_LANES, { path: "not_connected", dem: "empty" })).path)
      .toBe("no_data");
  });

  it("marks a rung no_data when its lanes looked and saw nothing", () => {
    expect(byId(buildLadder(ALL_LANES, { routing: "empty" })).igp).toBe("no_data");
    expect(byId(buildLadder(ALL_LANES, { routing: "error" })).bgp).toBe("no_data");
  });

  it("gives every rung a non-empty operator note", () => {
    const states: Partial<Record<LaneId, LaneState>> = {
      dem: "ready", changed: "empty", health: "not_connected", path: "loading",
      routing: "error", flows: "not_connected", events: "ready",
    };
    for (const r of buildLadder(lanesForSymptom("app_slow"), states)) {
      expect(r.note.trim().length).toBeGreaterThan(0);
      expect(r.label.trim().length).toBeGreaterThan(0);
    }
  });

  it("never claims a rung is answered merely because its lane is on screen", () => {
    const rungs = buildLadder(ALL_LANES, {});
    expect(rungs.every((r) => r.state !== "has_data")).toBe(true);
  });
});

// ── the honesty contract: not_connected is never collapsed into empty ────────

describe("lane classifiers — not_connected vs empty are never collapsed", () => {
  it("DEM: no path ever reported = not connected (never a healthy blank)", () => {
    const r = classifyDemLane([]);
    expect(r.state).toBe("not_connected");
    expect(r.note).toMatch(/probe/i);
    expect(r.rows).toEqual([]);
  });

  it("DEM: reported paths are ready, worst score first", () => {
    const r = classifyDemLane([pathHealth({ path_id: "ok", score: 90 }), pathHealth({ path_id: "bad", score: 10 })]);
    expect(r.state).toBe("ready");
    expect(r.rows.map((p) => p.path_id)).toEqual(["bad", "ok"]);
    expect(r.note).toBe("");
  });

  it("path: no traceroute recorded = not connected; recorded = ready", () => {
    expect(classifyPathLane([]).state).toBe("not_connected");
    expect(classifyPathLane([]).note).toMatch(/traceroute/i);
    const ready = classifyPathLane([probePath()]);
    expect(ready.state).toBe("ready");
    expect(ready.rows).toHaveLength(1);
  });

  it("flows: no exporter = not connected; exporter but no conversation = empty", () => {
    const unwired = classifyFlowLane([], []);
    expect(unwired.state).toBe("not_connected");
    expect(unwired.note).toMatch(/exporter/i);

    const zeroExporters = classifyFlowLane([{ flow_type: "netflow", flows: 0, exporters: 0 }], []);
    expect(zeroExporters.state).toBe("not_connected");

    const quiet = classifyFlowLane([{ flow_type: "netflow", flows: 12, exporters: 2 }], []);
    expect(quiet.state).toBe("empty");
    expect(quiet.note).toMatch(/sending/i);

    const ready = classifyFlowLane([{ flow_type: "netflow", flows: 12, exporters: 2 }], [{ a: 1 }]);
    expect(ready.state).toBe("ready");
    expect(ready.rows).toHaveLength(1);
  });

  it("metrics: a family never scraped = not connected; scraped but no match = empty", () => {
    const note = "No device metric has ever been scraped.";
    const unwired = classifyMetricLane([], ["device_if_oper_status"], [], note);
    expect(unwired.state).toBe("not_connected");
    expect(unwired.note).toBe(note); // the caller's sentence, verbatim

    const quiet = classifyMetricLane(["device_if_oper_status"], ["device_if_oper_status"], [], note);
    expect(quiet.state).toBe("empty");
    expect(quiet.note).not.toBe(note);

    const ready = classifyMetricLane(["device_if_oper_status"], ["device_if_oper_status"], [series("r1")], note);
    expect(ready.state).toBe("ready");
    expect(ready.rows).toHaveLength(1);
  });

  it("metrics: ANY of the wanted families being known is enough to be wired", () => {
    const r = classifyMetricLane(["device_isis_adj_state"], ["device_bgp_peer_state", "device_isis_adj_state"], [], "x");
    expect(r.state).toBe("empty");
  });

  it("changes: the event store is always wired, so no rows is EMPTY, never not_connected", () => {
    const r = classifyChangeLane([]);
    expect(r.state).toBe("empty");
    expect(r.state).not.toBe("not_connected");
    expect(r.note).toMatch(/no change/i);
  });

  it("changes: configuration changes sort ahead of state changes", () => {
    const r = classifyChangeLane([
      feed({ signal_id: "a", kind: "link_down" }),
      feed({ signal_id: "b", kind: DEVICE_CONFIG_CHANGE_KIND }),
      feed({ signal_id: "c", kind: "cloud_change" }),
    ]);
    expect(r.state).toBe("ready");
    expect(r.rows.map((i) => i.signal_id)).toEqual(["b", "c", "a"]);
  });

  it("changes: classify does not mutate the caller's array", () => {
    const input = [feed({ signal_id: "a", kind: "link_down" }), feed({ signal_id: "b", kind: "config_change" })];
    classifyChangeLane(input);
    expect(input.map((i) => i.signal_id)).toEqual(["a", "b"]);
  });

  it("events: the feed is wired, so no rows is EMPTY", () => {
    expect(classifyEventsLane([]).state).toBe("empty");
    expect(classifyEventsLane([feed()]).state).toBe("ready");
  });

  // The cross-cutting invariant, stated once: for every source that CAN be
  // unwired, the two answers must land on different states with different words.
  it.each([
    ["dem", () => classifyDemLane([]), () => classifyDemLane([pathHealth()])],
    ["path", () => classifyPathLane([]), () => classifyPathLane([probePath()])],
    ["flows", () => classifyFlowLane([], []), () => classifyFlowLane([{ flow_type: "n", flows: 1, exporters: 1 }], [])],
    ["metrics", () => classifyMetricLane([], ["m"], [], "unwired"), () => classifyMetricLane(["m"], ["m"], [], "unwired")],
  ] as const)("%s never renders the same sentence for unwired and quiet", (_name, unwired, wired) => {
    const a = unwired();
    const b = wired();
    expect(a.state).toBe("not_connected");
    expect(b.state).not.toBe("not_connected");
    expect(a.note).not.toBe(b.note);
    expect(a.note.trim().length).toBeGreaterThan(0);
    expect(b.note.trim().length + (b.state === "ready" ? 1 : 0)).toBeGreaterThan(0);
  });
});

describe("lane state helpers", () => {
  it("laneLoading is loading with no rows and a note", () => {
    const r = laneLoading<number>();
    expect(r).toEqual({ state: "loading", note: "Loading…", rows: [] });
  });

  it("laneError carries the message verbatim", () => {
    expect(laneError<number>("boom: 503")).toEqual({ state: "error", note: "boom: 503", rows: [] });
  });
});

// ── change vocabulary ────────────────────────────────────────────────────────

describe("change vocabulary", () => {
  it.each(["device_config_change", "config_change", "cloud_change", "cloud_audit"])(
    "%s is a configuration change", (k) => { expect(isConfigChangeKind(k)).toBe(true); },
  );

  it.each(["link_down", "bgp_state_anomaly", "", "  "])(
    "%p is not a configuration change", (k) => { expect(isConfigChangeKind(k)).toBe(false); },
  );

  it("spells a device config change out in operator words", () => {
    expect(changeLabel("device_config_change")).toBe("Configuration change");
    expect(changeLabel(" config_change ")).toBe("Configuration change");
  });

  it("keeps the shared RCA vocabulary for every other kind", () => {
    expect(changeLabel("link_down")).not.toBe("Configuration change");
    expect(changeLabel("link_down").length).toBeGreaterThan(0);
  });
});

// ── the honest symptom-only header ───────────────────────────────────────────

describe("bisectingHeadline", () => {
  it("asks the question when nothing has been picked", () => {
    const h = bisectingHeadline(null);
    expect(h.title).toBe("What's wrong?");
    expect(h.sub).toMatch(/pick a problem or an open case/i);
  });

  it("states plainly that we do not have the cause yet", () => {
    const h = bisectingHeadline(symptomById("bgp_upstream"));
    expect(h.title).toBe("BGP or an upstream is unstable");
    expect(h.sub).toMatch(/do not have the cause yet/i);
    // never borrows the RCA verdict vocabulary, and never engine words either
    expect(h.sub.toLowerCase()).not.toMatch(/confirmed|root cause|because|correlat|verdict|bisect/);
  });
});

// ── deep link ────────────────────────────────────────────────────────────────

describe("parseInvestigationHash", () => {
  it.each([
    ["#/investigate/troubleshooting", "investigate"],
    ["#/investigate/troubleshooting?section=investigate", "investigate"],
    ["#/investigate/troubleshooting?section=protocol", "investigate"],
    ["#/investigate/troubleshooting?section=pipeline", "pipeline"],
    ["#/investigate/troubleshooting?section=nonsense", "investigate"],
    ["#/investigate/troubleshooting?section=", "investigate"],
    ["", "investigate"],
    ["?section=protocol", "investigate"],
  ] as const)("%p → section %s", (hash, section) => {
    expect(parseInvestigationHash(hash).section).toBe(section);
  });

  it("is case-sensitive on the section token (no fuzzy matching)", () => {
    expect(parseInvestigationHash("#/x?section=Protocol").section).toBe("investigate");
  });

  it("reads a known symptom and drops an unknown one", () => {
    expect(parseInvestigationHash("#/x?symptom=dns").symptom).toBe("dns");
    expect(parseInvestigationHash("#/x?section=investigate&symptom=app_slow").symptom).toBe("app_slow");
    expect(parseInvestigationHash("#/x?symptom=made_up").symptom).toBeNull();
    expect(parseInvestigationHash("#/x").symptom).toBeNull();
  });

  it("accepts only an opaque case token", () => {
    expect(parseInvestigationHash("#/x?case=corr-abc_123").caseId).toBe("corr-abc_123");
    expect(parseInvestigationHash("#/x?case=" + "a".repeat(64)).caseId).toHaveLength(64);
  });

  it.each([
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "a b",
    "'; DROP TABLE--",
    "a".repeat(65),
    "",
  ])("rejects the case token %p", (bad) => {
    expect(parseInvestigationHash(`#/x?case=${encodeURIComponent(bad)}`).caseId).toBe("");
  });

  it("reads section, symptom and case together", () => {
    expect(parseInvestigationHash("#/investigate/troubleshooting?section=investigate&symptom=site_down&case=corr-1"))
      .toEqual({ section: "investigate", symptom: "site_down", caseId: "corr-1" });
  });

  it.each([null, undefined, "#", "#?", "#/x?", "#/x?&&"] as const)("survives the malformed hash %p", (h) => {
    expect(() => parseInvestigationHash(h as unknown as string)).not.toThrow();
    expect(parseInvestigationHash(h as unknown as string).section).toBe("investigate");
  });
});

// ── the OPERATOR reading of the ladder (step 2) ──────────────────────────────
//
// Owner, 2026-09-06: "too much jargon… NOC admin doesn't need all the jargon".
// The engine's seven-rung bisection ladder stays exactly as it was; this is the
// four-rung reading a NOC admin can act on, with plain status words.

describe("buildPlainLadder", () => {
  const byId = (rungs: ReturnType<typeof buildPlainLadder>) =>
    Object.fromEntries(rungs.map((r) => [r.id, r]));

  it("renders exactly four rungs, in operator language, in bottom-up order", () => {
    expect(buildPlainLadder(ALL_LANES, {}).map((r) => r.label))
      .toEqual(["Physical link", "Routing", "Overlay / Service", "Application"]);
    expect(PLAIN_LADDER.map((l) => l.id)).toEqual(["link", "routing", "overlay", "application"]);
  });

  it("uses no engine vocabulary in any status or note", () => {
    const states: Partial<Record<LaneId, LaneState>> = {
      health: "ready", routing: "not_connected", path: "empty", dem: "loading", flows: "empty",
      events: "ready", changed: "empty",
    };
    for (const r of buildPlainLadder(ALL_LANES, states)) {
      expect(r.status.trim().length).toBeGreaterThan(0);
      expect(r.note.trim().length).toBeGreaterThan(0);
      expect(`${r.label} ${r.status} ${r.note}`.toLowerCase())
        .not.toMatch(/lane|rung|igp|bgp|l2|not_connected|no_data|has_data|bisect|seam/);
    }
  });

  it("says 'Problem found here' only when an ANOMALY lane answered", () => {
    // the health lane's query returns only out-of-state interfaces — a row IS a fault
    expect(byId(buildPlainLadder(ALL_LANES, { health: "ready" })).link.status)
      .toBe("Problem found here");
    // the flow lane returns observations; rows there are evidence, not a verdict
    expect(byId(buildPlainLadder(ALL_LANES, { flows: "ready" })).application.status)
      .toBe("Evidence to review");
  });

  it("says OK only after a lane looked and saw nothing", () => {
    expect(byId(buildPlainLadder(ALL_LANES, { routing: "empty" })).routing.status).toBe("OK");
    // still in flight is NOT "OK" — that would be a claim we have not earned
    expect(byId(buildPlainLadder(ALL_LANES, { routing: "loading" })).routing.status).toBe("Checking…");
    expect(byId(buildPlainLadder(ALL_LANES, {})).routing.status).toBe("Checking…");
  });

  it("says it cannot check when nothing feeds the layer", () => {
    const r = byId(buildPlainLadder(["path", "dem"], { path: "not_connected", dem: "not_connected" })).overlay;
    expect(r.status).toBe("Can't check");
    expect(r.state).toBe("blind");
  });

  it("says a layer this problem does not need was not checked", () => {
    // routing_adjacency opens routing/health/changed/events — no path, no dem
    const r = byId(buildPlainLadder(lanesForSymptom("routing_adjacency"), {})).overlay;
    expect(r.status).toBe("Not checked yet");
    expect(r.state).toBe("skipped");
  });

  it("takes the most informative state of the engine layers beneath it", () => {
    // physical (health) is clean, L2 (health OR events) has rows → the rung reports the finding
    expect(byId(buildPlainLadder(ALL_LANES, { health: "empty", events: "ready" })).link.state).toBe("found");
  });
});

// ── the quiet/loud split and the plain lane summary (step 3) ─────────────────

describe("laneIsQuiet", () => {
  it("counts nothing-to-say states as quiet, and everything else as loud", () => {
    expect(laneIsQuiet("empty")).toBe(true);
    expect(laneIsQuiet("not_connected")).toBe(true);
    expect(laneIsQuiet("ready")).toBe(false);
    expect(laneIsQuiet("error")).toBe(false);
    expect(laneIsQuiet("loading")).toBe(false);
  });
});

describe("laneSummary", () => {
  it("says what a lane found, with a singular and a plural form", () => {
    expect(laneSummary("health", "ready", 1)).toBe("1 interface is down right now.");
    expect(laneSummary("health", "ready", 3)).toBe("3 interfaces are down right now.");
    expect(laneSummary("routing", "ready", 1)).toBe("1 routing neighbour is not up.");
    expect(laneSummary("changed", "ready", 2)).toBe("2 changes were recorded in this window.");
  });

  it("says nothing for a state whose own honest note is already the sentence", () => {
    for (const st of ["loading", "error", "empty", "not_connected"] as LaneState[]) {
      expect(laneSummary("health", st, 0)).toBe("");
    }
  });

  it("has a sentence for every lane", () => {
    for (const l of ALL_LANES) expect(laneSummary(l, "ready", 2).trim().length).toBeGreaterThan(0);
  });
});

// ── the answer, in plain words (step 4) ──────────────────────────────────────

const rca = (over: Partial<Parameters<typeof plainAnswer>[0] & object> = {}) => ({
  verdictState: "suspected" as const, decision: { text: "" }, summary: "", title: "Upstream link fault",
  ...over,
});

describe("plainAnswer", () => {
  it("says plainly that there is no cause when no case backs the investigation", () => {
    const a = plainAnswer(null);
    expect(a.state).toBe("unconfirmed");
    expect(a.headline).toBe("No cause confirmed yet");
    expect(a.detail).toMatch(/ask iris/i);
  });

  it("leads with the engine's decision for a CONFIRMED verdict", () => {
    const a = plainAnswer(rca({ verdictState: "confirmed", decision: { text: "The carrier's circuit is down." }, summary: "Two independent observers saw it." }));
    expect(a).toEqual({ state: "confirmed", headline: "The carrier's circuit is down.", detail: "Two independent observers saw it." });
  });

  it("never upgrades a SUSPECTED verdict past 'likely'", () => {
    const a = plainAnswer(rca({ possiblyCause: "possibly because of the upstream circuit" }));
    expect(a.state).toBe("likely");
    expect(a.headline).toBe("possibly because of the upstream circuit");
  });

  it("says a ruled-out cause was ruled out rather than showing a blank", () => {
    const a = plainAnswer(rca({ verdictState: "contradicted" }));
    expect(a.state).toBe("unconfirmed");
    expect(a.headline).toMatch(/ruled out/i);
    expect(a.detail.trim().length).toBeGreaterThan(0);
  });

  it("says an undetermined verdict is undetermined", () => {
    expect(plainAnswer(rca({ verdictState: "undetermined" })).headline).toBe("No cause confirmed yet");
  });

  it("names a recovered incident as recovered", () => {
    expect(plainAnswer(rca({ verdictState: "recovered" })).state).toBe("recovered");
  });

  it("always produces a non-empty headline", () => {
    for (const v of ["confirmed", "suspected", "undetermined", "contradicted", "recovered"] as const) {
      expect(plainAnswer(rca({ verdictState: v })).headline.trim().length).toBeGreaterThan(0);
    }
  });
});

describe("plainOwner", () => {
  it("returns the attributed owner verbatim", () => {
    expect(plainOwner("Lumen (DIA #12345) · ISP / carrier")).toBe("Lumen (DIA #12345) · ISP / carrier");
  });

  it("never invents an owner — it says nobody is named yet", () => {
    for (const v of ["", "   ", undefined]) {
      expect(plainOwner(v)).toMatch(/nobody is named yet/i);
    }
  });
});

// ── the three-line intro ─────────────────────────────────────────────────────

describe("HOW_IT_WORKS", () => {
  it("is exactly three plain lines, in the order the operator works them", () => {
    expect(HOW_IT_WORKS).toHaveLength(3);
    expect(HOW_IT_WORKS[0]).toMatch(/what is wrong/i);
    expect(HOW_IT_WORKS[1]).toMatch(/evidence/i);
    expect(HOW_IT_WORKS[2]).toMatch(/answer/i);
    for (const l of HOW_IT_WORKS) {
      expect(l.toLowerCase()).not.toMatch(/lane|rung|seam|correlat|verdict|bisect|signal/);
    }
  });
});
