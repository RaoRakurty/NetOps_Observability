// bgpAlerts.model.test.ts — the PURE model behind the Prefixes, Peers and
// Bogons views. Each case locks in an honesty contract, not a layout.

import { describe, it, expect } from "vitest";
import type {
  BgpIncident, BgpBogonSighting, BgpAlertConfigResp, PromInstantResponse,
} from "../../services/api";
import {
  incidentTone, incidentSummary, pathLabel, alertStatusLine,
  peerRowsFromSessions, peerRowsFromMetrics, mergePeerRows, peersState,
  transitSet, groupSightings, type PeerRow,
  EMPTY_POLICY_CONFIG, POLICY_LIMIT_FALLBACK, emptySetConsequence, isPrefixKey,
  parseAsnList, policyBody, policyDirty, policyEvaluationNote, policyForm,
  policyLimits, validatePolicy, type PolicyForm,
} from "./bgpAlerts.model";

const inc = (over: Partial<BgpIncident>): BgpIncident => ({
  prefix: "193.0.0.0/21", class: "none", severity: "info", summary: "",
  evidence: { detail: "" }, first_seen: "", last_seen: "", since: "", ...over,
});

describe("incident class presentation", () => {
  it("never renders an unmeasured prefix as healthy", () => {
    const unknown = incidentTone("unknown");
    const none = incidentTone("none");
    expect(unknown.tone).not.toBe(none.tone);
    expect(unknown.tone).not.toBe("var(--ok)");
    // Plain-language labels (owner, 2026-09-06): the operator reads "Not
    // checked", the protocol word lives in the tooltip.
    expect(unknown.label).toBe("Not checked");
    expect(unknown.detail).toMatch(/missing check/i);
  });

  it("gives the two hijack-shaped classes the critical tone", () => {
    expect(incidentTone("origin_change").tone).toBe("var(--crit)");
    expect(incidentTone("rpki_invalid").tone).toBe("var(--crit)");
    expect(incidentTone("bogon").tone).toBe("var(--crit)");
  });

  it("does not assert a hijack for an RPKI invalid", () => {
    expect(incidentTone("rpki_invalid").detail).toMatch(/stale ROA/i);
  });

  it("counts unknown separately from none", () => {
    const s = incidentSummary([inc({ class: "unknown" }), inc({ class: "none" }), inc({ class: "none" })]);
    expect(s.unknown).toBe(1);
    expect(s.none).toBe(2);
    expect(s.origin_change).toBe(0);
  });
});

describe("alertStatusLine", () => {
  it("says the evaluator is off rather than staying silent", () => {
    expect(alertStatusLine({ enabled: false, note: "BGP alerting is off. Set FEATURE_BGP_ALERTS=true" }))
      .toMatch(/FEATURE_BGP_ALERTS/);
  });
  it("surfaces a last-pass error", () => {
    expect(alertStatusLine({ enabled: true, runs: 3, last_error: "upstream 502" })).toMatch(/upstream 502/);
  });
  it("says nothing when the evaluator is healthy and has run", () => {
    expect(alertStatusLine({ enabled: true, runs: 3 })).toBe("");
  });
  it("says the evaluator has not run yet when there are no passes", () => {
    expect(alertStatusLine({ enabled: true, runs: 0, note: "has not completed a pass" })).toMatch(/pass/);
  });
});

describe("pathLabel", () => {
  it("renders hops as AS numbers", () => {
    expect(pathLabel([3356, 64500, 64496])).toBe("AS3356 → AS64500 → AS64496");
  });
  it("is empty for an absent path", () => {
    expect(pathLabel(undefined)).toBe("");
  });
});

describe("peer rows", () => {
  const sessions = [{
    id: "s1", device_id: "edge-r1",
    peers: [
      { address: "10.0.0.5", as: 64500, state: "down", down_reason: "hold timer", rib: "adj-rib-in", announced_prefixes: 0, withdrawn_prefixes: 12 },
      { address: "10.0.0.6", as: 64501, state: "unknown", rib: "adj-rib-in", announced_prefixes: 5, withdrawn_prefixes: 0 },
    ],
  }];

  it("never turns an unobserved BMP peer into 'up'", () => {
    const rows = peerRowsFromSessions(sessions);
    expect(rows.find((r) => r.peer === "10.0.0.6")?.state).toBe("unknown");
  });

  it("reads the BGP4-MIB enum: only 6 is established", () => {
    const resp: PromInstantResponse = {
      status: "success",
      data: {
        resultType: "vector",
        result: [
          { metric: { device: "edge-r1", peer: "10.0.0.7" }, value: [0, "6"] },
          { metric: { device: "edge-r1", peer: "10.0.0.8" }, value: [0, "3"] },
          { metric: { device: "edge-r1", peer: "10.0.0.9" }, value: [0, "NaN"] },
        ],
      },
    };
    const rows = peerRowsFromMetrics(resp);
    expect(rows.find((r) => r.peer === "10.0.0.7")?.state).toBe("up");
    expect(rows.find((r) => r.peer === "10.0.0.8")?.state).toBe("down");
    // A sample we cannot read is an ABSENT measurement, never "up".
    expect(rows.find((r) => r.peer === "10.0.0.9")?.state).toBe("unknown");
  });

  it("is empty for an absent metric response rather than throwing", () => {
    expect(peerRowsFromMetrics(null)).toEqual([]);
    expect(peerRowsFromMetrics({ status: "error", error: "down" })).toEqual([]);
  });

  it("lets BMP win over the device metric for the same peer, and sorts worst first", () => {
    const bmp = peerRowsFromSessions(sessions);
    const dev: PeerRow[] = [
      { key: "dev:edge-r1:10.0.0.5", device: "edge-r1", peer: "10.0.0.5", state: "up", source: "device" },
      { key: "dev:edge-r2:10.1.0.1", device: "edge-r2", peer: "10.1.0.1", state: "up", source: "device" },
    ];
    const merged = mergePeerRows(bmp, dev);
    // the duplicate is gone…
    expect(merged.filter((r) => r.peer === "10.0.0.5")).toHaveLength(1);
    expect(merged.find((r) => r.peer === "10.0.0.5")?.source).toBe("bmp");
    // …the device-only peer survives…
    expect(merged.find((r) => r.peer === "10.1.0.1")?.source).toBe("device");
    // …and down sorts above unknown, which sorts above up.
    expect(merged.map((r) => r.state)).toEqual(["down", "unknown", "up"]);
  });
});

describe("peersState — the five honest states", () => {
  it("distinguishes the receiver being off from nothing exporting", () => {
    expect(peersState({ bmpAvailable: false, sessions: 0, rows: 0 })).toBe("bmp_off");
    expect(peersState({ bmpAvailable: true, sessions: 0, rows: 0 })).toBe("no_exporter");
  });
  it("distinguishes sessions-with-no-peer-state from real rows", () => {
    expect(peersState({ bmpAvailable: true, sessions: 2, rows: 0 })).toBe("no_peers");
    expect(peersState({ bmpAvailable: true, sessions: 2, rows: 3 })).toBe("rows");
  });
  it("reports a failed read as an error, not as an empty table", () => {
    expect(peersState({ error: true, bmpAvailable: true, sessions: 0, rows: 0 })).toBe("error");
  });
});

describe("transitSet", () => {
  it("marks the hop adjacent to the origin as the upstream", () => {
    const i = inc({ evidence: { detail: "", paths: [[3356, 64500, 64496], [1299, 64500, 64496]] } });
    const set = transitSet(i);
    expect(set[0]).toEqual({ asn: 64500, adjacent: true });
    expect(set.map((t) => t.asn).sort()).toEqual([1299, 3356, 64500]);
    // The origin itself is not transit.
    expect(set.find((t) => t.asn === 64496)).toBeUndefined();
  });
  it("is empty when nothing was observed", () => {
    expect(transitSet(undefined)).toEqual([]);
    expect(transitSet(inc({}))).toEqual([]);
  });
});

describe("groupSightings", () => {
  const s = (prefix: string, block: string, peer: string): BgpBogonSighting => ({
    prefix, entry: { block, reason: "special_purpose", why: "Private-use" },
    source: "bmp", peer, first_seen: "", last_seen: "", count: 1,
  });
  it("groups by the reserved block that matched, busiest first", () => {
    const g = groupSightings([
      s("10.1.0.0/24", "10.0.0.0/8", "a"),
      s("172.16.5.0/24", "172.16.0.0/12", "b"),
      s("10.2.0.0/24", "10.0.0.0/8", "c"),
    ]);
    expect(g[0].block).toBe("10.0.0.0/8");
    expect(g[0].rows).toHaveLength(2);
    expect(g[1].block).toBe("172.16.0.0/12");
  });
  it("is empty for no sightings", () => {
    expect(groupSightings([])).toEqual([]);
  });
});

// ── Alert policy ────────────────────────────────────────────────────────────
//
// The policy is operator INTENT, and the two failure modes here are both about
// intent being misrepresented: an empty set whose consequence is not stated,
// and a saved policy the server rewrote (dedupe · AS0 · canonical prefix) that
// the screen keeps showing as typed.

describe("alert policy — form ↔ wire", () => {
  const resp = (over: Partial<BgpAlertConfigResp> = {}): BgpAlertConfigResp => ({
    config: { default: {} },
    defaults: { min_visibility: 0.5, min_vantages: 2, max_prefixes: 200, max_asns_per_set: 32 },
    ...over,
  });

  it("reads the stored policy into the form, prefixes in key order", () => {
    const f = policyForm(resp({
      config: {
        default: { expected_origins: ["AS64500"], upstreams: ["AS3356"], min_visibility: 0.7, min_vantages: 3 },
        prefixes: {
          "203.0.113.0/24": { expected_origins: ["AS64502"] },
          "193.0.0.0/21": { min_vantages: 4 },
        },
      },
    }));
    expect(f.def).toEqual({ expectedOrigins: "AS64500", upstreams: "AS3356", minVisibility: "0.7", minVantages: "3" });
    expect(f.prefixes.map((p) => p.key)).toEqual(["193.0.0.0/21", "203.0.113.0/24"]);
    expect(f.prefixes[0].cfg.minVantages).toBe("4");
  });

  it("renders an unset threshold as empty rather than as a configured zero", () => {
    const f = policyForm(resp({ config: { default: { min_visibility: 0, min_vantages: 0 } } }));
    expect(f.def.minVisibility).toBe("");
    expect(f.def.minVantages).toBe("");
  });

  it("survives a policy read that never answered", () => {
    expect(policyForm(null)).toEqual({ def: EMPTY_POLICY_CONFIG, prefixes: [] });
  });

  it("takes the caps from the server, and falls back to the documented ones", () => {
    expect(policyLimits(resp()).maxAsnsPerSet).toBe(32);
    expect(policyLimits(null)).toEqual(POLICY_LIMIT_FALLBACK);
  });
});

describe("alert policy — ASN parsing keeps the operator's notation", () => {
  it("accepts both notations and sends back exactly what was typed", () => {
    expect(parseAsnList("AS64500, 64501  as64502", 32).list).toEqual(["AS64500", "64501", "as64502"]);
  });

  it("refuses what ParseASN refuses", () => {
    expect(parseAsnList("AS0", 32).error).toMatch(/AS0 is reserved/);
    expect(parseAsnList("banana", 32).error).toMatch(/not an AS number/);
    expect(parseAsnList("4294967296", 32).error).toMatch(/largest AS number/);
  });

  it("dedupes before the cap, and refuses a set over it", () => {
    expect(parseAsnList("AS1, AS1, AS1", 2).list).toEqual(["AS1"]);
    const many = Array.from({ length: 33 }, (_, i) => `AS${i + 1}`).join(",");
    expect(parseAsnList(many, 32).error).toMatch(/At most 32 AS numbers/);
  });

  it("reads an empty set as empty, not as an error", () => {
    expect(parseAsnList("  ", 32)).toEqual({ list: [] });
  });
});

describe("alert policy — validation mirrors the server", () => {
  const limits = POLICY_LIMIT_FALLBACK;
  const form = (over: Partial<PolicyForm> = {}): PolicyForm =>
    ({ def: { ...EMPTY_POLICY_CONFIG }, prefixes: [], ...over });

  it("accepts an empty policy — that IS a valid intent", () => {
    expect(validatePolicy(form(), limits)).toEqual({});
  });

  it("holds visibility to a share and vantages to a whole number", () => {
    expect(validatePolicy(form({ def: { ...EMPTY_POLICY_CONFIG, minVisibility: "1.5" } }), limits)["default.min_visibility"])
      .toMatch(/between 0 and 1/);
    expect(validatePolicy(form({ def: { ...EMPTY_POLICY_CONFIG, minVantages: "65" } }), limits)["default.min_vantages"])
      .toMatch(/between 0 and 64/);
    expect(validatePolicy(form({ def: { ...EMPTY_POLICY_CONFIG, minVantages: "2.5" } }), limits)["default.min_vantages"])
      .toBeTruthy();
  });

  it("refuses a policy key that is not a prefix, and a repeated one", () => {
    expect(validatePolicy(form({ prefixes: [{ key: "AS64500", cfg: { ...EMPTY_POLICY_CONFIG } }] }), limits)["AS64500.key"])
      .toMatch(/not a prefix/);
    const dup = validatePolicy(form({
      prefixes: [
        { key: "193.0.0.0/21", cfg: { ...EMPTY_POLICY_CONFIG } },
        { key: "193.0.0.0/21", cfg: { ...EMPTY_POLICY_CONFIG } },
      ],
    }), limits);
    expect(dup["193.0.0.0/21.key"]).toMatch(/appears twice/);
  });

  it("accepts the prefix shapes the server parses", () => {
    expect(isPrefixKey("193.0.0.0/21")).toBe(true);
    expect(isPrefixKey("2001:db8::/32")).toBe(true);
    expect(isPrefixKey("193.0.0.0")).toBe(false);
    expect(isPrefixKey("193.0.0.0/33")).toBe(false);
    expect(isPrefixKey("300.0.0.0/8")).toBe(false);
  });

  it("refuses more per-prefix policies than the server stores", () => {
    const rows = Array.from({ length: 201 }, (_, i) => ({ key: `10.${i}.0.0/16`, cfg: { ...EMPTY_POLICY_CONFIG } }));
    expect(validatePolicy(form({ prefixes: rows }), limits).prefixes).toMatch(/At most 200/);
  });
});

describe("alert policy — the PUT body", () => {
  const limits = POLICY_LIMIT_FALLBACK;

  it("omits an empty set instead of sending an empty array", () => {
    const body = policyBody({ def: { ...EMPTY_POLICY_CONFIG }, prefixes: [] }, limits);
    expect(body).toEqual({ default: {} });
    expect("expected_origins" in body.default).toBe(false);
    expect("prefixes" in body).toBe(false);
  });

  it("carries no tenant field — the server stamps the owner from the token", () => {
    const body = policyBody({
      def: { expectedOrigins: "AS64500", upstreams: "", minVisibility: "0.6", minVantages: "3" },
      prefixes: [{ key: " 193.0.0.0/21 ", cfg: { ...EMPTY_POLICY_CONFIG, upstreams: "AS3356" } }],
    }, limits);
    expect(body).toEqual({
      default: { expected_origins: ["AS64500"], min_visibility: 0.6, min_vantages: 3 },
      prefixes: { "193.0.0.0/21": { upstreams: ["AS3356"] } },
    });
    expect(JSON.stringify(body)).not.toMatch(/tenant/i);
  });

  it("drops a half-typed prefix row rather than sending an empty key", () => {
    const body = policyBody({
      def: { ...EMPTY_POLICY_CONFIG },
      prefixes: [{ key: "  ", cfg: { ...EMPTY_POLICY_CONFIG, minVantages: "3" } }],
    }, limits);
    expect("prefixes" in body).toBe(false);
  });
});

describe("alert policy — what an empty set means is SAID", () => {
  it("names the guessed baseline and the transit check that does not run", () => {
    expect(emptySetConsequence("expected_origins", "")).toMatch(/guessed from the first observation/);
    expect(emptySetConsequence("upstreams", "")).toMatch(/unexpected-transit check does not run/);
    expect(emptySetConsequence("expected_origins", "AS64500")).toBeNull();
    expect(emptySetConsequence("upstreams", "AS3356")).toBeNull();
  });

  it("says a stored policy is not being evaluated while alerting is off", () => {
    const off = policyEvaluationNote({ enabled: false, note: "BGP alerting is off." });
    expect(off).toMatch(/BGP alerting is off/);
    expect(off).toMatch(/stored either way/);
    expect(policyEvaluationNote({ enabled: true })).toMatch(/applied on every automatic check/);
  });
});

describe("alert policy — dirtiness", () => {
  it("is false until something changes", () => {
    const f = policyForm(null);
    expect(policyDirty(f, policyForm(null))).toBe(false);
    expect(policyDirty({ ...f, def: { ...f.def, minVantages: "3" } }, f)).toBe(true);
  });
});
