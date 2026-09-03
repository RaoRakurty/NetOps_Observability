// bgpAlerts.model.test.ts — the PURE model behind the Prefixes, Peers and
// Bogons views. Each case locks in an honesty contract, not a layout.

import { describe, it, expect } from "vitest";
import type { BgpIncident, BgpBogonSighting, PromInstantResponse } from "../../services/api";
import {
  incidentTone, incidentSummary, pathLabel, alertStatusLine,
  peerRowsFromSessions, peerRowsFromMetrics, mergePeerRows, peersState,
  transitSet, groupSightings, type PeerRow,
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
    expect(unknown.label).toMatch(/NOT MEASURED/);
    expect(unknown.detail).toMatch(/absent measurement/i);
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
