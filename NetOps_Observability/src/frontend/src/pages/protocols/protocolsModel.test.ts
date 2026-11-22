// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import type { CorrObject, Device, IgpAdjacency } from "../../services/api";
import {
  attentionReason, deviceIndex, needsAttention, problemsByDevice, tabFromHash, tabHash,
} from "./protocolsModel";

const dev = (id: string, name: string, address = "", site = ""): Device =>
  ({ id, name, address, source: "snmp", last_seen: "", labels: site ? { site } : {} }) as unknown as Device;

const corr = (id: string, affected: object, extra: Partial<CorrObject> = {}): CorrObject =>
  ({
    correlation_id: id, version: 1, state: "open", window_start: "", verdict_tier: "suspected",
    signal_count: 3, affected: JSON.stringify(affected), top_hypothesis: "sig.ent.wan-edge.bgp-peer-flap", ...extra,
  }) as unknown as CorrObject;

const adj = (o: Partial<IgpAdjacency>): IgpAdjacency =>
  ({
    device: "r1", peer: "10.0.0.2", current_state: "full", state_source: "live_series", up: true,
    flaps: 0, changes: 0, up_events: 0, down_events: 0, hold_seconds: null, timeline: [], ...o,
  }) as IgpAdjacency;

describe("tabs", () => {
  it("reads the tab from the third hash segment, BGP by default", () => {
    expect(tabFromHash("#/analytics/protocols/ospf")).toBe("ospf");
    expect(tabFromHash("#/analytics/protocols/isis?x=1")).toBe("isis");
    expect(tabFromHash("#/analytics/protocols")).toBe("bgp");
    expect(tabFromHash("#/analytics/protocols/nonsense")).toBe("bgp");
    expect(tabHash("isis")).toBe("#/analytics/protocols/isis");
  });
});

describe("deviceIndex", () => {
  const idx = deviceIndex([dev("vedge-20-02efdcad", "vEdge-20", "192.168.222.103", "Branch 20"), dev("a", "A", "10.0.0.1"), dev("b", "B", "10.0.0.1")]);
  it("resolves id, name and a unique address to the device", () => {
    expect(idx.idOf("vedge-20-02efdcad")).toBe("vedge-20-02efdcad");
    expect(idx.idOf("vEdge-20")).toBe("vedge-20-02efdcad");
    expect(idx.idOf("192.168.222.103")).toBe("vedge-20-02efdcad");
    expect(idx.nameOf("vedge-20-02efdcad")).toBe("vEdge-20");
    expect(idx.siteOf("vedge-20-02efdcad")).toBe("Branch 20");
  });
  it("an address two devices share names nobody", () => {
    expect(idx.idOf("10.0.0.1")).toBeUndefined();
  });
});

describe("problemsByDevice", () => {
  const idx = deviceIndex([dev("r1", "core-1", "10.1.1.1"), dev("r2", "edge-2", "10.1.1.2")]);
  it("maps a problem to each device it names, by id, address or interface key", () => {
    const uuid = "5564d1aa-0000-4000-8000-000000000001";
    const m = problemsByDevice([corr(uuid, { interfaces: ["10.1.1.1:if3"] }), corr("c-2", { devices: ["edge-2"] })], idx);
    expect(m.get("r1")?.id).toBe(uuid);
    expect(m.get("r2")?.id).toBe("c-2");
    expect(m.get("r1")?.handle).toMatch(/^P-/);
    expect(m.get("r1")?.title).not.toContain("sig.ent");
  });
  it("the newest problem wins a device and noise is skipped", () => {
    const m = problemsByDevice([
      corr("noise", { devices: ["r1"] }, { verdict_tier: "undetermined", signal_count: 1 }),
      corr("newest", { devices: ["r1"] }),
      corr("older", { devices: ["r1"] }),
    ], idx);
    expect(m.get("r1")?.id).toBe("newest");
  });
});

describe("needsAttention", () => {
  it("lists down-now, flapping and last-reported-down; leaves steady-up out", () => {
    expect(needsAttention(adj({ up: false }))).toBe(true);
    expect(needsAttention(adj({ flaps: 2 }))).toBe(true);
    expect(needsAttention(adj({ state_source: "events", up: null, timeline: [{ ts: "t", signal_id: "s", device: "r1", state: "down", severity: "warn", source: "syslog" }] }))).toBe(true);
    expect(needsAttention(adj({}))).toBe(false);
    expect(needsAttention(adj({ state_source: "events", up: null, timeline: [{ ts: "t", signal_id: "s", device: "r1", state: "up", severity: "info", source: "trap" }] }))).toBe(false);
  });
  it("says why in plain words", () => {
    expect(attentionReason(adj({ up: false }))).toBe("Down now");
    expect(attentionReason(adj({ flaps: 1 }))).toBe("Flapped once");
    expect(attentionReason(adj({ flaps: 4 }))).toBe("Flapped 4×");
    expect(attentionReason(adj({ state_source: "events", up: null, timeline: [{ ts: "t", signal_id: "s", device: "r1", state: "down", severity: "warn", source: "syslog" }] }))).toBe("Last reported down");
  });
});
