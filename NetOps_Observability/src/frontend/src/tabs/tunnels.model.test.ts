// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tunnels.model.test.ts — the pure rules of the Tunnels page (Paths P4).

import { describe, it, expect } from "vitest";
import type { Tunnel, TunnelEnd, TunnelMatrix, TunnelMatrixCell } from "../services/api";
import {
  agoText, asOfText, caseHref, cellFilter, endText, matrixGrid, oldestQualityAsOf, rowInCell,
  rowState, searchText, stateLabel, stateOrder, stateTone,
} from "./tunnels.model";

function end(over: Partial<TunnelEnd> = {}): TunnelEnd {
  return { device_id: "d", device: "edge", system_ip: "10.0.0.1", color: "mpls", state: "up", sessions: 1, up: 1, site: null, ...over };
}

function cell(over: Partial<TunnelMatrixCell>): TunnelMatrixCell {
  return {
    a: "s1", b: "s1", state: "up", tunnels: 1, up: 1, down: 0, disagree: 0, transports: [],
    measured: 0, worst_loss_pct: null, worst_latency_ms: null, quality_as_of: null, cases: [], ...over,
  };
}

function row(over: Partial<Tunnel> = {}): Tunnel {
  return {
    id: "t", type: "sdwan", local_device: "", local_addr: "", remote_device: "", remote_addr: "",
    status: "up", latency_ms: 0, jitter_ms: 0, loss_pct: 0, qoe: 0, uptime_s: 0, ts: "", ...over,
  } as Tunnel;
}

const MATRIX: TunnelMatrix = {
  sites: [
    { key: "s1", label: "Branch 40", source: "manual", devices: 1 },
    { key: "s2", label: "DC East", source: "manual", devices: 2 },
    { key: "s3", label: "Branch 50", source: "label", devices: 1 },
  ],
  cells: [
    cell({ a: "s1", b: "s2", state: "up", tunnels: 2 }),
    cell({ a: "s2", b: "s3", state: "down", tunnels: 1, down: 1, cases: ["c-1"] }),
    cell({ a: "s2", b: "s2", state: "disagree", tunnels: 1, disagree: 1 }),
  ],
  sites_total: 3, unplaced_tunnels: 0, truncated: false,
};

describe("state", () => {
  it("tones down bad, disagree warn, up good, anything else muted", () => {
    expect(stateTone("down")).toBe("bad");
    expect(stateTone("disagree")).toBe("warn");
    expect(stateTone("UP")).toBe("good");
    expect(stateTone("")).toBe("muted");
    expect(stateTone(undefined)).toBe("muted");
  });

  it("names a disagreement in plain words", () => {
    expect(stateLabel("disagree")).toBe("ends disagree");
    expect(stateLabel("weird")).toBe("unknown");
  });

  it("sorts the trouble first: down, disagree, up, unknown", () => {
    const order = ["up", "", "disagree", "down"].sort((a, b) => stateOrder(a) - stateOrder(b));
    expect(order).toEqual(["down", "disagree", "up", ""]);
  });

  it("reads the folded state, falling back to the legacy status", () => {
    expect(rowState(row({ status: "down", state: "disagree" }))).toBe("disagree");
    expect(rowState(row({ status: "down" }))).toBe("down");
  });
});

describe("matrixGrid", () => {
  it("is symmetric: a cell is found in either order", () => {
    const g = matrixGrid(MATRIX);
    expect(g.cellAt("s1", "s2")?.tunnels).toBe(2);
    expect(g.cellAt("s2", "s1")?.tunnels).toBe(2);
    expect(g.cellAt("s1", "s3")).toBeUndefined();
    expect(g.cellAt("s2", "s2")?.state).toBe("disagree");
  });

  it("puts the worst site first, then the busiest, then by label", () => {
    // s2 and s3 touch a down cell; s2 terminates more tunnels. s1 is only up.
    expect(matrixGrid(MATRIX).sites.map((s) => s.key)).toEqual(["s2", "s3", "s1"]);
  });

  it("is empty, never throwing, with no matrix", () => {
    expect(matrixGrid(undefined).sites).toEqual([]);
    expect(matrixGrid(null).cellAt("a", "b")).toBeUndefined();
  });
});

describe("cell filter", () => {
  const atSites = (a: string | null, b: string | null) =>
    row({ a: end({ site: a ? { label: a, source: "manual" } : null }), b: end({ site: b ? { label: b, source: "manual" } : null }) });

  it("turns a cell into its two site labels", () => {
    expect(cellFilter(MATRIX, MATRIX.cells[1])).toEqual({ a: "DC East", b: "Branch 50" });
  });

  it("matches the label pair in either direction", () => {
    const f = { a: "DC East", b: "Branch 50" };
    expect(rowInCell(atSites("Branch 50", "DC East"), f)).toBe(true);
    expect(rowInCell(atSites("DC East", "Branch 50"), f)).toBe(true);
    expect(rowInCell(atSites("DC East", "Branch 40"), f)).toBe(false);
  });

  it("an intra-site cell needs both ends at that site", () => {
    const f = { a: "DC East", b: "DC East" };
    expect(rowInCell(atSites("DC East", "DC East"), f)).toBe(true);
    expect(rowInCell(atSites("DC East", "Branch 50"), f)).toBe(false);
  });

  it("a row with an end at no site belongs to no cell", () => {
    expect(rowInCell(atSites("DC East", null), { a: "DC East", b: "DC East" })).toBe(false);
    expect(rowInCell(row(), { a: "x", b: "x" })).toBe(false);
  });
});

describe("as of", () => {
  const now = new Date(Date.UTC(2026, 10, 21, 17, 10, 0));

  it("says the clock time and the age", () => {
    expect(asOfText("2026-11-21T16:30:00Z", now, "utc")).toBe("as of 16:30 (40 min ago)");
  });

  it("is empty for a missing or unreadable time", () => {
    expect(asOfText(null, now)).toBe("");
    expect(asOfText("not a time", now)).toBe("");
  });

  it("never says a negative age", () => {
    expect(agoText(-5000)).toBe("just now");
    expect(agoText(30_000)).toBe("just now");
    expect(agoText(119 * 60_000)).toBe("119 min ago");
    expect(agoText(185 * 60_000)).toBe("3 h ago");
  });

  it("a summary uses the OLDEST reading", () => {
    const q = (as_of: string) => ({ latency_ms: 1, jitter_ms: 1, loss_pct: 0, qoe: 9, as_of, ends: 1, source: "controller_statistics" });
    const rows = [row({ quality: q("2026-11-21T16:40:00Z") }), row({ quality: q("2026-11-21T16:20:00Z") }), row({ quality: null })];
    expect(oldestQualityAsOf(rows)).toBe("2026-11-21T16:20:00Z");
    expect(oldestQualityAsOf([row()])).toBeNull();
  });
});

describe("links and text", () => {
  it("a case chip opens the RCA workspace on that object, id encoded", () => {
    expect(caseHref("3f2a-1")).toBe("#/investigate/rca?id=3f2a-1");
    expect(caseHref("a b&c")).toBe("#/investigate/rca?id=a%20b%26c");
  });

  it("names a hidden end by its system-ip", () => {
    expect(endText(end({ device: "", system_ip: "10.255.255.40", color: "biz-internet" }))).toBe("10.255.255.40 · biz-internet");
    expect(endText(undefined, "legacy-dev")).toBe("legacy-dev");
  });

  it("search finds sites, colours and the tunnel id", () => {
    const t = row({ tunnel_id: "10.0.0.1/mpls|10.0.0.2/mpls", a: end({ site: { label: "DC East", source: "manual" } }), b: end({ color: "lte" }) });
    const s = searchText(t);
    expect(s).toContain("dc east");
    expect(s).toContain("lte");
    expect(s).toContain("10.0.0.1/mpls|10.0.0.2/mpls");
  });
});
