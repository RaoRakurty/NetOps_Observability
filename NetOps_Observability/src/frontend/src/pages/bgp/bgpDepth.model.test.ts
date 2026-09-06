// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// bgpDepth.model.test.ts — the pure model behind the BGP depth panels. These
// are the assertions that keep the panels HONEST: an unavailable RPKI lookup
// must never present as a verdict, a capped graph must never draw a dangling
// edge, and the client feed buffer must stay bounded.

import { describe, expect, it } from "vitest";
import type { BgpAsPathGraph, BgpFeedUpdate, BgpRpkiResult } from "../../services/api";
import {
  NODE_H, NODE_W, edgeWidth, feedCounts, geofeedCountries, layoutAsPathGraph,
  mergeFeed, nodeLabel, nodeSubLabel, pathLengthHint, rpkiStateTone, rpkiSummary,
} from "./bgpDepth.model";

// ── RPKI ────────────────────────────────────────────────────────────────────

describe("rpkiStateTone", () => {
  it("distinguishes the two invalid reasons an operator acts on differently", () => {
    // Plain-language labels (owner, 2026-09-06); "RPKI"/"ROA"/"maxLength" moved
    // into the tooltip, so the LABEL is checked here and the detail carries the
    // protocol word.
    expect(rpkiStateTone("invalid", "origin_as").label).toBe("Wrong origin AS");
    expect(rpkiStateTone("invalid", "origin_as").detail).toMatch(/ROA/);
    expect(rpkiStateTone("invalid", "max_length").label).toBe("Too specific");
    expect(rpkiStateTone("invalid", "max_length").detail).toMatch(/maxLength/);
    expect(rpkiStateTone("invalid").tone).toBe("var(--crit)");
  });

  it("never renders unavailable or unknown as a passing verdict", () => {
    for (const s of ["unavailable", "unknown", undefined] as const) {
      const t = rpkiStateTone(s);
      expect(t.label).not.toBe("Authorised");
      expect(t.tone).not.toBe("var(--ok)");
    }
  });

  it("surfaces the upstream error text on unavailable rather than inventing a reason", () => {
    expect(rpkiStateTone("unavailable", undefined, "validator 503").detail).toContain("503");
  });

  it("valid is the only state that reads as protected", () => {
    expect(rpkiStateTone("valid").tone).toBe("var(--ok)");
  });
});

describe("rpkiSummary", () => {
  it("keeps 'could not check' separate from 'no ROA published'", () => {
    const rs = [
      { prefix: "a", state: "valid", fetched_at: "" },
      { prefix: "b", state: "unknown", fetched_at: "" },
      { prefix: "c", state: "unavailable", fetched_at: "" },
      { prefix: "d", state: "unavailable", fetched_at: "" },
    ] as BgpRpkiResult[];
    const s = rpkiSummary(rs);
    expect(s.valid).toBe(1);
    expect(s.unknown).toBe(1);
    expect(s.unavailable).toBe(2);
    expect(s.invalid).toBe(0);
    // The mistake this guards: folding unavailable into unknown (or into valid)
    // would overstate how much of the watchlist has actually been checked.
    expect(s.unknown + s.unavailable).toBe(3);
  });
});

// ── AS-path layout ──────────────────────────────────────────────────────────

function graph(partial: Partial<BgpAsPathGraph>): BgpAsPathGraph {
  return {
    prefix: "203.0.113.0/24", nodes: [], edges: [], origins: [],
    paths: 0, paths_seen: 0, max_edges: 500, edges_capped: false, nodes_capped: false,
    source: "bgp-state", fetched_at: "2026-09-02T12:00:00Z", ...partial,
  };
}

const sample = graph({
  nodes: [
    { asn: 7018, depth: 0, paths: 2, vantage: true },
    { asn: 6939, depth: 0, paths: 1, vantage: true },
    { asn: 1299, depth: 1, paths: 2 },
    { asn: 3333, depth: 2, paths: 3, origin: true, name: "RIPE-NCC" },
  ],
  edges: [
    { from: 7018, to: 1299, peers: 2 },
    { from: 1299, to: 3333, peers: 2 },
    { from: 6939, to: 3333, peers: 1 },
  ],
  origins: [3333],
  paths: 3, paths_seen: 3,
});

describe("layoutAsPathGraph", () => {
  it("lays vantage points on the left and the origin on the right", () => {
    const l = layoutAsPathGraph(sample);
    const at = (asn: number) => l.nodes.find((n) => n.asn === asn)!;
    expect(at(7018).x).toBe(0);
    expect(at(6939).x).toBe(0);
    expect(at(1299).x).toBeGreaterThan(at(7018).x);
    expect(at(3333).x).toBeGreaterThan(at(1299).x);
  });

  it("forces an origin into the last column even when a short path gave it a small depth", () => {
    // AS3333 reached in 1 hop on one path but 2 on another: the API reports the
    // MINIMUM depth (1), and a naive layout would draw the origin mid-graph.
    const short = graph({
      nodes: [
        { asn: 7018, depth: 0, paths: 1, vantage: true },
        { asn: 1299, depth: 1, paths: 1 },
        { asn: 3333, depth: 1, paths: 2, origin: true },
      ],
      edges: [{ from: 7018, to: 1299, peers: 1 }, { from: 1299, to: 3333, peers: 1 }, { from: 7018, to: 3333, peers: 1 }],
      origins: [3333],
    });
    const l = layoutAsPathGraph(short);
    const origin = l.nodes.find((n) => n.asn === 3333)!;
    const transit = l.nodes.find((n) => n.asn === 1299)!;
    expect(origin.x).toBeGreaterThan(transit.x);
  });

  it("is deterministic — the same data always draws the same picture", () => {
    expect(JSON.stringify(layoutAsPathGraph(sample))).toBe(JSON.stringify(layoutAsPathGraph(sample)));
  });

  it("never emits an edge whose endpoint was not laid out", () => {
    const dangling = graph({
      nodes: [{ asn: 1, depth: 0, paths: 1 }],
      edges: [{ from: 1, to: 999, peers: 1 }],
      origins: [1],
    });
    expect(layoutAsPathGraph(dangling).edges).toHaveLength(0);
  });

  it("sizes the canvas to hold every node", () => {
    const l = layoutAsPathGraph(sample);
    for (const n of l.nodes) {
      expect(n.x + NODE_W).toBeLessThanOrEqual(l.width);
      expect(n.y + NODE_H).toBeLessThanOrEqual(l.height + NODE_H);
    }
    expect(l.depths).toEqual([0, 1, 2]);
  });

  it("handles an empty graph without exploding", () => {
    const l = layoutAsPathGraph(graph({}));
    expect(l.nodes).toHaveLength(0);
    expect(l.edges).toHaveLength(0);
  });

  it("puts a lone node somewhere valid", () => {
    const l = layoutAsPathGraph(graph({ nodes: [{ asn: 64500, depth: 0, paths: 1, origin: true }], origins: [64500] }));
    expect(l.nodes).toHaveLength(1);
    expect(l.nodes[0].x).toBe(0);
  });
});

describe("edgeWidth", () => {
  it("scales with the number of collector paths and never collapses to zero", () => {
    expect(edgeWidth(1, 1)).toBeGreaterThan(0);
    expect(edgeWidth(10, 10)).toBeGreaterThan(edgeWidth(1, 10));
    expect(edgeWidth(0, 10)).toBeGreaterThan(0);
    expect(edgeWidth(100, 10)).toBeLessThanOrEqual(edgeWidth(10, 10));
  });
});

describe("node labels", () => {
  it("labels a node by its ASN and only shows a name the registry actually gave", () => {
    expect(nodeLabel({ asn: 3333, depth: 0, paths: 1 })).toBe("AS3333");
    expect(nodeSubLabel({ asn: 3333, depth: 0, paths: 1 })).toBe("");
    expect(nodeSubLabel({ asn: 3333, depth: 0, paths: 1, name: "RIPE-NCC" })).toBe("RIPE-NCC");
  });
});

describe("pathLengthHint", () => {
  it("reports the observed hop-count range in hops, not depths", () => {
    expect(pathLengthHint(sample)).toEqual({ min: 1, max: 3 });
    expect(pathLengthHint({ nodes: [] })).toBeNull();
  });
});

// ── feed ────────────────────────────────────────────────────────────────────

function up(seq: number, type: "A" | "W" = "A"): BgpFeedUpdate {
  return { seq, time: "2026-09-02T12:00:00Z", type, resource: "AS1", prefix: "203.0.113.0/24", peer: "p" };
}

describe("mergeFeed", () => {
  it("appends new entries in cursor order and drops duplicates", () => {
    const merged = mergeFeed([up(1), up(2)], [up(2), up(3)]);
    expect(merged.map((u) => u.seq)).toEqual([1, 2, 3]);
  });

  it("stays bounded — the client buffer mirrors the server ring, oldest dropped", () => {
    const many = Array.from({ length: 900 }, (_, i) => up(i));
    const merged = mergeFeed([], many, 500);
    expect(merged).toHaveLength(500);
    expect(merged[0].seq).toBe(400);
    expect(merged[merged.length - 1].seq).toBe(899);
  });

  it("returns the same array when the page is empty", () => {
    const existing = [up(1)];
    expect(mergeFeed(existing, [])).toBe(existing);
  });
});

describe("feedCounts", () => {
  it("separates withdrawals — the signature of an outage — from announcements", () => {
    expect(feedCounts([up(1, "A"), up(2, "W"), up(3, "W")])).toEqual({ announce: 1, withdraw: 2 });
    expect(feedCounts([])).toEqual({ announce: 0, withdraw: 0 });
  });
});

// ── geofeed ─────────────────────────────────────────────────────────────────

describe("geofeedCountries", () => {
  it("counts rows per country, biggest first, and marks rows with no country", () => {
    const out = geofeedCountries({
      entries: [
        { prefix: "1.0.0.0/24", country: "US" },
        { prefix: "1.0.1.0/24", country: "US" },
        { prefix: "1.0.2.0/24", country: "DE" },
        { prefix: "1.0.3.0/24" },
      ],
    });
    expect(out[0]).toEqual({ country: "US", rows: 2 });
    expect(out.map((c) => c.country)).toContain("—");
  });
});
