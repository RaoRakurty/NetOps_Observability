// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaExport.topology.test.ts — the client print fallback draws its topology
// section from the server's topology_context (RCA document v2 §1/§2), so it
// cannot diverge from the server PDF: the same state words, the same device
// card, the same overlays — and never a node the context does not carry (the
// old client "affected devices" chain drew one the server PDF denied).

import { describe, it, expect } from "vitest";
import { reportHtml, topologyContextHtml } from "./rcaExport";
import { EXAMPLE_CASE, type RcaCase } from "./rcaCase";
import { readTopologyContext, type TopologyContext } from "./topologyContext";
import {
  P3E0400_CONTEXT, TOPOLOGY_ONLY_CONTEXT, NO_ASSET_MAPPING_CONTEXT,
} from "./testdata/topologyFixtures";

const ctx = (v: unknown): TopologyContext => {
  const tc = readTopologyContext(v);
  if (!tc) throw new Error("fixture did not validate");
  return tc;
};
const withCtx = (tc?: TopologyContext): RcaCase => ({ ...EXAMPLE_CASE, ...(tc ? { topologyContext: tc } : {}) });

describe("exported RCA document — topology from topology_context", () => {
  it("P-3E0400 prints the device_only state and card in the server's words", () => {
    const html = reportHtml(withCtx(ctx(P3E0400_CONTEXT)), "3e0400bc");
    expect(html).toContain("Network topology &amp; causality");
    expect(html).toContain("State: <b>device only — no neighbour or path data</b>");
    expect(html).toContain("cedge-60-07ae8615 is in the inventory, but no neighbour or path data was found for it.");
    expect(html).toContain("Device diagnostic — cedge-60-07ae8615");
    expect(html).toContain("LLDP, CDP, BGP-LS, the persisted topology graph, the SD-WAN overlay, the SD-WAN controller");
    expect(html).toContain("Network topology &amp; causality — sources: inventory only");
    // the same undirected count the server partial prints under its picture
    expect(html).toContain("6 undirected interface ↔ interface co-occurrence(s)");
    expect(html).not.toMatch(/path-shaped/);
  });

  it("draws no node beyond the context (no client-side device area)", () => {
    const tc = ctx(TOPOLOGY_ONLY_CONTEXT);
    const body = topologyContextHtml(tc);
    // one <circle> per drawn node + one "?" badge per unknown mark
    const unknownMarks = (body.match(/>\?<\/text>/g) ?? []).length;
    const circles = (body.match(/<circle /g) ?? []).length;
    expect(circles - unknownMarks).toBe(tc.nodes.length);
    expect(body).toContain("the causal path across this topology is <b>unverified</b>");
  });

  it("no_asset_mapping prints the data-availability error and its remediation", () => {
    const body = topologyContextHtml(ctx(NO_ASSET_MAPPING_CONTEXT));
    expect(body).toContain("Data-availability error");
    expect(body).toContain("Not in the inventory: ghost-9.");
    expect(body).toContain("Add the device to the inventory");
    expect(body).not.toContain("<svg");
  });

  it("without a context it says so — it never falls back to a guessed picture", () => {
    const html = reportHtml(withCtx(undefined), "obj");
    expect(html).toContain("The topology context was not built for this document.");
  });

  it("escapes every context string in the print document", () => {
    const tc = ctx({ ...NO_ASSET_MAPPING_CONTEXT, reason: '<script>alert(1)</script>' });
    const body = topologyContextHtml(tc);
    expect(body).not.toContain("<script>");
    expect(body).toContain("&lt;script&gt;");
  });
});
