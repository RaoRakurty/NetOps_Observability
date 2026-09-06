// NetworkPathView.test.tsx — the dedicated src→dst path ribbon (#77). Proves the
// PIXELS that matter: hops render in forwarding order, endpoints are marked, a
// COMPUTED path is never sold as a live trace (honesty guard, parallel to
// PathAnalysisPanel.test), a grounded RCA verdict surfaces on the ribbon, and a
// sub-2-hop "path" draws nothing (the parent owns the empty/resolving states).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import NetworkPathView from "./NetworkPathView";
import type { TopologyView, RcaOverlayState } from "../api/topologyTypes";

afterEach(cleanup);

function viewWith(opts: {
  path_source?: "measured" | "computed";
  rca?: (RcaOverlayState | undefined)[];
  util?: (number | undefined)[]; // util on link i→i+1
  stamp?: (Record<string, number> | undefined)[]; // per-hop node.metrics
}): TopologyView {
  const ids = ["a", "b", "c"];
  return {
    view_id: "v1",
    topology_id: "t1",
    mode: "path_trace",
    scope: { tenant_id: "t1" },
    generated_at: "",
    layout_type: "path_first",
    nodes: ids.map((id, i) => ({
      id, label: { a: "edge1", b: "core1", c: "dc1" }[id]!,
      kind: "router", health: "ok", confidence: 1, evidence: [],
      rca_status: opts.rca?.[i],
      metrics: opts.stamp?.[i],
    })),
    edges: [
      { id: "e1", source: "a", target: "b", relationship: "connected_to", protocol: "lldp",
        confidence: 1, evidence: [], source_port: "Et1", target_port: "Et2",
        utilization_pct: opts.util?.[0] },
      { id: "e2", source: "b", target: "c", relationship: "connected_to", protocol: "lldp",
        confidence: 1, evidence: [], source_port: "Et3", target_port: "Et4",
        utilization_pct: opts.util?.[1] },
    ],
    groups: [],
    overlays: [],
    path: ids,
    path_source: opts.path_source,
  };
}

describe("NetworkPathView — ribbon", () => {
  it("renders every hop in forwarding order with endpoint markers", () => {
    render(<NetworkPathView view={viewWith({ path_source: "measured" })} />);
    expect(screen.getAllByText("edge1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("core1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("dc1").length).toBeGreaterThan(0);
    expect(screen.getByText("Source")).toBeTruthy();
    expect(screen.getByText("Destination")).toBeTruthy();
    // "3 hops" also appears in the embedded hop-ladder rail — both is fine.
    expect(screen.getAllByText(/3 hops/).length).toBeGreaterThan(0);
  });

  // UI-words sweep 4 (tracker 270): the honesty CLAIM is unchanged — a computed
  // path still says "not a live trace" on screen, and the word "traced" is still
  // never used for one. What moved is the sentence that EXPLAINED the inference;
  // it is ai/skills/explain/path.computed.md now, behind the `(i)` on the chip.
  it("HONESTY: a computed path is never presented as a live trace", () => {
    render(<NetworkPathView view={viewWith({ path_source: "computed" })} />);
    expect(screen.getAllByText(/not a live trace/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Measured · live traceroute/)).toBeNull();
    expect(screen.getAllByRole("button", { name: "Ask Iris about Computed · not a live trace" }).length).toBeGreaterThan(0);
  });

  it("a measured path reads 'Measured'", () => {
    render(<NetworkPathView view={viewWith({ path_source: "measured" })} />);
    expect(screen.getAllByText("Measured").length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Ask Iris about Measured" }).length).toBeGreaterThan(0);
    expect(screen.queryByText(/not a live trace/i)).toBeNull();
  });

  it("surfaces a grounded RCA verdict on the ribbon node", () => {
    render(<NetworkPathView view={viewWith({ path_source: "measured", rca: [undefined, "suspected_down", undefined] })} />);
    // "Suspected fault" is the ribbon's RCA sub-label (RCA_OVERLAY.suspected_down.label).
    expect(screen.getByText("Suspected fault")).toBeTruthy();
  });

  it("flags the busiest link as the bottleneck", () => {
    render(<NetworkPathView view={viewWith({ path_source: "measured", util: [20, 92] })} />);
    // The ribbon's own "bottleneck ·" tag + the rail's "Likely bottleneck:" line.
    expect(screen.getAllByText(/bottleneck/i).length).toBeGreaterThan(0);
  });

  it("shows per-hop STAMP latency + jitter inline (no redundant 'delay')", () => {
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      stamp: [{ stamp_rtt_ms: 0.7, stamp_pdv_ms: 0.4, stamp_owd_ms: 0.3, stamp_loss_pct: 0 }, undefined, undefined],
    })} />);
    expect(screen.getAllByText("LAT").length).toBeGreaterThan(0); // latency label inline
    expect(screen.getAllByText("JIT").length).toBeGreaterThan(0); // jitter label inline
    expect(screen.getByText("700 µs")).toBeTruthy();              // 0.7ms → µs value
  });

  it("expands the FULL per-hop metric list on click (latency/OWD/jitter/loss/hop position)", () => {
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      stamp: [{ stamp_rtt_ms: 0.7, stamp_pdv_ms: 0.4, stamp_owd_ms: 0.3, stamp_loss_pct: 0 }, undefined, undefined],
    })} />);
    // click the first hop's metric button
    fireEvent.click(screen.getAllByTitle(/Open the full per-hop metrics/)[0]);
    expect(screen.getByText("Latency (round-trip)")).toBeTruthy();
    expect(screen.getByText("One-way delay")).toBeTruthy();
    expect(screen.getByText("Hop position")).toBeTruthy();
    expect(screen.getByText("1 of 3")).toBeTruthy();
    // not-yet-wired metrics show an honest "—", not a fabricated value
    expect(screen.getByText("Bandwidth")).toBeTruthy();
  });

  it("derives per-segment added latency and flags the worst segment", () => {
    // hop a=0.3ms, b=0.5ms, c=2.0ms (OWD) → seg a→b adds 0.2ms, seg b→c adds 1.5ms (worst)
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      stamp: [
        { stamp_owd_ms: 0.3 },
        { stamp_owd_ms: 0.5 },
        { stamp_owd_ms: 2.0 },
      ],
    })} />);
    expect(screen.getByText(/200 µs/)).toBeTruthy();      // a→b delta = 0.2ms
    expect(screen.getByText(/most delay/)).toBeTruthy();  // worst segment flagged
    expect(screen.getByText(/1.5 ms/)).toBeTruthy();      // b→c delta = 1.5ms
  });

  it("falls back to traceroute per-hop RTT/loss when STAMP is absent (with provenance)", () => {
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      // hop a: traceroute-only measurement (an intermediate hop STAMP never targets)
      stamp: [{ trace_rtt_ms: 5, trace_loss_pct: 33.3 }, undefined, undefined],
    })} />);
    expect(screen.getAllByText("5.0 ms").length).toBeGreaterThan(0); // inline LAT from trace_*
    fireEvent.click(screen.getAllByTitle(/Open the full per-hop metrics/)[0]);
    expect(screen.getByText("33.3%")).toBeTruthy(); // packet loss from trace_*
    // provenance: the value tooltip says traceroute, never STAMP
    expect(screen.getAllByTitle(/Measured by a traceroute probe/).length).toBeGreaterThan(0);
    expect(screen.queryByTitle(/Measured by a STAMP probe/)).toBeNull();
    // OWD/jitter have no traceroute source → honest "—" naming what is missing;
    // what STAMP measures that traceroute cannot is ai/skills/explain/path.stamp.md.
    expect(screen.getAllByTitle(/No STAMP probe targets this hop yet/).length).toBe(2);
    expect(screen.getByRole("button", { name: "Ask Iris about Active measurement" })).toBeTruthy();
  });

  it("prefers STAMP over traceroute when both measured the hop", () => {
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      stamp: [{ stamp_rtt_ms: 1, trace_rtt_ms: 9 }, undefined, undefined],
    })} />);
    expect(screen.getAllByText("1.0 ms").length).toBeGreaterThan(0);
    expect(screen.queryByText("9.0 ms")).toBeNull();
    fireEvent.click(screen.getAllByTitle(/Open the full per-hop metrics/)[0]);
    expect(screen.getAllByTitle(/Measured by a STAMP probe/).length).toBeGreaterThan(0);
  });

  it("shows the honest footnote when no hop has a STAMP probe", () => {
    render(<NetworkPathView view={viewWith({ path_source: "computed" })} />);
    // The CLAIM stays on the ribbon; how to light the hops up is
    // ai/skills/explain/path.not-measured.md, reached from the `(i)` beside it.
    expect(screen.getByText(/No probe covers the hops on this path\./i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about No probe covers these hops" })).toBeTruthy();
  });

  it("draws nothing for a sub-2-hop path (parent owns the empty state)", () => {
    const v = viewWith({ path_source: "measured" });
    const { container } = render(<NetworkPathView view={{ ...v, path: ["a"] }} />);
    expect(container.querySelector(".netpath")).toBeNull();
  });
});
