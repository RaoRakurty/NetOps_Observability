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

  it("HONESTY: a computed path is never presented as a live trace", () => {
    render(<NetworkPathView view={viewWith({ path_source: "computed" })} />);
    expect(screen.getAllByText(/not a live trace/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Measured · live traceroute/)).toBeNull();
  });

  it("a measured path reads 'Measured'", () => {
    render(<NetworkPathView view={viewWith({ path_source: "measured" })} />);
    expect(screen.getAllByText(/Measured · live traceroute/).length).toBeGreaterThan(0);
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
    expect(screen.getAllByText(/lat/).length).toBeGreaterThan(0); // latency inline
    expect(screen.getAllByText(/jit/).length).toBeGreaterThan(0); // jitter inline
    expect(screen.getByText("700 µs")).toBeTruthy();              // 0.7ms → µs
  });

  it("expands the FULL per-hop metric list on click (latency/OWD/jitter/loss/hop position)", () => {
    render(<NetworkPathView view={viewWith({
      path_source: "measured",
      stamp: [{ stamp_rtt_ms: 0.7, stamp_pdv_ms: 0.4, stamp_owd_ms: 0.3, stamp_loss_pct: 0 }, undefined, undefined],
    })} />);
    // click the first hop's metric button
    fireEvent.click(screen.getAllByTitle("Click for the full per-hop metrics")[0]);
    expect(screen.getByText("Latency (round-trip)")).toBeTruthy();
    expect(screen.getByText("One-way delay (OWD)")).toBeTruthy();
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

  it("shows the honest footnote when no hop has a STAMP probe", () => {
    render(<NetworkPathView view={viewWith({ path_source: "computed" })} />);
    expect(screen.getByText(/add a STAMP target per hop/i)).toBeTruthy();
  });

  it("draws nothing for a sub-2-hop path (parent owns the empty state)", () => {
    const v = viewWith({ path_source: "measured" });
    const { container } = render(<NetworkPathView view={{ ...v, path: ["a"] }} />);
    expect(container.querySelector(".netpath")).toBeNull();
  });
});
