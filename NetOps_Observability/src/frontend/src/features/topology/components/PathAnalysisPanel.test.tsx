// PathAnalysisPanel.test.tsx — HONESTY guard (gap-report #8 / non-negotiable): an
// IGP-computed shortest path must NEVER be presented to the operator as a live trace.
// These prove the PIXELS: a measured path reads "Measured", a computed path reads
// "Computed … not a live trace", and neither word "traced" nor a false claim appears
// for a computed path.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import PathAnalysisPanel from "./PathAnalysisPanel";
import type { TopologyView } from "../api/topologyTypes";

afterEach(cleanup);

function viewWith(path_source?: "measured" | "computed"): TopologyView {
  return {
    view_id: "v1",
    topology_id: "t1",
    mode: "path_trace",
    scope: { tenant_id: "t1" },
    generated_at: "",
    layout_type: "path_first",
    nodes: [
      { id: "a", label: "edge1", kind: "router", health: "ok", confidence: 1, evidence: [] },
      { id: "b", label: "core1", kind: "router", health: "ok", confidence: 1, evidence: [] },
      { id: "c", label: "dc1", kind: "router", health: "ok", confidence: 1, evidence: [] },
    ],
    edges: [],
    groups: [],
    overlays: [],
    path: ["a", "b", "c"],
    path_source,
  };
}

describe("PathAnalysisPanel — path provenance honesty", () => {
  it("labels a measured path as measured", () => {
    render(<PathAnalysisPanel view={viewWith("measured")} />);
    expect(screen.getByText(/Measured/)).toBeTruthy();
  });

  it("labels a computed path as a non-trace inference (never 'traced')", () => {
    render(<PathAnalysisPanel view={viewWith("computed")} />);
    const chip = screen.getByText(/Computed/);
    expect(chip).toBeTruthy();
    expect(chip.textContent).toMatch(/not a live trace/i);
    // The non-negotiable: the word "traced" must not appear for a computed path.
    expect(document.body.textContent).not.toMatch(/\btraced\b/i);
  });

  it("shows no provenance claim when the source is unknown", () => {
    render(<PathAnalysisPanel view={viewWith(undefined)} />);
    expect(screen.queryByText(/Measured|Computed/)).toBeNull();
  });
});

// Increment 5 — hop → evidence link: an investigated path marks the hops the RCA
// engine implicated, connecting the path to the verdict. Honesty: only fault roles
// get a tag; a healthy/observed hop never gets a fabricated root cause.
function investigatedView(statuses: (string | undefined)[]): TopologyView {
  return {
    view_id: "v1", topology_id: "t1", mode: "investigate", scope: { tenant_id: "t1" },
    generated_at: "", layout_type: "incident",
    nodes: [
      { id: "a", label: "edge1", kind: "router", health: "ok", confidence: 1, evidence: [], rca_status: statuses[0] as never },
      { id: "b", label: "core1", kind: "router", health: "warning", confidence: 1, evidence: [], rca_status: statuses[1] as never },
      { id: "c", label: "dc1", kind: "router", health: "ok", confidence: 1, evidence: [], rca_status: statuses[2] as never },
    ],
    edges: [], groups: [], overlays: [], path: ["a", "b", "c"],
  };
}

// #85 — the hop rail carries the edge's interface facts (bandwidth / throughput /
// reliability / MTU). Honesty: a measured value renders formatted; an absent one
// renders "—" with a provenance tooltip — never a fabricated number.
function edgeMetricsView(withMetrics: boolean): TopologyView {
  const base = viewWith("measured");
  return {
    ...base,
    edges: [
      {
        id: "e1", source: "a", target: "b", relationship: "connected_to", protocol: "lldp",
        confidence: 1, evidence: [], source_port: "Et1", target_port: "Et2",
        ...(withMetrics
          ? { bandwidth_mbps: 1000, throughput_mbps: 320, reliability_pct: 99.98, mtu: 9000 }
          : {}),
      },
    ],
  };
}

describe("PathAnalysisPanel — #85 hop-edge interface metrics", () => {
  it("renders bandwidth / throughput / reliability / MTU on the hop rows", () => {
    render(<PathAnalysisPanel view={edgeMetricsView(true)} />);
    expect(screen.getAllByText("bw 1 Gbps").length).toBeGreaterThan(0);
    expect(screen.getAllByText("thr 320 Mbps").length).toBeGreaterThan(0);
    expect(screen.getAllByText("rel 99.98%").length).toBeGreaterThan(0);
    expect(screen.getAllByText("mtu 9000 B").length).toBeGreaterThan(0);
  });

  it("HONESTY: absent metrics read as an em-dash with a provenance tooltip", () => {
    render(<PathAnalysisPanel view={edgeMetricsView(false)} />);
    // hop c touches no measured edge → all four slots are "—" there
    expect(screen.getAllByText("bw —").length).toBeGreaterThan(0);
    expect(screen.getAllByText("thr —").length).toBeGreaterThan(0);
    expect(screen.getAllByText("rel —").length).toBeGreaterThan(0);
    expect(screen.getAllByText("mtu —").length).toBeGreaterThan(0);
    // the "—" tooltips explain WHERE the value would come from, not just "missing"
    expect(screen.getAllByTitle(/ifSpeed/).length).toBeGreaterThan(0);
    expect(screen.getAllByTitle(/ifMtu/).length).toBeGreaterThan(0);
    // no fabricated numbers anywhere
    expect(document.body.textContent).not.toMatch(/Gbps|Mbps/);
  });
});

describe("PathAnalysisPanel — hop → evidence link (Increment 5)", () => {
  it("tags a confirmed-fault hop as the root cause", () => {
    render(<PathAnalysisPanel view={investigatedView([undefined, "confirmed_down", undefined])} />);
    expect(screen.getByText(/Confirmed root cause/)).toBeTruthy();
  });

  it("tags a suspected hop as where evidence points (not confirmed)", () => {
    render(<PathAnalysisPanel view={investigatedView([undefined, "suspected_down", undefined])} />);
    const tag = screen.getByText(/Where evidence points/);
    expect(tag.textContent).toMatch(/suspected/i);
    expect(document.body.textContent).not.toMatch(/Confirmed root cause/);
  });

  it("never fabricates a root cause on a healthy/observed path", () => {
    render(<PathAnalysisPanel view={investigatedView(["observed", undefined, undefined])} />);
    expect(screen.queryByText(/root cause|evidence points|Needs evidence|Limited visibility/)).toBeNull();
  });
});
