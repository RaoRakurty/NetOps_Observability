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
