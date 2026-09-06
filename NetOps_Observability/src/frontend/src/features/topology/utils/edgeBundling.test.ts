// edgeBundling.test.ts — #133b. `bundleParallelEdges` shipped fully built and
// called by NOTHING, so a 4-member port-channel drew as four stacked parallel
// curves the operator had to count by eye. It is now wired into the canvas view
// pipeline, which makes its REFUSAL rules load-bearing: bundling collapses edges,
// and collapsing the wrong ones hides the answer.

import { describe, it, expect } from "vitest";
import { bundleParallelEdges } from "./edgeBundling";
import type { TopologyView, TopologyEdge } from "../api/topologyTypes";

const ev = [{ source: "lldp" as const, confidence: 0.9 }];

function edge(over: Partial<TopologyEdge> & Pick<TopologyEdge, "id">): TopologyEdge {
  return {
    source: "a",
    target: "b",
    relationship: "connected_to",
    status: "up",
    confidence: 0.9,
    evidence: ev,
    ...over,
  } as TopologyEdge;
}

function view(edges: TopologyEdge[]): TopologyView {
  return {
    view_id: "bundling",
    mode: "explore",
    layout_type: "spine_leaf",
    generated_at: "2026-08-01T00:00:00Z",
    nodes: [
      { id: "a", label: "a", kind: "switch", health: "ok", confidence: 1, evidence: ev },
      { id: "b", label: "b", kind: "switch", health: "ok", confidence: 1, evidence: ev },
    ],
    edges,
    groups: [],
    overlays: ["health"],
  } as unknown as TopologyView;
}

describe("bundleParallelEdges — the LAG collapse", () => {
  it("collapses parallel healthy links between one pair into a single ×N edge", () => {
    const out = bundleParallelEdges(view([edge({ id: "e1" }), edge({ id: "e2" }), edge({ id: "e3" })]));
    expect(out.edges).toHaveLength(1);
    expect(out.edges[0].bundle_count).toBe(3);
    expect(out.edges[0].bundle_id).toBe("×3");
  });

  it("bundles A→B with B→A — a LAG is one link, not two directions", () => {
    const out = bundleParallelEdges(view([edge({ id: "e1" }), edge({ id: "e2", source: "b", target: "a" })]));
    expect(out.edges).toHaveLength(1);
    expect(out.edges[0].bundle_count).toBe(2);
  });

  it("sums utilization and keeps the highest confidence across members", () => {
    const out = bundleParallelEdges(
      view([
        edge({ id: "e1", utilization_pct: 30, confidence: 0.6 }),
        edge({ id: "e2", utilization_pct: 25, confidence: 0.95 }),
      ]),
    );
    expect(out.edges[0].utilization_pct).toBe(55);
    expect(out.edges[0].confidence).toBe(0.95);
  });

  it("leaves a lone link untouched — same object, no bundle marking", () => {
    const only = edge({ id: "e1" });
    const out = bundleParallelEdges(view([only]));
    expect(out.edges[0]).toBe(only);
    expect(out.edges[0].bundle_id).toBeUndefined();
  });

  it("does not mutate the input view", () => {
    const input = view([edge({ id: "e1" }), edge({ id: "e2" })]);
    bundleParallelEdges(input);
    expect(input.edges).toHaveLength(2);
  });
});

describe("bundleParallelEdges — refuses to hide the answer", () => {
  it("keeps members SEPARATE when one is down: which member broke is the question", () => {
    // BundledEdge carries no health colour and `edgeVariant` ranks bundled above
    // degraded, so bundling here would draw a calm ×2 over a real fault.
    const out = bundleParallelEdges(view([edge({ id: "e1" }), edge({ id: "e2", status: "down" })]));
    expect(out.edges.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
    expect(out.edges.every((e) => e.bundle_id === undefined)).toBe(true);
  });

  it("keeps members separate when one is degraded", () => {
    const out = bundleParallelEdges(view([edge({ id: "e1" }), edge({ id: "e2", status: "degraded" })]));
    expect(out.edges).toHaveLength(2);
  });

  it("never bundles an RCA-flagged link away — that is the engine's verdict on ONE link", () => {
    const out = bundleParallelEdges(
      view([edge({ id: "e1" }), edge({ id: "e2", rca_status: "suspected_down" })]),
    );
    expect(out.edges).toHaveLength(2);
    expect(out.edges.find((e) => e.id === "e2")!.rca_status).toBe("suspected_down");
  });

  it("never merges an OBSERVED adjacency with an INFERRED edge between the same pair", () => {
    // Observed ≠ inferred must stay visually distinct; they are different claims.
    const out = bundleParallelEdges(
      view([edge({ id: "e1", relationship: "connected_to" }), edge({ id: "e2", relationship: "inferred" })]),
    );
    expect(out.edges).toHaveLength(2);
  });

  it("bundles WITHIN a relationship class while leaving the other class alone", () => {
    const out = bundleParallelEdges(
      view([
        edge({ id: "e1", relationship: "connected_to" }),
        edge({ id: "e2", relationship: "connected_to" }),
        edge({ id: "e3", relationship: "inferred" }),
      ]),
    );
    expect(out.edges).toHaveLength(2);
    const bundled = out.edges.find((e) => e.bundle_count === 2);
    expect(bundled?.relationship).toBe("connected_to");
    expect(out.edges.find((e) => e.id === "e3")!.bundle_id).toBeUndefined();
  });
});
