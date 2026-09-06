// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TopologyCanvas.scale.test.tsx — the two connected scale/load defects.
//
//  1. LOAD FLASH. On mount the canvas rendered `fetched ?? workflow?.view`, so the
//     bundled per-mode SAMPLE flashed for ~0.5s before the live fetch resolved —
//     the operator briefly saw a network that is not theirs. The fix shows a
//     loading placeholder until the first fetch resolves, never the sample.
//
//  2. AGGREGATE AT SCALE. A fabric over MAX_CANVAS_NODES (1000) used to hit a
//     dead-end "N nodes — too many for the interactive canvas" card. The fix
//     auto-collapses to the current grouping (default site) so the canvas shows a
//     few dozen interactive GROUP cards instead — the card is now a last resort.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import TopologyCanvas from "./TopologyCanvas";
import { makeEnterpriseScale } from "../../mock/enterpriseScaleTopology";
import type { TopologyView } from "../../api/topologyTypes";

// Keep ELK off the main thread in the test — the aggregate case would otherwise
// lay out >1000 nodes. Positions are irrelevant to what these tests assert.
vi.mock("../../layout/elkLayout", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../layout/elkLayout");
  return { ...actual, layoutView: vi.fn().mockResolvedValue({}) };
});

vi.mock("../../api/topologyApi", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../api/topologyApi");
  return {
    ...actual,
    fetchTopologyView: vi.fn(),
    fetchTopologyGraph: vi.fn().mockResolvedValue({ view: { view_id: "v", layout_type: "layered", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
    fetchCloudTopology: vi.fn().mockResolvedValue({ view: { view_id: "c", layout_type: "cloud_grouped", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
  };
});

const smallView: TopologyView = {
  view_id: "small-live",
  topology_id: "t",
  mode: "explore",
  scope: { tenant_id: "acme" },
  generated_at: "2026-06-18T01:20:00Z",
  layout_type: "layered",
  nodes: [{ id: "unique-marker-dev", label: "unique-marker-dev", kind: "switch", role: "leaf", health: "ok" } as unknown as TopologyView["nodes"][number]],
  edges: [],
  groups: [],
} as unknown as TopologyView;

describe("TopologyCanvas load-flash guard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows a loading placeholder — NOT the bundled sample — until the first fetch resolves", async () => {
    const api = await import("../../api/topologyApi");
    // Hold the fetch open so we can observe the pre-resolve state.
    let resolveView!: (v: { view: TopologyView; status: string }) => void;
    const pending = new Promise<{ view: TopologyView; status: string }>((res) => { resolveView = res; });
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockReturnValue(pending);

    render(<TopologyCanvas />);

    // While loading: the placeholder is up …
    expect(await screen.findByText(/Loading topology/i)).toBeInTheDocument();
    // … and NO node from the bundled Explore sample (physicalTopology) is on screen.
    // Before the fix, `dmz-fw` rendered in the inventory during this window.
    expect(screen.queryByText("dmz-fw")).toBeNull();

    // Resolve with a DISTINCT live view and the placeholder gives way to it.
    resolveView({ view: smallView, status: "live" });
    await waitFor(() => expect(screen.queryByText(/Loading topology/i)).toBeNull());
    expect(await screen.findByText("unique-marker-dev")).toBeInTheDocument();
    // The sample never appeared.
    expect(screen.queryByText("dmz-fw")).toBeNull();
  });
});

describe("TopologyCanvas aggregate-at-scale", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders the aggregated group view (not the dead-end card) for a >1000-node fabric", async () => {
    const api = await import("../../api/topologyApi");
    const big = makeEnterpriseScale(40); // > 1000 nodes, 40 site groups
    expect(big.nodes.length).toBeGreaterThan(1000);
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: big, status: "live" });

    render(<TopologyCanvas />);

    // The aggregate hint appears (auto-collapsed to site groups) …
    expect(await screen.findByText(/Expand a group to drill in/i)).toBeInTheDocument();
    expect(screen.getByText(/showing 40 groups/i)).toBeInTheDocument();
    // … the dead-end "too many" card does NOT …
    expect(screen.queryByText(/too many for the interactive canvas/i)).toBeNull();
    // … and the flat device inventory is suppressed at scale (search is the tool).
    expect(screen.queryByLabelText("Device inventory")).toBeNull();
    // Loading has resolved.
    expect(screen.queryByText(/Loading topology/i)).toBeNull();
  });
});
