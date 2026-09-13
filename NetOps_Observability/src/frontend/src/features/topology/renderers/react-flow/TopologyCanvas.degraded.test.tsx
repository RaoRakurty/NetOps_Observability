// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TopologyCanvas.degraded.test.tsx — tracker 290, the canvas half.
//
// An empty adjacency set is indistinguishable from the finding "nothing on this
// estate is next to anything", and that is exactly what the backend read path
// produced whenever the discovery channel was unreachable: nodes, zero edges,
// HTTP 200, nothing anywhere saying the evidence had never arrived. The backend
// now carries `degraded` on the view; this is the half that puts it in front of
// the operator, as a persistent role="alert" beside the map — the same treatment
// the failed cloud read already gets.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import TopologyCanvas from "./TopologyCanvas";

const UNREAD_NOTE =
  "Adjacency evidence could not be read, so links are missing from this view — an absent link here does NOT mean the devices are not adjacent.";

vi.mock("../../api/topologyApi", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../api/topologyApi");
  return {
    ...actual,
    fetchTopologyView: vi.fn(),
    fetchTopologyGraph: vi.fn().mockResolvedValue({ view: { view_id: "v", layout_type: "layered", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
    fetchCloudTopology: vi.fn().mockResolvedValue({ view: { view_id: "c", layout_type: "cloud_grouped", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
  };
});

async function renderWithDegraded(degraded: string[]) {
  const api = await import("../../api/topologyApi");
  vi.mocked(api.fetchTopologyView).mockResolvedValue({
    view: {
      view_id: "v", layout_type: "layered", mode: "explore",
      nodes: [{ id: "spine-1", label: "spine-1", kind: "device", health: "healthy", confidence: 1, resolved: true, evidence: [], metrics: {}, tags: {} }],
      edges: [], groups: [], overlays: [], degraded,
    },
    status: "live",
  } as never);
  render(<TopologyCanvas />);
  return screen.findByLabelText("Network domain");
}

describe("a topology view whose adjacency evidence never arrived", () => {
  beforeEach(() => vi.clearAllMocks());

  it("still draws, and says the missing links are UNREAD rather than absent", async () => {
    await renderWithDegraded([UNREAD_NOTE]);
    const banner = await waitFor(() => screen.getByTestId("topo-view-degraded"));
    // Persistent, and announced: an operator scanning a map during an incident
    // must not have to hover anything to learn the map is incomplete.
    expect(banner).toHaveAttribute("role", "alert");
    expect(banner.textContent).toMatch(/could not be read/i);
    expect(banner.textContent).toMatch(/does NOT mean/);
    // The canvas itself is still there — the nodes, alerts and health arrived.
    expect(screen.getByLabelText("Group the canvas by")).toBeInTheDocument();
  });

  it("says nothing at all when the read was healthy", async () => {
    await renderWithDegraded([]);
    await screen.findByLabelText("Group the canvas by");
    expect(screen.queryByTestId("topo-view-degraded")).toBeNull();
  });
});
