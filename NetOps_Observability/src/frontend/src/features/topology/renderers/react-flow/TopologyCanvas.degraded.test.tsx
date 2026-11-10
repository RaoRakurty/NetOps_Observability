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
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
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

async function renderWithDegraded(degraded: string[], notices: unknown[] = []) {
  const api = await import("../../api/topologyApi");
  vi.mocked(api.fetchTopologyView).mockResolvedValue({
    view: {
      view_id: "v", layout_type: "layered", mode: "explore",
      nodes: [{ id: "spine-1", label: "spine-1", kind: "device", health: "healthy", confidence: 1, resolved: true, evidence: [], metrics: {}, tags: {} }],
      edges: [], groups: [], overlays: [], degraded, notices,
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
    const chip = await waitFor(() => screen.getByTestId("topo-view-notices"));
    // Visible without hovering anything (tracker 290: the map must not read as
    // complete), but polite: a status, never an assertive alert (owner 2026-11-10).
    expect(chip).toHaveAttribute("role", "status");
    expect(chip.textContent).toMatch(/could not be read/i);
    expect(screen.queryByRole("alert")).toBeNull();
    // The canvas itself is still there — the nodes, alerts and health arrived.
    expect(screen.getByLabelText("Group the canvas by")).toBeInTheDocument();
  });

  it("shows only a short headline, and the why, devices and fix on click", async () => {
    const headline = "2 SD-WAN edges not matched to SD-WAN Manager";
    await renderWithDegraded([headline], [{
      id: "sdwan.tunnels.unmatched", severity: "info", headline,
      detail: "These edges are known only over SNMP, which does not show SD-WAN tunnels.",
      action: { label: "Review device matching", path: "/integrations" },
      devices: ["cEDGE-81", "vEdge-100"],
    }]);
    const chip = await waitFor(() => screen.getByTestId("topo-view-notices"));
    expect(chip.textContent).toContain(headline);
    expect(chip.textContent).not.toMatch(/known only over SNMP/);
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: new RegExp(headline) }));
    const pop = screen.getByRole("dialog", { name: "Map notices" });
    expect(pop.textContent).toMatch(/known only over SNMP/);
    expect(pop.textContent).toContain("cEDGE-81");
    expect(screen.getByRole("link", { name: /Review device matching/ })).toHaveAttribute("href", "/integrations");
    // The degraded headline the notice covers is not shown twice.
    expect(screen.getAllByTestId("topo-notice")).toHaveLength(1);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("says nothing at all when the read was healthy", async () => {
    await renderWithDegraded([]);
    await screen.findByLabelText("Group the canvas by");
    expect(screen.queryByTestId("topo-view-notices")).toBeNull();
  });
});
