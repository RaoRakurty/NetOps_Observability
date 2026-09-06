// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TopologyCanvas.domain.test.tsx — the domain selector must actually switch.
//
// This exists because the canvas shipped with `domain` prop-only (default
// "lan") and an OPTIONAL `onDomain?.()`, while the nav mounts it as
// `<TopologyCanvas />` with no props. Every domain click was therefore a silent
// no-op: the domain could never leave "lan", the Cloud view never mounted, and
// /api/topology/cloud was never requested. The Cloud page was UNREACHABLE, not
// broken — and nothing errored, which is exactly why it survived so long.
//
// An optional callback that nobody supplies fails silently by design. That is
// the class of defect this test closes.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import TopologyCanvas from "./TopologyCanvas";

// The cloud view fetches on mount; stub the network so the test is about wiring.
vi.mock("../../api/topologyApi", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../api/topologyApi");
  return {
    ...actual,
    fetchTopologyView: vi.fn().mockResolvedValue({ view: { view_id: "v", layout_type: "layered", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
    fetchTopologyGraph: vi.fn().mockResolvedValue({ view: { view_id: "v", layout_type: "layered", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
    fetchCloudTopology: vi.fn().mockResolvedValue({ view: { view_id: "c", layout_type: "cloud_grouped", mode: "explore", nodes: [], edges: [], groups: [] }, status: "empty" }),
  };
});

describe("domain selector", () => {
  beforeEach(() => vi.clearAllMocks());

  it("switches domain when mounted with NO props (the way the nav mounts it)", async () => {
    render(<TopologyCanvas />);
    const select = await screen.findByLabelText("Network domain");
    expect((select as HTMLSelectElement).value).toBe("lan");

    fireEvent.change(select, { target: { value: "cloud" } });

    await waitFor(() => {
      expect((select as HTMLSelectElement).value).toBe("cloud");
    });
  });

  // #131 changed the contract this case guards. Cloud is no longer a separate
  // page reached by picking a domain — the cloud projection is MERGED onto the one
  // canvas at mount, and the domain select filters that same graph. So the read
  // must happen without anyone selecting anything (an on-prem↔cloud investigation
  // needs both ends present before it starts), and picking Cloud must NOT swap in
  // a different renderer.
  it("reads the cloud topology on mount — it is part of the one canvas, not a separate page", async () => {
    const api = await import("../../api/topologyApi");
    render(<TopologyCanvas />);
    await screen.findByLabelText("Network domain");

    await waitFor(() => expect(api.fetchCloudTopology).toHaveBeenCalled());
  });

  it("selecting Cloud filters the SAME canvas — the toolbar and stage stay mounted", async () => {
    render(<TopologyCanvas />);
    const select = await screen.findByLabelText("Network domain");
    // Controls that belong to the shared canvas, not to a cloud-only renderer.
    expect(screen.getByLabelText("Group the canvas by")).toBeInTheDocument();

    fireEvent.change(select, { target: { value: "cloud" } });

    await waitFor(() => expect((select as HTMLSelectElement).value).toBe("cloud"));
    expect(screen.getByLabelText("Group the canvas by")).toBeInTheDocument();
    expect(screen.getByLabelText("Arrange by topology shape")).toBeInTheDocument();
  });
});
