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

  it("requests the cloud topology once the cloud domain is selected", async () => {
    const api = await import("../../api/topologyApi");
    render(<TopologyCanvas />);
    const select = await screen.findByLabelText("Network domain");

    expect(api.fetchCloudTopology).not.toHaveBeenCalled();
    fireEvent.change(select, { target: { value: "cloud" } });

    // The whole point: selecting Cloud must actually reach the network.
    await waitFor(() => expect(api.fetchCloudTopology).toHaveBeenCalled());
  });
});
