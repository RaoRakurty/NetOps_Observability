// CloudTopologyView.test.tsx — mount smoke + honest-state contract for the Cloud
// tab. Full React Flow measurement is unreliable under happy-dom, so the canvas
// tests pass an explicit `view` (the documented tests/embedding path — it skips
// the live fetch) and assert the tab MOUNTS (pipeline + official-mark nodes wire
// up: .topo-stage + .react-flow) — not pixel layout (that's the hand-off
// screenshot). Without a `view` prop the component fetches /api/topology/cloud
// and renders the honest loading/empty/error card INSTEAD of a canvas (2026-07
// product review — the fabricated-sample fallback is gone); that contract is
// asserted here too, with the API mocked so no real network is touched.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, cleanup, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import CloudTopologyView from "./CloudTopologyView";
import { cloudNetworkTopology } from "../../mock/cloudNetworkTopology";

const topologyCloud = vi.fn();
vi.mock("../../../../services/api", () => ({
  api: { topologyCloud: () => topologyCloud() },
}));

afterEach(cleanup);
beforeEach(() => {
  topologyCloud.mockReset();
});

describe("CloudTopologyView (Cloud tab)", () => {
  it("mounts the cloud canvas without throwing when given a view", () => {
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView view={cloudNetworkTopology} />
      </ReactFlowProvider>,
    );
    expect(container.querySelector(".topo-stage")).toBeTruthy();
    expect(container.querySelector(".react-flow")).toBeTruthy();
  });

  it("mounts with the carrier overlay enabled without throwing", () => {
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView view={cloudNetworkTopology} carrier />
      </ReactFlowProvider>,
    );
    expect(container.querySelector(".topo-stage")).toBeTruthy();
    expect(container.querySelector(".react-flow")).toBeTruthy();
  });

  it("renders the honest empty state — no canvas — when nothing is discovered", async () => {
    topologyCloud.mockResolvedValue({
      view_id: "cloud-network",
      mode: "explore",
      scope: { tenant_id: "" },
      layout_type: "cloud_grouped",
      generated_at: "2026-07-16T00:00:00Z",
      nodes: [],
      edges: [],
      groups: [],
      overlays: [],
    });
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView />
      </ReactFlowProvider>,
    );
    await screen.findByText("No cloud network discovered yet");
    expect(container.querySelector(".react-flow")).toBeNull();
  });

  it("renders the honest error state — no canvas — when the topology read fails", async () => {
    topologyCloud.mockRejectedValue(new Error("api down"));
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView />
      </ReactFlowProvider>,
    );
    await screen.findByText("Unable to load the cloud network");
    expect(container.querySelector(".react-flow")).toBeNull();
  });
});
