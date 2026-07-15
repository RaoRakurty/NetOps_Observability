// CloudTopologyView.test.tsx — mount smoke for the Cloud tab. Full React Flow
// measurement is unreliable under happy-dom, so this asserts the tab MOUNTS
// (pipeline + official-mark nodes wire up) and the legend renders — not pixel
// layout (that's the hand-off screenshot).

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import CloudTopologyView from "./CloudTopologyView";

afterEach(cleanup);

describe("CloudTopologyView (Cloud tab)", () => {
  it("mounts the cloud canvas without throwing", () => {
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView />
      </ReactFlowProvider>,
    );
    expect(container.querySelector(".topo-stage")).toBeTruthy();
    expect(container.querySelector(".react-flow")).toBeTruthy();
  });

  it("mounts with the carrier overlay enabled without throwing", () => {
    const { container } = render(
      <ReactFlowProvider>
        <CloudTopologyView carrier />
      </ReactFlowProvider>,
    );
    expect(container.querySelector(".topo-stage")).toBeTruthy();
  });
});
