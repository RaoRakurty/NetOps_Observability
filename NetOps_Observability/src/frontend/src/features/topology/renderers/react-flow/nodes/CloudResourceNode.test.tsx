// CloudResourceNode.test.tsx — the cloud resource card wears the official
// provider mark, and the cloud registry is ISOLATED from the default one.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { CloudResourceNode } from "./CloudResourceNode";
import { nodeTypes, cloudNodeTypes, CloudNode } from "./index";
import type { RFNodeData } from "../rfTypes";
import type { TopologyNode } from "../../../api/topologyTypes";

afterEach(cleanup);

function data(provider: string, role: string): RFNodeData {
  const node: TopologyNode = {
    id: "n", label: `${role} node`, kind: "cloud", role, health: "unknown",
    confidence: 0.95, evidence: [], tags: { provider, role },
  };
  return { node, emphasis: "normal", showLabel: true, overlay: "health" };
}

function renderNode(provider: string, role: string) {
  return render(
    <ReactFlowProvider>
      <CloudResourceNode id="n" type="cloudNode" data={data(provider, role) as unknown as Record<string, unknown>}
        selected={false} zIndex={1} isConnectable dragging={false} positionAbsoluteX={0} positionAbsoluteY={0} />
    </ReactFlowProvider>,
  );
}

describe("CloudResourceNode", () => {
  it("renders the official provider mark for an AWS resource", () => {
    const { container } = renderNode("aws", "igw");
    expect(container.querySelector("img")).toBeTruthy();
  });

  it("uses the monogram fallback for GCP", () => {
    const { container } = renderNode("gcp", "subnet");
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("G");
  });

  it("cloud registry SWAPS cloudNode but leaves the default registry untouched", () => {
    expect(cloudNodeTypes.cloudNode).toBe(CloudResourceNode);
    expect(nodeTypes.cloudNode).toBe(CloudNode);
    expect(cloudNodeTypes.cloudNode).not.toBe(nodeTypes.cloudNode);
    // every other node type is shared/unchanged
    expect(cloudNodeTypes.switchNode).toBe(nodeTypes.switchNode);
    expect(cloudNodeTypes.groupNode).toBe(nodeTypes.groupNode);
  });
});
