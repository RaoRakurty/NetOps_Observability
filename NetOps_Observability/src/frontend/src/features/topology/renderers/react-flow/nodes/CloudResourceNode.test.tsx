// CloudResourceNode.test.tsx — the cloud resource card wears the ORIGINAL
// provider-tagged cloud glyph (licence audit D5, 2026-09-04: the providers'
// official trademark icons were removed, so the card no longer renders an
// <img> asset — it draws an inline <svg> whose only provider-specific element
// is a plain letter tag). The cloud registry stays ISOLATED from the default one.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { CloudResourceNode } from "./CloudResourceNode";
import { nodeTypes, CloudNode } from "./index";
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

/** The tag each provider's card must carry — nothing else identifies it. */
const TAGS: Record<string, string> = { aws: "AWS", azure: "AZ", gcp: "GCP" };

describe("CloudResourceNode", () => {
  it("renders the tagged cloud glyph for an AWS resource", () => {
    const { container } = renderNode("aws", "igw");
    expect(container.querySelector("svg")).toBeTruthy();
    expect([...container.querySelectorAll("text")].map((t) => t.textContent)).toContain("AWS");
  });

  it("renders the tagged cloud glyph for a GCP resource", () => {
    const { container } = renderNode("gcp", "subnet");
    expect([...container.querySelectorAll("text")].map((t) => t.textContent)).toContain("GCP");
  });

  it("carries no provider trademark asset and no provider brand colour", () => {
    for (const provider of [...Object.keys(TAGS), "nifcloud"]) {
      const { container } = renderNode(provider, "igw");
      const html = container.innerHTML.toLowerCase();
      expect(container.querySelector("img"), provider).toBeNull();
      for (const hex of ["#ff9900", "#0078d4", "#4285f4", "#ea4335", "#34a853", "#fbbc05"]) {
        expect(html, `${provider} leaked ${hex}`).not.toContain(hex);
      }
      for (const asset of ["assets/cloud/", "aws.svg", "azure.svg", "gcp.svg"]) {
        expect(html, `${provider} leaked ${asset}`).not.toContain(asset);
      }
      cleanup();
    }
  });

  it("an unrecognised provider falls back to the UNTAGGED cloud, never another provider's mark", () => {
    const { container } = renderNode("nifcloud", "subnet");
    const texts = [...container.querySelectorAll("text")].map((t) => t.textContent);
    for (const tag of Object.values(TAGS)) expect(texts).not.toContain(tag);
    expect(container.querySelector("svg path")).toBeTruthy();
  });

  // ONE registry serves the whole unified canvas now (#131): the separate
  // cloud-tab registry is gone with the separate renderer, and the adapter picks
  // the provider-marked card per NODE, by fact. The generic cloud/WAN glyph must
  // stay exactly what it was for every on-prem node.
  it("the shared registry offers BOTH cards — the generic glyph and the provider card", () => {
    expect(nodeTypes.cloudResourceNode).toBe(CloudResourceNode);
    expect(nodeTypes.cloudNode).toBe(CloudNode);
    expect(nodeTypes.cloudResourceNode).not.toBe(nodeTypes.cloudNode);
  });
});
