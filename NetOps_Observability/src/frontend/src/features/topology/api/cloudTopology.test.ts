// cloudTopology.test.ts — the real-data path of the Cloud tab's topology client.
// Asserts fetchCloudTopology serves the live API view when it has content, and
// gracefully degrades to the grounded mock (never blank) on an empty graph or error.

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { TopologyView } from "./topologyTypes";

const topologyCloud = vi.fn();
vi.mock("../../../services/api", () => ({ api: { topologyCloud: () => topologyCloud() } }));

import { fetchCloudTopology } from "./topologyApi";

// A minimal REAL cloud view in the wire shape the backend emits (VPC group +
// subnet + gateway + a route-table edge labelled with the destination CIDR).
const realView: TopologyView = {
  view_id: "cloud-network",
  mode: "explore",
  scope: { tenant_id: "t_acme" },
  layout_type: "cloud_grouped",
  generated_at: "2026-07-15T00:00:00Z",
  nodes: [
    {
      id: "subnet-app", label: "Subnet · app-a · 10.60.10.0/24", kind: "cloud", role: "subnet",
      site: "aws", group_id: "vpc-1", health: "unknown", confidence: 0.9, resolved: true,
      tags: { provider: "aws", role: "subnet", cidr: "10.60.10.0/24" },
      evidence: [{ source: "cloud_api", confidence: 0.9, detail: "subnet subnet-app" }],
    },
    {
      id: "igw-1", label: "IGW · prod-igw", kind: "cloud", role: "internet_gateway",
      site: "aws", group_id: "vpc-1", health: "unknown", confidence: 0.9, resolved: true,
      tags: { provider: "aws", role: "internet_gateway" },
      evidence: [{ source: "cloud_api", confidence: 0.9, detail: "internet_gateway igw-1" }],
    },
  ],
  edges: [
    {
      id: "route-subnet-app-igw-1-0_0_0_0_0", source: "subnet-app", target: "igw-1",
      source_port: "0.0.0.0/0", relationship: "routed_adjacency", protocol: "cloud_api",
      status: "up", confidence: 0.7,
      evidence: [{ source: "cloud_api", confidence: 0.7, detail: "route table rt-app: 0.0.0.0/0 → igw-1" }],
    },
  ],
  groups: [
    { id: "vpc-1", label: "VPC · prod · 10.60.0.0/16", group_type: "vpc", children: ["subnet-app", "igw-1"], health: "unknown", collapsed: false },
  ],
  overlays: ["health"],
};

// NB: we drive the mock with mockImplementation(() => Promise.resolve/reject(...))
// rather than mockResolvedValue/mockRejectedValue — the latter leaves a
// promise-tracking artifact in tinyspy that makes a LATER rejecting test spuriously
// surface the rejection (reproduced: a prior mockResolvedValue test poisons it).
beforeEach(() => {
  topologyCloud.mockReset();
});

describe("fetchCloudTopology", () => {
  it("serves the live API view when it has content", async () => {
    topologyCloud.mockImplementation(() => Promise.resolve(realView));
    const { view, live } = await fetchCloudTopology();
    expect(live).toBe(true);
    expect(view.nodes.map((n) => n.id).sort()).toEqual(["igw-1", "subnet-app"]);
    // The route edge keeps its destination-CIDR label (source_port) through normalize.
    expect(view.edges[0].source_port).toBe("0.0.0.0/0");
    expect(view.groups[0].id).toBe("vpc-1");
  });

  it("falls back to the grounded mock when the API returns an empty graph", async () => {
    topologyCloud.mockImplementation(() => Promise.resolve({ ...realView, nodes: [], edges: [], groups: [] }));
    const { view, live } = await fetchCloudTopology();
    expect(live).toBe(false);
    expect(view.nodes.length).toBeGreaterThan(0); // the mock, never blank
  });

  it("falls back to the grounded mock on an API error", async () => {
    topologyCloud.mockImplementation(() => Promise.reject(new Error("network")));
    // fetchCloudTopology owns the rejection (try/catch) and resolves to the mock —
    // it must never propagate the API error to the caller.
    const { view, live } = await fetchCloudTopology();
    expect(live).toBe(false);
    expect(view.nodes.length).toBeGreaterThan(0);
  });
});
