// cloudNetworkTopology.test.ts — structural guards on the cloud-NETWORK fixture.
// These assert the contract the renderer + skill require (every edge has
// evidence, groups reference real nodes) AND the scope rule (NO workloads).

import { describe, it, expect } from "vitest";
import { cloudNetworkTopology as v } from "./cloudNetworkTopology";
import { hasEvidence } from "../utils/topologyHealth";

describe("cloudNetworkTopology fixture", () => {
  it("is the cloud_grouped network view", () => {
    expect(v.layout_type).toBe("cloud_grouped");
    expect(v.nodes.length).toBeGreaterThan(0);
    expect(v.edges.length).toBeGreaterThan(0);
  });

  it("EXCLUDES cloud workloads — no server/app nodes (owner scope)", () => {
    for (const n of v.nodes) {
      expect(n.kind).not.toBe("server");
      // no k8s/workload markers leaked in from the app-dependency view
      expect(n.tags?.workload).toBeUndefined();
    }
  });

  it("every edge carries non-empty evidence (never draw a link without it)", () => {
    for (const e of v.edges) expect(hasEvidence(e.evidence)).toBe(true);
  });

  it("every group child resolves to a real node", () => {
    const ids = new Set(v.nodes.map((n) => n.id));
    for (const g of v.groups) for (const c of g.children) expect(ids.has(c)).toBe(true);
  });

  it("every edge endpoint resolves to a real node", () => {
    const ids = new Set(v.nodes.map((n) => n.id));
    for (const e of v.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
    }
  });

  it("is provider-parametric — carries both AWS and Azure resources", () => {
    const providers = new Set(v.nodes.map((n) => n.tags?.provider).filter(Boolean));
    expect(providers.has("aws")).toBe(true);
    expect(providers.has("azure")).toBe(true);
  });

  it("route edges are control-plane FACTS labelled with the destination CIDR", () => {
    const routes = v.edges.filter((e) => e.relationship === "routed_adjacency");
    expect(routes.length).toBeGreaterThan(0);
    for (const r of routes) {
      expect(r.protocol).toBe("cloud_api");
      // destination stashed as the edge label (source_port), never asserted as traffic
      expect(r.source_port).toBeTruthy();
      expect(r.confidence).toBeLessThan(0.8); // inferred, not measured
    }
  });

  it("covers the core cloud network taxonomy roles", () => {
    const roles = new Set(v.nodes.map((n) => n.role));
    for (const role of ["subnet", "igw", "nva", "endpoint", "vgw", "tgw", "dx"]) {
      expect(roles.has(role)).toBe(true);
    }
  });
});
