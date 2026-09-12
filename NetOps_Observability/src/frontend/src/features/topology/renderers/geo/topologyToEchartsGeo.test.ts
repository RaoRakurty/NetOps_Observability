// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { topologyToEchartsGeo } from "./topologyToEchartsGeo";
import { geoWanTopology } from "../../mock/geoWanTopology";
import type { TopologyView } from "../../api/topologyTypes";

const ev = [{ source: "snmp" as const, confidence: 1, observed_at: "t", raw_ref: "r" }];

const view: TopologyView = {
  view_id: "v",
  mode: "executive_geo",
  layout_type: "wan_geo",
  generated_at: "t",
  overlays: ["health"],
  groups: [],
  nodes: [
    // placed sites
    { id: "nyc", label: "New York", kind: "site", health: "ok", confidence: 1, evidence: [], coordinates: { x: -74, y: 40.7 }, metrics: { devices: 12 } },
    { id: "lon", label: "London", kind: "site", health: "warning", confidence: 1, evidence: [], coordinates: { x: -0.1, y: 51.5 }, metrics: { devices: 3 } },
    // unplaced — no coordinates
    { id: "ghost", label: "Ghost", kind: "site", health: "unknown", confidence: 1, evidence: [] },
  ],
  edges: [
    // both endpoints placed + has evidence → a circuit
    { id: "nyc-lon", source: "nyc", target: "lon", relationship: "routed_adjacency", status: "up", utilization_pct: 47, confidence: 1, evidence: ev },
    // endpoint unplaced → dropped
    { id: "nyc-ghost", source: "nyc", target: "ghost", relationship: "routed_adjacency", status: "up", confidence: 1, evidence: ev },
    // no evidence → dropped (contract: never draw a link without evidence)
    { id: "no-ev", source: "nyc", target: "lon", relationship: "routed_adjacency", status: "down", confidence: 1, evidence: [] },
  ],
};

describe("topologyToEchartsGeo", () => {
  it("plots only nodes that carry coordinates, and counts the unplaced", () => {
    const m = topologyToEchartsGeo(view);
    expect(m.sites.map((s) => s.id).sort()).toEqual(["lon", "nyc"]);
    expect(m.unplaced).toBe(1);
  });

  it("interprets coordinates as { x: lng, y: lat }", () => {
    const m = topologyToEchartsGeo(view);
    const nyc = m.sites.find((s) => s.id === "nyc")!;
    expect(nyc.lng).toBe(-74);
    expect(nyc.lat).toBe(40.7);
  });

  it("reads device count from metrics.devices", () => {
    const m = topologyToEchartsGeo(view);
    expect(m.sites.find((s) => s.id === "nyc")!.devices).toBe(12);
    expect(m.sites.find((s) => s.id === "lon")!.devices).toBe(3);
  });

  it("draws a circuit only when it has evidence AND both endpoints are placed", () => {
    const m = topologyToEchartsGeo(view);
    expect(m.circuits.map((c) => c.id)).toEqual(["nyc-lon"]);
    const c = m.circuits[0];
    expect(c.from).toEqual([-74, 40.7]);
    expect(c.to).toEqual([-0.1, 51.5]);
    expect(c.fromName).toBe("New York");
    expect(c.toName).toBe("London");
    expect(c.health).toBe("ok"); // status "up" → ok band
    expect(c.utilization).toBe(47);
  });

  it("is deterministic", () => {
    expect(topologyToEchartsGeo(view)).toEqual(topologyToEchartsGeo(view));
  });

  it("projects the sample geo dataset: every node placed, every edge a circuit", () => {
    const m = topologyToEchartsGeo(geoWanTopology);
    expect(m.sites.length).toBe(geoWanTopology.nodes.length);
    expect(m.unplaced).toBe(0);
    expect(m.circuits.length).toBe(geoWanTopology.edges.length);
    // sanity: real-world lon/lat ranges
    for (const s of m.sites) {
      expect(s.lng).toBeGreaterThanOrEqual(-180);
      expect(s.lng).toBeLessThanOrEqual(180);
      expect(s.lat).toBeGreaterThanOrEqual(-90);
      expect(s.lat).toBeLessThanOrEqual(90);
    }
  });
});
