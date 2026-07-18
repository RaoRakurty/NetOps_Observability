// serviceMap.test.ts — the pure API-shape → view-model transform behind the
// observed Service Map (tracker #110). Asserts the honesty contract: node
// classification never promotes an unresolved endpoint, edge weight comes from
// ACCEPTED bytes only (blocked counts never inflate volume), and the caption
// labels are derived verbatim from meta — including the truncation line that
// only appears when the backend actually dropped unattributed endpoints.

import { describe, it, expect } from "vitest";
import {
  buildServiceMapView, edgeWeight, nodeSizeBucket, nodeKind, mapLabels,
  SVCMAP_NODE_SIZE,
} from "./serviceMap";
import type { ServiceMapWire, ServiceMapWireMeta } from "./serviceMap";

const meta = (over: Partial<ServiceMapWireMeta> = {}): ServiceMapWireMeta => ({
  window_hours: 24, pair_signals: 12, resolved_endpoints: 4,
  unresolved_endpoints: 2, unattributed_shown: 2, unattributed_dropped: 0,
  generated_at: "2026-07-18T10:00:00Z", ...over,
});

const wire = (over: Partial<ServiceMapWire> = {}): ServiceMapWire => ({
  nodes: [
    { id: "svc:web", label: "web", kind: "service", resolved: true, bytes: 1_000_000, providers: ["aws"] },
    { id: "svc:db", label: "db", kind: "service", resolved: true, bytes: 500_000, providers: ["aws"] },
    { id: "ip:10.0.0.9", label: "10.0.0.9", kind: "endpoint", resolved: false, bytes: 100, providers: ["azure"] },
  ],
  edges: [
    { source_service: "svc:web", dest_service: "svc:db", relationship: "talks_to",
      bytes: 500_000, pair_count: 3, blocked: false, blocked_count: 0, providers: ["aws"] },
    { source_service: "svc:web", dest_service: "ip:10.0.0.9", relationship: "talks_to",
      bytes: 0, pair_count: 0, blocked: true, blocked_count: 7, providers: ["azure"] },
  ],
  meta: meta(),
  ...over,
});

describe("node classification", () => {
  it("keeps resolved services and unresolved endpoints distinct", () => {
    const v = buildServiceMapView(wire());
    expect(v.nodes.find((n) => n.id === "svc:web")?.kind).toBe("service");
    expect(v.nodes.find((n) => n.id === "ip:10.0.0.9")?.kind).toBe("endpoint");
  });

  it("never promotes an unresolved node to a service, whatever kind claims", () => {
    // zero-trust on the upstream shape: resolved is the authority.
    expect(nodeKind({ kind: "service", resolved: false })).toBe("endpoint");
    expect(nodeKind({ kind: "endpoint", resolved: true })).toBe("endpoint");
    expect(nodeKind({ kind: "service", resolved: true })).toBe("service");
  });

  it("buckets node size by observed bytes — loudest node largest, quiet smallest", () => {
    const v = buildServiceMapView(wire());
    const web = v.nodes.find((n) => n.id === "svc:web")!;
    const ep = v.nodes.find((n) => n.id === "ip:10.0.0.9")!;
    expect(web.sizeBucket).toBe(3);
    expect(ep.sizeBucket).toBeLessThan(web.sizeBucket);
    // the layout footprint and the DOM footprint are the same numbers
    expect(web.width).toBe(SVCMAP_NODE_SIZE[web.sizeBucket].width);
    expect(web.height).toBe(SVCMAP_NODE_SIZE[web.sizeBucket].height);
  });

  it("a node with no accepted volume renders '—', never a fabricated 0 B", () => {
    const v = buildServiceMapView(wire({
      nodes: [{ id: "ip:x", label: "x", kind: "endpoint", resolved: false, bytes: 0, providers: [] }],
      edges: [],
    }));
    expect(v.nodes[0].bytesText).toBe("—");
    expect(v.nodes[0].sizeBucket).toBe(1);
  });
});

describe("edge weight bucketing", () => {
  it("weights by accepted bytes on a log scale, max edge heaviest", () => {
    expect(edgeWeight(1_000_000, 1_000_000)).toBe(4);
    expect(edgeWeight(0, 1_000_000)).toBe(1);
    expect(edgeWeight(50, 1_000_000)).toBeLessThan(4);
  });

  it("degenerate graphs (no volume anywhere) stay at weight 1", () => {
    expect(edgeWeight(0, 0)).toBe(1);
    expect(nodeSizeBucket(0, 0)).toBe(1);
  });
});

describe("blocked handling", () => {
  it("keeps blocked evidence as a count and never as volume", () => {
    const v = buildServiceMapView(wire());
    const blocked = v.edges.find((e) => e.target === "ip:10.0.0.9")!;
    expect(blocked.blocked).toBe(true);
    expect(blocked.blockedCount).toBe(7);
    expect(blocked.bytes).toBe(0);
    expect(blocked.bytesText).toBe("—"); // no fabricated bytes from REJECTs
    expect(blocked.weight).toBe(1); // blocked counts never feed the volume weight
  });

  it("a talks_to edge that also saw REJECTs keeps both truths", () => {
    const v = buildServiceMapView(wire({
      edges: [{ source_service: "svc:web", dest_service: "svc:db", relationship: "talks_to",
        bytes: 500_000, pair_count: 2, blocked: true, blocked_count: 3, providers: ["aws"] }],
    }));
    const e = v.edges[0];
    expect(e.blocked).toBe(true);
    expect(e.blockedCount).toBe(3);
    expect(e.bytes).toBe(500_000); // accepted volume survives untouched
  });

  it("drops an edge that references a node not on the map (no evidence-less links)", () => {
    const v = buildServiceMapView(wire({
      edges: [{ source_service: "svc:web", dest_service: "svc:ghost", relationship: "talks_to",
        bytes: 9, pair_count: 1, blocked: false, blocked_count: 0, providers: [] }],
    }));
    expect(v.edges).toHaveLength(0);
  });
});

describe("meta → honesty labels", () => {
  it("derives window / signals / endpoints verbatim from meta", () => {
    const l = mapLabels(meta({ window_hours: 24, pair_signals: 132, resolved_endpoints: 5, unresolved_endpoints: 3 }));
    expect(l.window).toBe("last 24 hours");
    expect(l.signals).toBe("132 pair signals aggregated");
    expect(l.endpoints).toBe("5 resolved · 3 unresolved endpoints");
    expect(l.generatedAt).toBe("2026-07-18T10:00:00Z");
  });

  it("speaks the 7d window as days and singulars correctly", () => {
    const l = mapLabels(meta({ window_hours: 168, pair_signals: 1, unresolved_endpoints: 1 }));
    expect(l.window).toBe("last 7 days");
    expect(l.signals).toBe("1 pair signal aggregated");
    expect(l.endpoints).toContain("1 unresolved endpoint");
  });

  it("states the truncation ONLY when endpoints were actually dropped", () => {
    expect(mapLabels(meta({ unattributed_dropped: 0 })).truncation).toBe("");
    const l = mapLabels(meta({ unresolved_endpoints: 25, unattributed_shown: 10, unattributed_dropped: 15 }));
    expect(l.truncation).toBe("top 10 of 25 unattributed shown · 15 dropped");
  });
});

describe("empty detection", () => {
  it("an empty window is empty — and still carries its labels", () => {
    const v = buildServiceMapView(wire({ nodes: [], edges: [], meta: meta({ pair_signals: 0 }) }));
    expect(v.empty).toBe(true);
    expect(v.labels.window).toBe("last 24 hours");
  });

  it("a populated graph is not empty", () => {
    expect(buildServiceMapView(wire()).empty).toBe(false);
  });
});
