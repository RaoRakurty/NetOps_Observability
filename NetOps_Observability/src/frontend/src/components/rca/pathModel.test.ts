// pathModel.test.ts — the canonical segment taxonomy + topological completeness
// + boundary/seam derivation (owner directive 2026-07-19: between a site LAN and
// cloud there is ALWAYS a WAN construct; visible boundaries between seams; the
// break sits ON a boundary when the seam is suspected). Model-level tests — the
// render assertions live in RcaPathCausality.test.tsx.

import { describe, it, expect } from "vitest";
import type { RcaPathAttribution, RcaTypedSegment } from "../../services/api";
import {
  derivePathModel, canonicalSegment, ensureCompleteness, deriveBoundaries,
  attachmentLabel, type PathSegmentView,
} from "./pathModel";

const seg = (over: Partial<RcaTypedSegment> & { index: number; segment_type: string }): RcaTypedSegment =>
  ({ ambiguous: false, ...over });

const attribution = (segments: RcaTypedSegment[], over?: Partial<RcaPathAttribution>): RcaPathAttribution => ({
  verdict_tier: "suspected", baseline_verdict_tier: "suspected",
  confidence_lifted: false, capped: false, on_path_device_count: 0,
  attributed: null,
  path: { ambiguous: false, segments },
  ...over,
});

describe("canonicalSegment", () => {
  it("maps the legacy engine vocabulary onto the canonical taxonomy", () => {
    expect(canonicalSegment(seg({ index: 0, segment_type: "lan" }))).toBe("site_lan");
    expect(canonicalSegment(seg({ index: 0, segment_type: "dc" }))).toBe("dc_fabric");
    expect(canonicalSegment(seg({ index: 0, segment_type: "wan" }))).toBe("wan_edge");
    expect(canonicalSegment(seg({ index: 0, segment_type: "internet" }))).toBe("carrier");
    expect(canonicalSegment(seg({ index: 0, segment_type: "cloud" }))).toBe("cloud");
    expect(canonicalSegment(seg({ index: 0, segment_type: "unknown" }))).toBe("unknown");
  });

  it("refines with discovery device roles — never contradicts across ownership", () => {
    // a LAN span of firewalls is the edge-security tier
    expect(canonicalSegment(seg({
      index: 0, segment_type: "lan",
      key_devices: [{ role: "firewall", label: "fw1" }, { role: "firewall", label: "fw2" }],
    }))).toBe("edge_security");
    // leaf/spine roles put a private-space span in the DC fabric
    expect(canonicalSegment(seg({
      index: 0, segment_type: "lan",
      key_devices: [{ role: "unknown", device_role: "dc_leaf", label: "leaf1" }],
    }))).toBe("dc_fabric");
    // a carrier-boundary span whose devices are enterprise WAN edges IS the WAN edge
    expect(canonicalSegment(seg({
      index: 0, segment_type: "internet",
      key_devices: [{ role: "edge", device_role: "wan_edge", label: "cpe1" }],
    }))).toBe("wan_edge");
    // a cloud span of pure edge constructs is the cloud edge
    expect(canonicalSegment(seg({
      index: 0, segment_type: "cloud",
      key_devices: [{ role: "gateway", device_role: "cloud_edge", label: "vgw" }],
    }))).toBe("cloud_edge");
    // unknown roles never force a refinement
    expect(canonicalSegment(seg({
      index: 0, segment_type: "lan",
      key_devices: [{ role: "unknown" }],
    }))).toBe("site_lan");
  });
});

describe("ensureCompleteness — measurement absence ≠ topological absence", () => {
  const canon = (m: { segments: PathSegmentView[] }) => m.segments.map((s) => s.canonical);

  it("a LAN→cloud path ALWAYS gets wan_edge + carrier between, as inferred segments", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "cloud", key_devices: [{ role: "host", label: "app" }] }),
    ]));
    expect(canon(m)).toEqual(["site_lan", "wan_edge", "carrier", "cloud"]);
    expect(m.segments[1].inferred).toBe(true);
    expect(m.segments[2].inferred).toBe(true);
    // inferred segments use synthetic negative indexes — never colliding with
    // engine segment indexes (health/device identity stays keyed to real ones).
    expect(m.segments[1].index).toBeLessThan(0);
  });

  it("a LAN→DC path gets wan_edge + carrier + dc_wan_edge", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "dc", key_devices: [{ role: "leaf", label: "leaf1" }] }),
    ]));
    expect(canon(m)).toEqual(["site_lan", "wan_edge", "carrier", "dc_wan_edge", "dc_fabric"]);
  });

  it("reclassifies a positional unknown span between site and cloud as the inferred carrier leg (hop count kept)", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "unknown", unknown_hops: [3, 4], reason: "2 hops silent" }),
      seg({ index: 2, segment_type: "cloud", key_devices: [{ role: "host", label: "app" }] }),
    ]));
    expect(canon(m)).toEqual(["site_lan", "wan_edge", "carrier", "cloud"]);
    const carrier = m.segments.find((s) => s.canonical === "carrier")!;
    expect(carrier.inferred).toBe(true);
    expect(carrier.unknown_hops).toEqual([3, 4]);   // measured silence is kept, not invented
    expect(carrier.index).toBe(1);                  // the real engine segment, reclassified
  });

  it("does NOT add cloud/WAN segments to a purely intra-site path", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }, { role: "switch", label: "sw1" }] }),
    ]));
    expect(canon(m)).toEqual(["site_lan"]);
  });

  it("does not duplicate a WAN edge that was measured (device role present on the site side)", () => {
    const views = ensureCompleteness([
      seg({ index: 0, segment_type: "lan", key_devices: [
        { role: "client", label: "c1" }, { role: "edge", device_role: "wan_edge", label: "cpe" },
      ] }),
      seg({ index: 1, segment_type: "cloud", key_devices: [{ role: "host", label: "app" }] }),
    ].map((s) => ({ ...s, canonical: canonicalSegment(s), ownerClass: "unknown" as const }))
      .map((s) => ({ ...s, ownerClass: s.canonical === "cloud" ? "provider" as const : "enterprise" as const })));
    const canons = views.map((s) => s.canonical);
    expect(canons).toEqual(["site_lan", "carrier", "cloud"]); // carrier inferred; wan_edge already measured in-seg
  });
});

describe("boundaries & seam ownership", () => {
  it("labels the seam only where ownership changes", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "cloud", key_devices: [{ role: "host", label: "app" }] }),
    ]));
    // site_lan | wan_edge | carrier | cloud → 3 boundaries
    expect(m.boundaries.length).toBe(3);
    expect(m.boundaries[0].seamLabel).toBeUndefined();            // enterprise↔enterprise
    expect(m.boundaries[1].seamLabel).toBe("enterprise ↔ carrier");
    expect(m.boundaries[2].seamLabel).toBe("carrier ↔ provider");
  });

  it("puts the break ON the boundary when the blamed segment has no responding devices", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "internet", unknown_hops: [2, 3], reason: "carrier hops silent" }),
      seg({ index: 2, segment_type: "cloud", key_devices: [{ role: "host", label: "app" }] }),
    ], {
      attributed: {
        device: { role: "unknown", segment_index: 1, segment_type: "internet", upstream_rank: 0, ambiguous: false },
        kind: "path_loss",
      },
    }));
    expect(m.causeBoundary).not.toBeNull();
    expect(m.boundaries[m.causeBoundary!].suspected).toBe(true);
  });

  it("keeps the break WITHIN the segment when a named device is the suspect", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "cloud", key_devices: [{ role: "load_balancer", label: "lb1" }] }),
    ], {
      attributed: {
        device: { role: "load_balancer", label: "lb1", segment_index: 1, segment_type: "cloud", upstream_rank: 1, ambiguous: false },
        kind: "cloud_lb_log",
      },
    }));
    expect(m.causeBoundary).toBeNull();
    expect(m.boundaries.every((b) => !b.suspected)).toBe(true);
  });
});

describe("cloud attachment flavor", () => {
  it("renders only the known backend vocabulary — never guesses", () => {
    expect(attachmentLabel("dia")).toBe("ISP breakout");
    expect(attachmentLabel("direct_connect")).toBe("Direct Connect");
    expect(attachmentLabel("expressroute")).toBe("ExpressRoute");
    expect(attachmentLabel("ipsec_vpn")).toBe("IPsec VPN");
    expect(attachmentLabel("mystery_link")).toBe("");
    expect(attachmentLabel(undefined)).toBe("");
  });

  it("carries the backend attachment onto the segment view", () => {
    const m = derivePathModel(attribution([
      seg({ index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }] }),
      seg({ index: 1, segment_type: "cloud", attachment: "expressroute",
        key_devices: [{ role: "gateway", device_role: "cloud_edge", label: "er-gw" }] }),
    ]));
    const edge = m.segments.find((s) => s.canonical === "cloud_edge")!;
    expect(edge.attachmentText).toBe("ExpressRoute");
  });
});
