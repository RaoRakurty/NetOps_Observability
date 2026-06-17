import { describe, it, expect } from "vitest";
import { signatureNocTitle } from "./labels";

// #8 — the scenario → NOC-title library. Pins the mapped scenarios, the
// domain-correct fallback, and the specific cloud-mislabel bug fix.
describe("signatureNocTitle — scenario library", () => {
  it("maps every emitted-today signature to a factual title", () => {
    expect(signatureNocTitle("sig.ent.wan-edge.bgp-peer-flap")).toBe("Routing adjacency change");
    expect(signatureNocTitle("sig.ent.middle-mile.dia-egress-latency")).toBe("Middle-mile latency increase");
    expect(signatureNocTitle("sig.ent.cloud.region-degradation")).toBe("Cloud region degradation");
  });

  it("covers cloud region-IMPAIRMENT (was missing → mislabelled WAN)", () => {
    const t = signatureNocTitle("sig.ent.cloud.region-impairment");
    expect(t).toBe("Cloud region impairment");
    expect(t).not.toMatch(/WAN|provider/);
  });

  it("maps the Phase-2/3 forward scenarios", () => {
    expect(signatureNocTitle("sig.ent.sdwan.tunnel-sla-breach")).toBe("SD-WAN tunnel SLA breach");
    expect(signatureNocTitle("sig.ent.cloud.path-blocked")).toBe("Cloud path unreachable");
    expect(signatureNocTitle("sig.ent.access.uplink-down")).toBe("Access uplink down");
    expect(signatureNocTitle("sig.ent.app.degradation-network-clear")).toBe("Application degradation (network clear)");
  });

  it("fallback is domain-correct: cloud/sdwan are NOT swallowed by WAN/provider", () => {
    expect(signatureNocTitle("sig.ent.cloud.something-new")).toBe("Cloud service-path change");
    expect(signatureNocTitle("sig.ent.sdwan.something-new")).toBe("SD-WAN / tunnel change");
    expect(signatureNocTitle("sig.sp.core.mpls-lsp-down")).toBe("MPLS LSP down"); // mapped
    expect(signatureNocTitle("sig.sp.core.mpls-anything")).toBe("MPLS / VPN path change"); // fallback
    expect(signatureNocTitle("sig.x.y.bgp-thing")).toBe("Routing adjacency change");
    expect(signatureNocTitle("sig.x.y.unrelated")).toBe("Network change observed");
  });

  it("titles never overclaim a verdict (no Confirmed/Down-as-certainty wording)", () => {
    for (const id of ["sig.ent.cloud.region-impairment", "sig.ent.sdwan.tunnel-sla-breach", "sig.ent.wan-edge.bgp-peer-flap"]) {
      expect(signatureNocTitle(id)).not.toMatch(/confirmed|outage|root cause/i);
    }
  });
});
