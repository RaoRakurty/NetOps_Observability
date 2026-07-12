import { describe, it, expect } from "vitest";
import { signatureNocTitle, friendlyProblemId, friendlyIncidentId } from "./labels";

// Friendly Problem ID — the NOC handle shown in the Action Queue, RCA inspector
// and Iris AI. MUST stay byte-identical to the Go backend problemDisplayID
// ("P-" + first 6 hex of the UUID, uppercased) so one id reads the same
// everywhere. Display-only; the raw UUID stays the routing/API key.
describe("friendlyProblemId — P-XXXXXX handle", () => {
  it("derives P- + first 6 hex, uppercased", () => {
    expect(friendlyProblemId("5564d162-c891-5480-800b-9b7fbcdd59b2")).toBe("P-5564D1");
    expect(friendlyProblemId("9f0537bd-0000-0000-0000-000000000000")).toBe("P-9F0537");
  });
  it("is idempotent and safe on already-friendly / empty input", () => {
    expect(friendlyProblemId("P-5564D1")).toBe("P-5564D1");
    expect(friendlyProblemId("")).toBe("");
  });
});

// Friendly Incident ID — the Incident-system sibling (#103 UX-2). MUST stay
// byte-identical to the Go backend incidentDisplayID ("INC-" + first 6 of the
// internal hex id, uppercased) so the Slack card, list and Inspector agree.
describe("friendlyIncidentId — INC-XXXXXX handle", () => {
  it("derives INC- + first 6 hex, uppercased", () => {
    expect(friendlyIncidentId("8591a323df59f393")).toBe("INC-8591A3");
    expect(friendlyIncidentId("deadbeefcafef00d")).toBe("INC-DEADBE");
  });
  it("is idempotent and safe on already-friendly / short / empty input", () => {
    expect(friendlyIncidentId("INC-8591A3")).toBe("INC-8591A3");
    expect(friendlyIncidentId("ab12")).toBe("ab12");
    expect(friendlyIncidentId("")).toBe("");
  });
});

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
    expect(signatureNocTitle("sig.x.y.unrelated")).toBe("Anomaly observed — cause undetermined");
  });

  it("titles never overclaim a verdict (no Confirmed/Down-as-certainty wording)", () => {
    for (const id of ["sig.ent.cloud.region-impairment", "sig.ent.sdwan.tunnel-sla-breach", "sig.ent.wan-edge.bgp-peer-flap"]) {
      expect(signatureNocTitle(id)).not.toMatch(/confirmed|outage|root cause/i);
    }
  });
});
