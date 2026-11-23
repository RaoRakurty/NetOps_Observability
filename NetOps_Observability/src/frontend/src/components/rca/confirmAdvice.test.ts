// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// confirmAdvice.test.ts — "What would confirm it" names the protocol the case
// is about (ticket P-5B357F: an OSPF flap was told to add BGP state).

import { describe, it, expect } from "vitest";
import { confirmAdvice, confirmProtocol } from "./confirmAdvice";
import { nocVerdictReason } from "./labels";

describe("confirmProtocol", () => {
  it.each([
    ["sig.ent.access.ospf-adjacency-flap", "ospf"],
    ["ospf_adjacency_change", "ospf"],
    ["isis_adjacency_change", "isis"],
    ["IS-IS adjacency flap", "isis"],
    ["bgp_adjacency_change", "bgp"],
    ["sig.ent.wan.bgp-peer-down", "bgp"],
    ["ldp_session_down", "ldp"],
    ["bfd_session_down", "bfd"],
    ["controller_control_connection_loss", "control"],
    ["omp_peer_down", "omp"],
    ["stp_topology_change", "stp"],
    ["fhrp_state_change", "fhrp"],
    ["link_state_change", "link"],
    ["sig.ent.access.local-link-fault", "none"],
    ["Device & routing change", "routing"],
    ["dns_failure_rate", "none"],
  ])("%s → %s", (name, want) => {
    expect(confirmProtocol(name)).toBe(want);
  });

  it("takes the first name that names a protocol (headline before routing signal)", () => {
    expect(confirmProtocol("sig.ent.security.threat-signal-story", "", "ospf_adjacency_change")).toBe("ospf");
    expect(confirmProtocol("sig.ent.wan.bgp-peer-down", "", "ospf_adjacency_change")).toBe("bgp");
  });

  it("never reads a site tunnel as RSVP-TE", () => {
    expect(confirmProtocol("site-tunnel-down")).not.toBe("rsvp");
  });
});

describe("confirmAdvice", () => {
  it("asks an OSPF case for OSPF from the peer, never BGP", () => {
    const s = confirmAdvice("ospf", true);
    expect(s).toMatch(/OSPF neighbor state from the peer router/);
    expect(s).not.toMatch(/BGP/);
  });

  it("asks a BGP case for the BGP session from the peer", () => {
    expect(confirmAdvice("bgp", false)).toMatch(/BGP session state from the peer/);
  });

  it("names no routing protocol when the case is not about one", () => {
    for (const hasDevice of [true, false]) {
      const s = confirmAdvice("none", hasDevice);
      expect(s).not.toMatch(/BGP|OSPF|IS-IS|routing state/);
    }
  });

  it("never mentions another protocol in any protocol's advice", () => {
    const names: Record<string, RegExp> = { ospf: /OSPF/, isis: /IS-IS/, bgp: /BGP/, eigrp: /EIGRP/ };
    for (const p of Object.keys(names)) {
      const s = confirmAdvice(p as never, true);
      for (const [q, rx] of Object.entries(names)) if (q !== p) expect(s).not.toMatch(rx);
    }
  });
});

describe("nocVerdictReason — the P-5B357F reasons", () => {
  it("translates the support-plane rule instead of printing engine text", () => {
    const s = nocVerdictReason(
      "support plane (management_plane) supports but never anchors — confirmation needs two independent measurement-plane witnesses (have 1: device_telemetry)",
    );
    expect(s).toBe("The controller's own statement backs this up but cannot confirm it. Confirming needs two independent measurements; there is one (device health).");
    expect(s).not.toMatch(/management_plane|anchors|witness/);
  });

  it("says no router reported the routing change, not 'no trusted routing evidence'", () => {
    expect(nocVerdictReason("required modality missing (no trusted witness): control_plane"))
      .toBe("No router reported the routing/link change itself in this window.");
    expect(nocVerdictReason("required modality missing (no trusted witness): passive_flow"))
      .toBe("No traffic flow from a trusted source in this window.");
  });
});
