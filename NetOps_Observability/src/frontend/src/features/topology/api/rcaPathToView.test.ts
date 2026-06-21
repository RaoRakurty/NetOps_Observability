// rcaPathToView.test.ts — the pure RCA-path → TopologyView adapter (#77). Asserts
// the kind/health/status mapping, annotation-override authority, and that the
// fault path is carried as an ordered node-id list for the canvas to spotlight.

import { describe, it, expect } from "vitest";
import { rcaPathToView } from "./rcaPathToView";
import type { RcaPathView } from "../../../services/api";

function baseView(): RcaPathView {
  return {
    corr_object_id: "obj-1",
    verdict: "confirmed",
    confidence: 0.9,
    internal: false,
    title: "WAN edge down",
    summary: "",
    recommended_action: "",
    path: {
      source: "n-src",
      destination: "n-dst",
      nodes: [
        { id: "n-src", type: "device", kind: "server", label: "App", role: "affected", status: "observed" },
        { id: "n-rtr", type: "device", kind: "router", label: "Edge", role: "fault", status: "confirmed_down" },
        { id: "n-dst", type: "device", kind: "cloud", label: "AWS", role: "target", status: "observed" },
      ],
      edges: [
        { id: "e1", source: "n-src", target: "n-rtr", type: "path_hop", state: "degraded" },
        { id: "e2", source: "n-rtr", target: "n-dst", type: "bgp_session", state: "confirmed_down", label: "eBGP" },
      ],
    },
    annotations: [],
    evidence_summary: {},
    missing_evidence_summary: [],
  };
}

describe("rcaPathToView", () => {
  it("maps node kinds, health and the ordered fault path", () => {
    const v = rcaPathToView(baseView());
    expect(v.mode).toBe("investigate");
    expect(v.layout_type).toBe("path_first");
    expect(v.scope?.incident_id).toBe("obj-1");
    expect(v.path).toEqual(["n-src", "n-rtr", "n-dst"]);

    const rtr = v.nodes.find((n) => n.id === "n-rtr")!;
    expect(rtr.kind).toBe("router");
    expect(rtr.health).toBe("critical"); // confirmed_down
    const dst = v.nodes.find((n) => n.id === "n-dst")!;
    expect(dst.kind).toBe("cloud");
    expect(dst.health).toBe("ok"); // observed
  });

  it("maps edge relationship + status", () => {
    const v = rcaPathToView(baseView());
    const bgp = v.edges.find((e) => e.id === "e2")!;
    expect(bgp.relationship).toBe("routed_adjacency"); // bgp_session
    expect(bgp.status).toBe("down"); // confirmed_down
    const hop = v.edges.find((e) => e.id === "e1")!;
    expect(hop.relationship).toBe("path_hop");
    expect(hop.status).toBe("degraded");
  });

  it("lets an annotation override the inline node status (authoritative)", () => {
    const rpv = baseView();
    rpv.path.nodes[2].status = "observed"; // inline says healthy…
    rpv.annotations = [
      {
        target_type: "node",
        target_id: "n-dst",
        status: "suspected_down", // …annotation says otherwise
        verdict: "suspected",
        confidence: 0.7,
        owner: "netops",
        visibility: "shown",
        reason: "",
        evidence_refs: [],
        missing_evidence: [],
      },
    ];
    const v = rcaPathToView(rpv);
    expect(v.nodes.find((n) => n.id === "n-dst")!.health).toBe("warning");
  });

  it("carries the annotation's grounded reasoning onto the node's evidence", () => {
    const rpv = baseView();
    rpv.annotations = [
      {
        target_type: "node",
        target_id: "n-rtr",
        status: "confirmed_down",
        verdict: "confirmed",
        confidence: 0.82,
        owner: "wan_provider",
        visibility: "partial",
        reason: "BGP adjacency down grounded on this device",
        evidence_refs: ["sig-42"],
        missing_evidence: ["provider-side interface counters"],
      },
    ];
    const v = rcaPathToView(rpv);
    const rtr = v.nodes.find((n) => n.id === "n-rtr")!;
    expect(rtr.owner).toBe("wan_provider");
    const ev = rtr.evidence[0];
    expect(ev.summary).toBe("BGP adjacency down grounded on this device");
    expect(ev.used_by_rca).toBe(true);
    expect(ev.confidence).toBe(0.82);
    expect(ev.raw_ref).toBe("sig-42");
    expect(ev.missing_evidence_if_any).toBe("provider-side interface counters");
  });

  it("falls back to a plain status evidence row when a node has no annotation", () => {
    const v = rcaPathToView(baseView()); // no annotations
    const ev = v.nodes.find((n) => n.id === "n-src")!.evidence[0];
    expect(ev.used_by_rca).toBeUndefined();
    expect(ev.detail).toBe("observed");
  });

  it("survives an empty path without throwing", () => {
    const rpv = baseView();
    rpv.path = { source: "", destination: "", nodes: [], edges: [] };
    const v = rcaPathToView(rpv);
    expect(v.nodes).toEqual([]);
    expect(v.edges).toEqual([]);
    expect(v.path).toEqual([]);
  });
});
