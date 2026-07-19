// RcaPathCausality.test.tsx — the path-first RCA render (design §5/§5a, reworked
// per the owner directive 2026-07-18). Asserts: ONE clean left-to-right chain of
// small nodes; the attributed cause is the RED hero ("Break here" / "Possible
// break here"); unknown/opaque spans collapse to a dotted connector with a count
// (reason behind hover, never a grey box); healthy hops carry NO state chips; a
// capped verdict never over-claims; cloud devices deep-link into Cloud Logs; and
// the no-path / no-break cases each render one honest sentence (never a
// fabricated path or break).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import type { RcaPathAttribution } from "../../services/api";
import RcaPathCausality from "./RcaPathCausality";
import { signal, timeline } from "../../test/factories";

afterEach(cleanup);

// The engine's decoded attribution: a confirmed CLOUD/Load-Balancer break, lifted
// over a suspected symptom-only baseline, on a LAN → CLOUD typed path (matches the
// backend passthrough fixture in rca_path_attribution_test.go).
const confirmed: RcaPathAttribution = {
  src: "10.20.30.40", dst: "52.216.100.6",
  attributed: {
    device: { address: "52.216.100.5", role: "load_balancer", label: "correlix-edge-urlmap",
      segment_index: 1, segment_type: "cloud", upstream_rank: 1, ambiguous: false },
    kind: "cloud_lb_log", modality: "passive_flow",
  },
  explained_away: [{
    device: { address: "52.216.100.6", role: "host", label: "app-host-01",
      segment_index: 1, segment_type: "cloud", upstream_rank: 2, ambiguous: false },
    kind: "cloud_health",
  }],
  discounted: [{ identity: "cloud_dns_log:other.example.com", kind: "dns",
    reason: "off-path: device not on the affected SRC->DST path" }],
  verdict_tier: "confirmed", baseline_verdict_tier: "suspected",
  confidence_lifted: true, capped: false, on_path_device_count: 2,
  path: {
    src: "10.20.30.40", dst: "52.216.100.6", ambiguous: false,
    head: { query_name: "app.correlix.example", resolved_address: "52.216.100.6" },
    segments: [
      { index: 0, segment_type: "lan", boundary: "LAN", confidence: "medium",
        key_devices: [{ address: "10.20.30.40", role: "client", label: "client-01", confidence: "medium" }],
        ambiguous: false },
      { index: 1, segment_type: "cloud", boundary: "CLOUD", provider: "aws", confidence: "strong",
        key_devices: [
          { address: "52.216.100.5", role: "load_balancer", label: "correlix-edge-urlmap", confidence: "strong" },
          { address: "52.216.100.6", role: "host", label: "app-host-01", confidence: "strong" },
        ], ambiguous: false },
    ],
    notes: [],
  },
};

describe("RcaPathCausality", () => {
  it("renders the discovered path as customer-labeled typed segments", () => {
    render(<RcaPathCausality data={confirmed} />);
    // segment types use the canonical NOC labels — never the raw tokens. "Cloud"
    // appears both in the headline claim and as the segment name.
    expect(screen.getAllByText("Cloud").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Site LAN").length).toBeGreaterThan(0);
    // TOPOLOGICAL COMPLETENESS (owner 2026-07-19): a LAN→cloud path ALWAYS
    // renders the WAN constructs between them, inferred (dotted) when silent —
    // never a bare "LAN … CLOUD".
    expect(screen.getAllByText("WAN edge").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Carrier / middle mile").length).toBeGreaterThan(0);
    expect(screen.getByText(/WAN edge inferred/i)).toBeTruthy();
    expect(screen.getByText(/carrier path inferred/i)).toBeTruthy();
    // visible seam labels where ownership changes between adjacent segments.
    expect(screen.getByText("enterprise ↔ carrier")).toBeTruthy();
    expect(screen.getByText("carrier ↔ provider")).toBeTruthy();
    // role labels are customer-facing (no schema kinds).
    expect(screen.getAllByText("Load Balancer").length).toBeGreaterThan(0);
    expect(screen.getByText("Client")).toBeTruthy();
    // DNS head at the path start.
    expect(screen.getByText("app.correlix.example")).toBeTruthy();
    // raw segment/kind tokens must NOT leak into the UI.
    expect(screen.queryByText(/cloud_lb_log/)).toBeNull();
    expect(screen.queryByText(/segment_type/)).toBeNull();
  });

  it("highlights the attributed cause as the broken link and shows the verdict lift", () => {
    render(<RcaPathCausality data={confirmed} />);
    // the named cause reads as path causality in the headline.
    expect(screen.getByText(/broke at/i)).toBeTruthy();
    // the cause device is the hero: break tag, definitive on a confirmed verdict.
    expect(screen.getByText("Break here")).toBeTruthy();
    // verdict LIFT: confirmed now, suspected baseline.
    expect(screen.getByText("Confirmed")).toBeTruthy();
    expect(screen.getByText("Suspected")).toBeTruthy();
    expect(screen.getByText(/lifted by on-path evidence/i)).toBeTruthy();
    // explained-away downstream victim is secondary, not blamed.
    expect(screen.getByText("Downstream")).toBeTruthy();
    // discounted off-path fault is listed as ruled-out.
    expect(screen.getByText(/Ruled out \(off-path\)/i)).toBeTruthy();
  });

  it("healthy hops are minimal — no state chips, no confidence footers (owner 2026-07-18)", () => {
    render(<RcaPathCausality data={confirmed} />);
    // no per-segment "Classified · <confidence>" footers on the chain
    expect(screen.queryByText(/^Classified ·/)).toBeNull();
    // no observed/none state chips anywhere in the default view
    expect(screen.queryByText(/observed/i)).toBeNull();
    expect(screen.queryByText(/no data/i)).toBeNull();
  });

  it("draws the chain with NO break + one clean sentence when no break is attributable", () => {
    const noBreak: RcaPathAttribution = {
      ...confirmed, attributed: null, explained_away: [], discounted: [],
      verdict_tier: "suspected", baseline_verdict_tier: "suspected", confidence_lifted: false,
    };
    render(<RcaPathCausality data={noBreak} />);
    // the chain still draws (never hidden just because no cause is named)…
    expect(screen.getByText("Client")).toBeTruthy();
    expect(screen.getAllByText("Load Balancer").length).toBeGreaterThan(0);
    // …with no break invented…
    expect(screen.queryByText(/break here/i)).toBeNull();
    // …and the one clean sentence.
    expect(screen.getByText(/no break point is attributable/i)).toBeTruthy();
  });

  it("deep-links a cloud device on the path into the family-tagged Cloud Logs", () => {
    render(<RcaPathCausality data={confirmed} />);
    const lb = screen.getByLabelText(/Load Balancer correlix-edge-urlmap.*open logs/i) as HTMLAnchorElement;
    expect(lb.tagName).toBe("A");
    expect(lb.getAttribute("href")).toContain("#/logs/cloud?");
    expect(lb.getAttribute("href")).toContain("family=lb");
    expect(lb.getAttribute("href")).toContain("provider=aws");
    expect(lb.getAttribute("href")).toContain("resource_id=correlix-edge-urlmap");
  });

  it("renders an opaque segment greyed WITH its reason, capped verdict never over-claims", () => {
    const capped: RcaPathAttribution = {
      src: "a", dst: "b",
      attributed: {
        device: { role: "load_balancer", label: "lb1", segment_index: 2, segment_type: "cloud",
          upstream_rank: 1, ambiguous: false },
        kind: "cloud_lb_log",
      },
      verdict_tier: "suspected", baseline_verdict_tier: "suspected",
      confidence_lifted: false, capped: true,
      cap_reason: "path segment 1 is unknown/opaque on the SRC->cause span",
      on_path_device_count: 1,
      path: {
        ambiguous: false, segments: [
          { index: 0, segment_type: "lan", key_devices: [{ role: "client", label: "c1" }], ambiguous: false },
          { index: 1, segment_type: "unknown", reason: "no telemetry crosses this provider backbone", ambiguous: false },
          { index: 2, segment_type: "cloud", provider: "aws",
            key_devices: [{ role: "load_balancer", label: "lb1" }], ambiguous: false },
        ],
      },
    };
    render(<RcaPathCausality data={capped} />);
    // an unknown span BETWEEN the site LAN and the cloud is the WAN/carrier leg
    // topologically (owner 2026-07-19: measurement absence ≠ topological
    // absence): it renders as an INFERRED carrier segment — identity kept, body
    // dotted, never a bare grey box. Its original classification reason stays
    // reachable on hover (title) AND as screen-reader-only text.
    expect(screen.queryByText("Unknown segment")).toBeNull();
    expect(screen.getAllByText("Carrier / middle mile").length).toBeGreaterThan(0);
    const inferredBody = screen.getByText(/carrier path inferred/i);
    expect(inferredBody.className).toContain("rpc-seg-inferred-body");
    expect(inferredBody.getAttribute("title")).toMatch(/no telemetry crosses this provider backbone/i);
    const srReason = screen.getByText(/no telemetry crosses this provider backbone/i);
    expect(srReason.className).toContain("sr-only");
    // an unconfirmed verdict reads "Possible break here", never definitive.
    expect(screen.getByText("Possible break here")).toBeTruthy();
    // the honesty cap is surfaced — reads suspected, never confirmed.
    expect(screen.getByText(/Verdict capped/i)).toBeTruthy();
    expect(screen.getByText(/unknown\/opaque/i)).toBeTruthy();
    expect(screen.queryByText("Confirmed")).toBeNull();
  });

  it("collapses a counted unknown-hop run to '· · · N hops'", () => {
    const withRun: RcaPathAttribution = {
      ...confirmed,
      path: {
        ...confirmed.path!,
        segments: [
          confirmed.path!.segments![0],
          { index: 1, segment_type: "unknown", ambiguous: false, unknown_hops: [4, 5, 6],
            reason: "3 hops did not respond" },
          confirmed.path!.segments![1],
        ],
      },
    };
    render(<RcaPathCausality data={withRun} />);
    expect(screen.getByText("3 hops")).toBeTruthy();
    expect(screen.queryByText("Unknown segment")).toBeNull();
  });

  it("marks an ambiguous (ECMP) segment", () => {
    const ecmp: RcaPathAttribution = {
      ...confirmed,
      path: {
        ...confirmed.path!,
        ambiguous: true,
        segments: [
          confirmed.path!.segments![0],
          { ...confirmed.path!.segments![1], ambiguous: true },
        ],
      },
    };
    render(<RcaPathCausality data={ecmp} />);
    expect(screen.getAllByText("ECMP").length).toBeGreaterThan(0);
  });

  it("renders an honest empty note when no path was attributed", () => {
    const { container } = render(<RcaPathCausality data={null} />);
    expect(screen.getByText(/Path not fully discovered/i)).toBeTruthy();
    // never a fabricated segment / device.
    expect(within(container).queryByText("Broke here")).toBeNull();
  });

  it("renders the empty note when attribution has no named cause", () => {
    render(<RcaPathCausality data={{
      verdict_tier: "suspected", baseline_verdict_tier: "suspected",
      confidence_lifted: false, capped: false, on_path_device_count: 0, attributed: null,
    }} />);
    expect(screen.getByText(/Path not fully discovered/i)).toBeTruthy();
  });

  it("renders the seam-ownership label and the honest 'possibly because of X' phrasing", () => {
    render(<RcaPathCausality data={confirmed}
      ownership="Lumen (DIA #12345) · ISP / carrier"
      possibleCause="packet loss on the ISP / middle-mile path" />);
    expect(screen.getByText(/Possibly because of/i)).toBeTruthy();
    expect(screen.getByText("packet loss on the ISP / middle-mile path")).toBeTruthy();
    expect(screen.getByText(/To engage:/i)).toBeTruthy();
    expect(screen.getByText("Lumen (DIA #12345) · ISP / carrier")).toBeTruthy();
  });
});

// ── merged single-logic fallbacks (owner P1 2026-07-19: one path view) ────────
describe("RcaPathCausality — merged fallback chain (pathModel.ts)", () => {
  const spineTimeline = () => {
    const tl = timeline({ verdict_tier: "suspected", signals: [] }) as ReturnType<typeof timeline> & { path?: unknown };
    tl.path = {
      spine: [
        { index: 0, kind: "client", label: "client-01", boundary: "LAN", state: "responding" },
        { index: 1, kind: "lan_gateway", label: "lan-gw", boundary: "LAN", state: "responding" },
        { index: 2, kind: "transit", boundary: "CARRIER", state: "missing" },
        { index: 3, kind: "wan_edge", label: "isp-edge", boundary: "CARRIER", state: "responding", fault: "suspected" },
        { index: 4, kind: "application", label: "app.example", boundary: "CLOUD", state: "responding", provider: "aws" },
      ],
      edges: [{ from: 3, to: 4, type: "PATH_HAS_HOP", state: "degraded", evidence: { ref: "ev1", method: "traceroute_icmp" } }],
      boundaries: [], evidence_branches: [],
    };
    return tl;
  };

  it("derives connected boundary segments + the red break from the measured spine when no typed path exists", () => {
    render(<RcaPathCausality data={null} timeline={spineTimeline()} />);
    // canonical boundary segments: Site LAN → WAN edge (the responding SD-WAN/
    // ISP edge device answers from the carrier-boundary span, so the span IS the
    // WAN edge construct) → Carrier (inferred — its hops are silent) → Cloud.
    expect(screen.getAllByText("Site LAN").length).toBeGreaterThan(0);
    expect(screen.getAllByText("WAN edge").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Carrier / middle mile").length).toBeGreaterThan(0);
    expect(screen.getByText(/carrier path inferred/i)).toBeTruthy();
    expect(screen.getAllByText("Cloud").length).toBeGreaterThan(0);
    // the fault mark sits on the LAST responding device before a dark carrier
    // leg across an ownership change — so the red hero sits ON the seam (owner
    // 2026-07-19: boundary break when the parties' handoff is the suspect), one
    // hero, suspected verdict, never definitive.
    expect(screen.getByText(/Possible break at this handoff/)).toBeTruthy();
    expect(screen.getAllByText(/enterprise ↔ carrier/).length).toBeGreaterThan(0);
    expect(screen.getByText(/broke at the/i)).toBeTruthy();
    // the last-responding device itself is NOT blamed (no device break tag)…
    expect(screen.queryByText("Possible break here")).toBeNull();
    expect(screen.getByText("isp-edge")).toBeTruthy();
    // health overlay per segment — toned words, never grey chips
    expect(screen.getByText("suspected down")).toBeTruthy();
    expect(screen.getByText("degraded")).toBeTruthy();
    // the silent hop collapses to a counted gap
    expect(screen.getByText("1 hop")).toBeTruthy();
    // still no observed/not-observed boxes in any mode
    expect(screen.queryByText(/observed/i)).toBeNull();
  });

  it("falls back to the named routing adjacency when no path exists at all", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}' })],
    });
    render(<RcaPathCausality data={null} timeline={tl} />);
    expect(screen.getByText(/localizes to this routing adjacency/i)).toBeTruthy();
    expect(screen.getAllByText("wan-r2").length).toBeGreaterThan(0);
    expect(screen.getAllByText("192.168.100.5").length).toBeGreaterThan(0);
    // no break invented, no observed boxes
    expect(screen.queryByText(/break here/i)).toBeNull();
    expect(screen.queryByText(/observed/i)).toBeNull();
  });

  it("says 'Internal monitoring path' for a platform self-probe object", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [signal({ kind: "probe_loss", modality_class: "active_probe", entity_id: "netops-probe", probe_scope: "internal_self_probe", probe_authority: "debug_only" })],
    });
    render(<RcaPathCausality data={null} timeline={tl} />);
    expect(screen.getByText(/Internal monitoring path/i)).toBeTruthy();
  });

  it("degrades to the honest 'path not fully discovered' sentence — no grey boxes", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      signals: [signal({ kind: "if_errors", modality_class: "device_telemetry", entity_id: "sw-3" })],
    });
    const { container } = render(<RcaPathCausality data={null} timeline={tl} />);
    expect(screen.getByText(/Path not fully discovered/i)).toBeTruthy();
    expect(container.querySelectorAll(".rpc-dev").length).toBe(0);
  });
});
