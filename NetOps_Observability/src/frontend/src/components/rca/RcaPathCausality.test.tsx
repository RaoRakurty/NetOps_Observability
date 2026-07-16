// RcaPathCausality.test.tsx — the path-first RCA render (design §5/§5a). Asserts the
// discovered typed path draws as customer-labeled segments, the attributed cause is
// highlighted as the broken link, opaque segments render greyed WITH their reason, a
// capped verdict never over-claims, cloud devices deep-link into Cloud Logs, and the
// absent case renders an honest "no discovered path" note (never a fabricated path).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import type { RcaPathAttribution } from "../../services/api";
import RcaPathCausality from "./RcaPathCausality";

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
    // segment types use customer labels — never the raw tokens. "Cloud" appears
    // both in the headline claim and as the segment name — both are customer text.
    expect(screen.getAllByText("Cloud").length).toBeGreaterThan(0);
    expect(screen.getAllByText("LAN").length).toBeGreaterThan(0);
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
    // the cause device carries the broken-link tag.
    expect(screen.getByText("Broke here")).toBeTruthy();
    // verdict LIFT: confirmed now, suspected baseline.
    expect(screen.getByText("Confirmed")).toBeTruthy();
    expect(screen.getByText("Suspected")).toBeTruthy();
    expect(screen.getByText(/lifted by on-path evidence/i)).toBeTruthy();
    // explained-away downstream victim is secondary, not blamed.
    expect(screen.getByText("Downstream")).toBeTruthy();
    // discounted off-path fault is listed as ruled-out.
    expect(screen.getByText(/Ruled out \(off-path\)/i)).toBeTruthy();
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
    // the opaque segment shows its reason, not a fabricated device.
    expect(screen.getByText("Unknown segment")).toBeTruthy();
    expect(screen.getByText(/no telemetry crosses this provider backbone/i)).toBeTruthy();
    // the honesty cap is surfaced — reads suspected, never confirmed.
    expect(screen.getByText(/Verdict capped/i)).toBeTruthy();
    expect(screen.getByText(/unknown\/opaque/i)).toBeTruthy();
    expect(screen.queryByText("Confirmed")).toBeNull();
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
    expect(screen.getByText(/No discovered path for this incident/i)).toBeTruthy();
    // never a fabricated segment / device.
    expect(within(container).queryByText("Broke here")).toBeNull();
  });

  it("renders the empty note when attribution has no named cause", () => {
    render(<RcaPathCausality data={{
      verdict_tier: "suspected", baseline_verdict_tier: "suspected",
      confidence_lifted: false, capped: false, on_path_device_count: 0, attributed: null,
    }} />);
    expect(screen.getByText(/No discovered path for this incident/i)).toBeTruthy();
  });
});
