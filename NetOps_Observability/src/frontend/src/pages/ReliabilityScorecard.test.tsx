// ReliabilityScorecard.test.tsx — the NOC Recovery Scorecard: NOC-friendly stat
// labels, exec insight strip, owner-domain breakdown, enriched chronic offenders,
// unavailable states explained (not bare dashes), and the include-internal default.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

vi.mock("echarts-for-react", () => ({ default: () => <div data-testid="chart" /> }));
vi.mock("../services/api", () => ({
  api: {
    reliabilityRollups: vi.fn(() => Promise.resolve({
      window_seconds: 2592000, mttf_ms: 0, mttf_asset_count: 0, capped: false, scan_cap: 5000, include_internal: false,
      rollup: {
        incident_count: 312, top_time_loss_phase: "evidence_bundle", repeat_incident_rate: 0.28, mtbf_ms: 242000000,
        metrics: {
          tti: { incident_count: 300, p50_ms: 383000, p90_ms: 1120000, p95_ms: 1500000, mean_ms: 500000 },
          ttc: { incident_count: 312, p50_ms: 165000, p90_ms: 300000, p95_ms: 350000, mean_ms: 180000 },
          // NO ttr_recovery / ttr_resolution → must render "No recovery evidence" / "Workflow required"
        },
      },
      by_owner_domain: [
        { domain: "ISP", incident_count: 44, mtti_p90_ms: 1120000, recovery_p90_ms: 0, repeat_incident_rate: 0.3, top_delay_driver: "evidence_bundle" },
        { domain: "Cloud", incident_count: 120, mtti_p90_ms: 0, recovery_p90_ms: 0, repeat_incident_rate: 0.4, top_delay_driver: "root_isolation" },
      ],
    })),
    reliabilityTrends: vi.fn(() => Promise.resolve({ window_seconds: 2592000, bucket_seconds: 604800, buckets: [
      { bucket_start: "2026-06-11T00:00:00Z", incident_count: 10, repeat_incident_rate: 0.3, mtbf_ms: 1, metrics: { tti: { incident_count: 10, p50_ms: 380000, p90_ms: 900000, p95_ms: 1000000, mean_ms: 500000 } } },
      { bucket_start: "2026-06-18T00:00:00Z", incident_count: 12, repeat_incident_rate: 0.3, mtbf_ms: 1, metrics: { tti: { incident_count: 12, p50_ms: 400000, p90_ms: 950000, p95_ms: 1100000, mean_ms: 520000 } } },
    ] })),
    reliabilityChronicOffenders: vi.fn(() => Promise.resolve({ offenders: [
      { group_key: "device:spine1", incident_count: 9, mtbf_ms: 86400000, last_seen: "2026-06-24T00:00:00Z", owner_domain: "LAN" },
    ] })),
  },
}));

import ReliabilityScorecard from "./ReliabilityScorecard";

afterEach(cleanup);

describe("NOC Recovery Scorecard", () => {
  it("renders NOC title, exec strip, NOC stat labels, and MTTI hero value", async () => {
    render(<ReliabilityScorecard />);
    expect(screen.getByText("NOC Recovery Scorecard")).toBeTruthy();
    expect(await screen.findByText("Median Time to Isolate")).toBeTruthy(); // async data loaded
    expect(screen.getByText(/summary:/)).toBeTruthy(); // exec insight strip
    expect(screen.getByText("P90 Isolation Time")).toBeTruthy();
    expect(screen.getAllByText(/6m 23s/).length).toBeGreaterThan(0); // 383000ms MTTI p50
  });

  it("explains unavailable recovery/resolution (no bare dash)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("No recovery evidence")).toBeTruthy();
    expect(screen.getByText("Workflow required")).toBeTruthy();
  });

  it("shows the owner-domain breakdown and enriched chronic offenders with actions", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/Owner Domain Breakdown/)).toBeTruthy();
    expect(screen.getAllByText("ISP").length).toBeGreaterThan(0);
    // chronic offender enriched name + recommended action
    expect(screen.getByText("DC Spine-1")).toBeTruthy();
    expect(screen.getByText(/Check optics/)).toBeTruthy();
  });

  it("maps the top delay driver to NOC language (Evidence Missing)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findAllByText("Evidence Missing")).toBeTruthy();
  });
});
