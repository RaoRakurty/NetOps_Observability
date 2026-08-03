// ReliabilityScorecard.test.tsx — the NOC Recovery Scorecard: readiness badge,
// evidence-coverage strip, NOC labels, muted unavailable recovery/closure cards,
// "No valid sample" (not 0 ms), object-aware actions, and an honest summary that
// never claims MTTR when recovery is missing.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));
vi.mock("../services/api", () => ({
  api: {
    reliabilityRollups: vi.fn(() => Promise.resolve({
      window_seconds: 2592000, mttf_ms: 0, mttf_asset_count: 0, capped: false, scan_cap: 5000, include_internal: false,
      rollup: {
        incident_count: 456, top_time_loss_phase: "evidence_bundle", repeat_incident_rate: 0.94, mtbf_ms: 242000000,
        metrics: {
          tti: { incident_count: 300, p50_ms: 1789000, p90_ms: 1813000, p95_ms: 1900000, mean_ms: 1800000 },
          ttc: { incident_count: 456, p50_ms: 1791000, p90_ms: 1820000, p95_ms: 1900000, mean_ms: 1800000 },
          // NO ttr_recovery / ttr_resolution → recovery + ticketing "missing"
        },
      },
      by_owner_domain: [
        { domain: "LAN", incident_count: 410, mtti_p90_ms: 1813000, recovery_p90_ms: 0, repeat_incident_rate: 0.95, top_delay_driver: "evidence_bundle" },
        { domain: "Cloud", incident_count: 46, mtti_p90_ms: 0, recovery_p90_ms: 0, repeat_incident_rate: 0.99, top_delay_driver: "root_isolation" },
      ],
    })),
    reliabilityTrends: vi.fn(() => Promise.resolve({ window_seconds: 2592000, bucket_seconds: 604800, buckets: [
      { bucket_start: "2026-06-11T00:00:00Z", incident_count: 10, repeat_incident_rate: 0.9, mtbf_ms: 1, metrics: { tti: { incident_count: 10, p50_ms: 1780000, p90_ms: 1810000, p95_ms: 1900000, mean_ms: 1800000 } } },
      { bucket_start: "2026-06-18T00:00:00Z", incident_count: 12, repeat_incident_rate: 0.9, mtbf_ms: 1, metrics: { tti: { incident_count: 12, p50_ms: 1790000, p90_ms: 1820000, p95_ms: 1900000, mean_ms: 1800000 } } },
    ] })),
    reliabilityChronicOffenders: vi.fn(() => Promise.resolve({ offenders: [
      { group_key: "device:spine1", incident_count: 70, mtbf_ms: 86400000, last_seen: "2026-06-24T00:00:00Z", owner_domain: "LAN" },
    ] })),
  },
}));

import ReliabilityScorecard from "./ReliabilityScorecard";

afterEach(cleanup);

describe("NOC Recovery Scorecard", () => {
  it("shows a Recovery Readiness badge (At Risk for high repeat + missing evidence)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/Recovery Readiness: At Risk/)).toBeTruthy();
    expect(screen.getByText(/\/100/)).toBeTruthy();
  });

  it("shows the evidence-coverage strip with recovery/ITSM Missing", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("Evidence coverage")).toBeTruthy();
    expect(screen.getByText("Correlation")).toBeTruthy();
    // Recovery + ITSM read "Missing"
    expect(screen.getAllByText("Missing").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("Connected").length).toBeGreaterThanOrEqual(2);
  });

  it("uses NOC labels + muted unavailable recovery/closure cards (no fabricated MTTR)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("Median root-domain isolation time")).toBeTruthy();
    expect(screen.getByText("Repeat-affected incidents")).toBeTruthy();
    expect(screen.getByText("Not measured")).toBeTruthy();              // recovery card value
    expect(screen.getByText("Recovery evidence not connected")).toBeTruthy(); // recovery subtext
    expect(screen.getByText("Not available")).toBeTruthy();             // closure card value
    expect(screen.getByText("ITSM workflow required")).toBeTruthy();    // closure subtext
  });

  it("never shows 0 ms for a no-sample percentile (Cloud MTTI p90 → No valid sample)", async () => {
    render(<ReliabilityScorecard />);
    await screen.findByText(/Owner Domain Breakdown/);
    expect(screen.getByText("No valid sample")).toBeTruthy();
    expect(screen.queryByText("0 ms")).toBeNull();
  });

  it("gives object-aware recommended actions (spine → fabric)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("DC Spine-1")).toBeTruthy();
    expect(screen.getByText(/uplink errors.*ECMP/)).toBeTruthy();
  });

  it("summary explains recovery/ITSM not measured (no measured-MTTR claim)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/not yet measured because recovery\/ITSM evidence is not connected/)).toBeTruthy();
  });
});
