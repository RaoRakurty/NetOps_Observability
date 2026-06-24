// ReliabilityScorecard.test.tsx — the exec scorecard renders percentile phase stats
// (MTTI emphasised), chronic offenders, and surfaces honest caveats (cap +
// internal-stack note). ECharts is mocked (no canvas in jsdom).

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

vi.mock("echarts-for-react", () => ({ default: () => <div data-testid="chart" /> }));
vi.mock("../services/api", () => ({
  api: {
    reliabilityRollups: vi.fn(() => Promise.resolve({
      window_seconds: 2592000, mttf_ms: 0, mttf_asset_count: 0, capped: true,
      note: "includes internal-stack incidents until #76 engine-side exclusion lands",
      rollup: {
        incident_count: 42, top_time_loss_phase: "evidence_missing", repeat_incident_rate: 0.5, mtbf_ms: 3600000,
        metrics: {
          tti: { incident_count: 40, p50_ms: 84000, p90_ms: 120000, p95_ms: 150000, mean_ms: 90000 },
          ttc: { incident_count: 42, p50_ms: 30000, p90_ms: 60000, p95_ms: 70000, mean_ms: 35000 },
        },
      },
    })),
    reliabilityTrends: vi.fn(() => Promise.resolve({ window_seconds: 2592000, bucket_seconds: 604800, buckets: [
      { bucket_start: "2026-06-18T00:00:00Z", incident_count: 10, repeat_incident_rate: 0.4, mtbf_ms: 1000,
        metrics: { tti: { incident_count: 10, p50_ms: 80000, p90_ms: 100000, p95_ms: 110000, mean_ms: 85000 } } },
    ] })),
    reliabilityChronicOffenders: vi.fn(() => Promise.resolve({ offenders: [
      { group_key: "device:rtr1", incident_count: 12, mtbf_ms: 7200000, last_seen: "2026-06-24T00:00:00Z" },
    ] })),
  },
}));

import ReliabilityScorecard from "./ReliabilityScorecard";

afterEach(cleanup);

describe("ReliabilityScorecard", () => {
  it("renders MTTI percentiles, chronic offenders, and the honest cap/note", async () => {
    render(<ReliabilityScorecard />);
    expect(screen.getByText("Operational Recovery Scorecard")).toBeTruthy();

    // MTTI p50 emphasis (84000ms = 1m 24s)
    expect(await screen.findByText(/MTTI p50/)).toBeTruthy();
    expect(screen.getByText("1m 24s")).toBeTruthy();

    // top time-loss phase mapped to friendly label
    expect(screen.getByText("Evidence readiness")).toBeTruthy();

    // chronic offender row
    expect(screen.getByText("device:rtr1")).toBeTruthy();

    // honesty: cap warning + internal-stack note both shown
    expect(screen.getByText(/5,000-incident scan cap/)).toBeTruthy();
    expect(screen.getByText(/internal-stack incidents until #76/)).toBeTruthy();
  });
});
