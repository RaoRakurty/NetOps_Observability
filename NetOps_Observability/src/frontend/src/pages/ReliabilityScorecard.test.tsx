// ReliabilityScorecard.test.tsx — the NOC Recovery Scorecard: readiness badge,
// evidence-coverage strip, NOC labels, muted unavailable recovery/closure cards,
// "No valid sample" (not 0 ms), object-aware actions, and an honest summary that
// never claims MTTR when recovery is missing.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { IncidentTimeMetricRow, IncidentTimeMetric } from "../services/api";

// The persisted phase-metric snapshot read is steered per test, so the trend
// panel can be exercised with measured, all-incomplete, and dead responses.
const hoisted = vi.hoisted(() => ({ timeMetrics: vi.fn() }));

vi.mock("../components/EChart", () => ({
  default: ({ option }: { option?: { series?: { name?: string; data?: unknown[] }[] } }) => (
    <div data-testid="chart" data-series={(option?.series ?? []).map((s) => `${s.name}=${JSON.stringify(s.data)}`).join("|")} />
  ),
}));
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
    // Project 2 P7 — the verdict-feedback tile fetches its own 30-day summary.
    rcaFeedbackSummary: vi.fn(() => Promise.resolve({
      days: 30, since: "2026-05-25T00:00:00Z", n: 0,
      counts: { correct: 0, wrong: 0, partial: 0 }, false_positive_rate: null, by_template: [],
    })),
    // #84 persisted phase-metric snapshots — the detection/repair trend.
    reliabilityTimeMetrics: hoisted.timeMetrics,
  },
}));

import ReliabilityScorecard from "./ReliabilityScorecard";

// Inside the page's default 30-day window, whatever day the suite runs.
const daysAgo = (n: number) => new Date(Date.now() - n * 86400_000).toISOString();

function phase(name: string, ms: number): IncidentTimeMetric {
  return {
    metric_name: name, complete: true, duration_ms: ms,
    start_event_type: "impact_started", end_event_type: name === "ttd" ? "detected" : "recovered",
    confidence: 1, is_inferred: false, calculated_at: daysAgo(1), calculation_version: "v1",
  };
}
function unmeasured(name: string, missing: string): IncidentTimeMetric {
  return {
    metric_name: name, complete: false, duration_ms: 0,
    start_event_type: "impact_started", end_event_type: missing,
    confidence: 0, is_inferred: false, blocked_by: `missing ${missing}`, missing_event: missing,
    calculated_at: daysAgo(1), calculation_version: "v1",
  };
}
function snapshot(id: string, days: number, metrics: IncidentTimeMetric[]): IncidentTimeMetricRow {
  return {
    correlation_id: id, calculation_version: "v1", occurred_at: daysAgo(days),
    owner_domain: "LAN", current_bottleneck: "recovery", metrics,
    calculated_at: daysAgo(days), internal: false, maintenance: false,
  };
}

beforeEach(() => {
  hoisted.timeMetrics.mockReset();
  hoisted.timeMetrics.mockResolvedValue({ snapshots: [] });
});

afterEach(cleanup);

describe("NOC Recovery Scorecard", () => {
  it("shows a Recovery Readiness badge (At Risk for high repeat + missing evidence)", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/Recovery Readiness: At Risk/)).toBeTruthy();
    expect(screen.getByText(/\/100/)).toBeTruthy();
  });

  it("an empty trend offers the action instead of spelling it out", async () => {
    hoisted.timeMetrics.mockResolvedValue({ snapshots: [] });
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("Nothing recorded in this window yet.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about Phase timings" })).toBeTruthy();
    expect(screen.queryByText(/phase timings appear once incidents are analyzed/)).toBeNull();
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
    await screen.findByText("Owner domains");
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

  // ── words (sweep 5, tracker 270) ──────────────────────────────────────────
  // Every metric definition that used to sit in a card tooltip is an authored
  // file behind the (i). The card still names its number; the (i) still names
  // the metric, so the assertion is on BOTH — a card that quietly lost its
  // explanation affordance is as broken as one that kept the paragraph.
  it("a card states its number and hands the definition to Iris", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("Median root-domain isolation time")).toBeTruthy();
    for (const label of [
      "Customer-impacting incidents",
      "Median root-domain isolation time",
      "P90 root-domain isolation time",
      "Median correlation time",
      "Median recovery time",
      "Median ticket closure time",
      "Repeat failure interval",
      "Repeat-affected incidents",
      "Top time-loss driver",
    ]) {
      expect(screen.getByRole("button", { name: `Ask Iris about ${label}` })).toBeTruthy();
    }
    // …and the definitions themselves are gone from the screen.
    expect(screen.queryByText(/Mean Time Between Failures/)).toBeNull();
    expect(screen.queryByText(/long-tail isolation/)).toBeNull();
  });

  it("the header states the page and asks Iris for the readiness recipe", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("Where incident time is spent.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about Recovery Readiness" })).toBeTruthy();
    expect(screen.queryByText(/deterministic score from repeat rate/)).toBeNull();
  });

  it("panel titles are short headings, not sentences", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByRole("heading", { name: "Owner domains" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Lifecycle time breakdown" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Recurring failure sources" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Isolation trend" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Detection and repair trend" })).toBeTruthy();
  });

  it("the window footnote states scope only — the two clocks are Iris's to explain", async () => {
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/customer-impacting incidents only/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about Investigation and repair clocks" })).toBeTruthy();
    expect(screen.queryByText(/separates the investigation clock from the repair clock/)).toBeNull();
  });
});

// ── Detection & repair trend (persisted phase-metric snapshots, #84) ─────────
// The rules under test are the honesty rules: an unmeasured phase is a stated
// gap and never a zero, and this panel's own read failing must not take the
// rest of the scorecard down with it.
describe("NOC Recovery Scorecard — detection and repair trend", () => {
  it("reads the recorded snapshots with an explicit limit the route accepts", async () => {
    render(<ReliabilityScorecard />);
    await screen.findByText(/Detection and repair trend/);
    expect(hoisted.timeMetrics).toHaveBeenCalledWith(500);
  });

  it("charts MTTD and MTTR from the recorded snapshots, gaps left as gaps", async () => {
    hoisted.timeMetrics.mockResolvedValue({ snapshots: [
      snapshot("a", 3, [phase("ttd", 30_000), phase("ttr_recovery", 600_000)]),
      snapshot("b", 3, [phase("ttd", 10_000)]),
      snapshot("c", 10, [phase("ttd", 90_000)]),
    ] });
    render(<ReliabilityScorecard />);
    await screen.findByText(/Detection and repair trend/);
    const chart = await screen.findByText(
      /complete detection and recovery lifecycle/,
    );
    expect(chart).toBeTruthy();
    const series = screen.getAllByTestId("chart").map((el) => el.getAttribute("data-series") ?? "");
    const trend = series.find((s) => s.includes("MTTD"));
    expect(trend).toBeTruthy();
    expect(trend).toContain("MTTR — Recover");
    // 30s and 10s in one bucket → the nearest-rank median, 10s; unmeasured
    // buckets are null (a gap), never 0.
    expect(trend).toMatch(/MTTD — Detect=\[[^\]]*10[,\]]/);
    expect(trend).toContain("null");
  });

  it("an all-incomplete window reads Not measured and names the missing signal, never a zero", async () => {
    hoisted.timeMetrics.mockResolvedValue({ snapshots: [
      snapshot("a", 2, [unmeasured("ttd", "detected"), unmeasured("ttr_recovery", "recovered")]),
      snapshot("b", 4, [unmeasured("ttr_recovery", "recovered")]),
      snapshot("c", 6, [unmeasured("ttr_recovery", "recovered")]),
    ] });
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/Not measured in this window/)).toBeTruthy();
    expect(screen.getByText(/waiting on a service-recovery signal/)).toBeTruthy();
    expect(screen.getByText(/none of the 3 incidents/)).toBeTruthy();
    expect(screen.queryByText(/0s/)).toBeNull();
    expect(screen.queryByText("0 ms")).toBeNull();
  });

  it("names the incomplete incidents alongside a chart that does have measurements", async () => {
    hoisted.timeMetrics.mockResolvedValue({ snapshots: [
      snapshot("a", 3, [phase("ttd", 30_000), unmeasured("ttr_recovery", "recovered")]),
      snapshot("b", 5, [phase("ttd", 20_000), unmeasured("ttr_recovery", "recovered")]),
    ] });
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/2 of 2 incidents in this window have an incomplete lifecycle/)).toBeTruthy();
    expect(screen.getByText(/2 phases waiting on a service-recovery signal/)).toBeTruthy();
  });

  it("counts a recalculated incident once (a calculation-version bump is not a second incident)", async () => {
    hoisted.timeMetrics.mockResolvedValue({ snapshots: [
      { ...snapshot("a", 3, [phase("ttd", 30_000)]), calculation_version: "v2", calculated_at: daysAgo(1) },
      { ...snapshot("a", 3, [phase("ttd", 30_000)]), calculation_version: "v1", calculated_at: daysAgo(3) },
    ] });
    render(<ReliabilityScorecard />);
    expect(await screen.findByText(/All 1 incident in this window/)).toBeTruthy();
  });

  it("a dead snapshot read shows an operator sentence and leaves the rest of the scorecard alive", async () => {
    hoisted.timeMetrics.mockRejectedValue(new Error('500 Internal Server Error: {"error":"pg: dial tcp 10.0.0.4:5432: connect: connection refused"}'));
    render(<ReliabilityScorecard />);
    expect(await screen.findByText("The service did not answer.")).toBeTruthy();
    // no raw failure text reaches the screen
    expect(screen.queryByText(/connection refused/)).toBeNull();
    // …and the panels that do not depend on this read are still standing
    expect(screen.getByText("Evidence coverage")).toBeTruthy();
    expect(screen.getByText(/Recovery Readiness/)).toBeTruthy();
    expect(screen.getByText("Median root-domain isolation time")).toBeTruthy();
  });
});
