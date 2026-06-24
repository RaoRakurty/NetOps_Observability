// RcaTimeImpact.test.tsx — the Time Impact card renders real phase durations + the
// time-loss driver, EMPHASISES MTTI (isolation), labels inferred timestamps, and
// shows an honest "—" (never a fake 0) for phases with no data.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import type { TimeIntel } from "../../services/api";

const fixture: TimeIntel = {
  correlation_id: "abc",
  verdict_tier: "suspected",
  owner: "isp",
  evidence_missing: true,
  lifecycle: [
    { event_type: "first_signal", at: "2026-06-24T12:00:00Z", timestamp_source: "observed", confidence: 1 },
    { event_type: "detected", at: "2026-06-24T12:00:05Z", timestamp_source: "observed", confidence: 1 },
    { event_type: "root_domain_identified", at: "2026-06-24T12:01:24Z", timestamp_source: "observed", confidence: 0.8 },
  ],
  metrics: [
    { metric_name: "ttd", complete: true, duration_ms: 5000, start_event_type: "impact_started", end_event_type: "detected", confidence: 1, is_inferred: true, calculation_version: "ti-1" },
    { metric_name: "tti", complete: true, duration_ms: 84000, start_event_type: "first_signal", end_event_type: "root_domain_identified", confidence: 0.8, is_inferred: false, calculation_version: "ti-1" },
    { metric_name: "tta", complete: false, duration_ms: 0, start_event_type: "ticket_created", end_event_type: "acknowledged", confidence: 1, is_inferred: false, missing_event: "ticket_created", calculation_version: "ti-1" },
  ],
  time_loss_driver: "provider_repair",
  time_loss_explanation: "owner identified as isp; provider repair pending",
  calculation_version: "ti-1",
};

vi.mock("../../services/api", () => ({
  api: { correlationTimeMetrics: vi.fn(() => Promise.resolve(fixture)) },
}));

import RcaTimeImpact from "./RcaTimeImpact";

afterEach(cleanup);

describe("RcaTimeImpact", () => {
  it("renders the time-loss driver, MTTI emphasis, and honest incomplete phases", async () => {
    render(<RcaTimeImpact correlationId="abc" />);

    // time-loss driver headline (precise wording, not marketing)
    expect(await screen.findByText(/provider repair pending/i)).toBeTruthy();
    expect(screen.getByText("Provider repair")).toBeTruthy();

    // MTTI (the differentiator) row present with its duration
    expect(screen.getByText(/Root \/ seam isolated in/)).toBeTruthy();
    expect(screen.getByText(/1m 24s/)).toBeTruthy(); // 84000ms

    // detection complete + inferred chip
    expect(screen.getByText(/Detected in/)).toBeTruthy();
    expect(screen.getByText("inferred")).toBeTruthy();

    // an ITSM-dependent phase is honestly incomplete (awaiting), not zero
    await waitFor(() => expect(screen.getByText(/awaiting ticket created/i)).toBeTruthy());
  });
});
