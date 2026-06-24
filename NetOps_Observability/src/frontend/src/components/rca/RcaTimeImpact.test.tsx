// RcaTimeImpact.test.tsx — the Time Impact card: phase-consistent CURRENT BOTTLENECK
// (no provider-repair while evidence is missing), Owner-assigned row, "Evidence
// bundle ready" wording, natural pending text, inferred chip, root-isolated owner/
// confidence context, and the elapsed-from-impact basis line.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { TimeIntel } from "../../services/api";

const t0 = "2026-06-24T12:00:00Z";
const t = (s: number) => new Date(Date.parse(t0) + s * 1000).toISOString();

// Evidence-missing ISP incident: isolated + owner, but evidence not ready, no workflow.
const fixture: TimeIntel = {
  correlation_id: "abc", verdict_tier: "suspected",
  owner: "isp", owner_domain: "ISP", owner_label: "ISP", root_domain: "wan-r2",
  confidence_label: "Candidate", evidence_missing: true, workflow_connected: false,
  current_bottleneck: "evidence_bundle",
  bottleneck_message: "ISP-owned seam isolated; provider escalation is waiting on evidence readiness.",
  calculation_version: "ti-1",
  lifecycle: [
    { event_type: "first_signal", at: t(0), timestamp_source: "observed", confidence: 1 },
    { event_type: "detected", at: t(5), timestamp_source: "observed", confidence: 1 },
    { event_type: "correlation_completed", at: t(120), timestamp_source: "observed", confidence: 1 },
    { event_type: "root_domain_identified", at: t(120), timestamp_source: "observed", confidence: 0.8 },
    { event_type: "owner_identified", at: t(120), timestamp_source: "inferred", confidence: 0.8 },
  ],
  metrics: [],
};

vi.mock("../../services/api", () => ({
  api: { correlationTimeMetrics: vi.fn(() => Promise.resolve(fixture)) },
}));

import RcaTimeImpact from "./RcaTimeImpact";

afterEach(cleanup);

describe("RcaTimeImpact — current bottleneck + NOC refinements", () => {
  it("shows the phase-consistent CURRENT BOTTLENECK (evidence, NOT provider repair)", async () => {
    render(<RcaTimeImpact correlationId="abc" />);
    expect(await screen.findByText("Current bottleneck")).toBeTruthy();
    expect(screen.getByText("Evidence bundle pending")).toBeTruthy();
    expect(screen.getByText(/waiting on evidence readiness/)).toBeTruthy();
    // the bug guard: provider-repair copy must NOT appear while evidence is missing
    expect(screen.queryByText(/Provider repair pending/)).toBeNull();
  });

  it("has the Owner-assigned row and 'Evidence bundle ready' wording", async () => {
    render(<RcaTimeImpact correlationId="abc" />);
    expect(await screen.findByText("Owner assigned")).toBeTruthy();
    expect(screen.getByText("Evidence bundle ready")).toBeTruthy();
    expect(screen.getByText("Root / seam isolated")).toBeTruthy();
  });

  it("uses natural pending language + workflow-required (no bare dash)", async () => {
    render(<RcaTimeImpact correlationId="abc" />);
    expect(await screen.findByText("Awaiting evidence bundle")).toBeTruthy();
    // ITSM phases with no workflow connected read "Workflow required"
    expect(screen.getAllByText("Workflow required").length).toBeGreaterThan(0);
  });

  it("shows the elapsed-from-impact basis (inferred) + root-isolated owner/confidence context", async () => {
    render(<RcaTimeImpact correlationId="abc" />);
    expect(await screen.findByText(/Elapsed from inferred impact onset/)).toBeTruthy();
    expect(screen.getByText(/ISP-owned · Candidate/)).toBeTruthy();
  });
});
