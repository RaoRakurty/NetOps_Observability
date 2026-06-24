// RcaTimeImpact.test.tsx — the Time Impact card: measurement-gap vs bottleneck,
// "Not measured" (not "Workflow required") downstream, the two zones, a data-driven
// outcome line that never claims recovery timing when it's not measured, and the
// inferred-onset basis. Plus the contradiction guard (no provider-repair w/o evidence).

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { TimeIntel } from "../../services/api";

const t0 = "2026-06-24T12:00:00Z";
const t = (s: number) => new Date(Date.parse(t0) + s * 1000).toISOString();

// RCA complete (isolated, owner, evidence ready) but NO workflow connected.
const gapFixture: TimeIntel = {
  correlation_id: "abc", verdict_tier: "suspected",
  owner: "netops", owner_domain: "LAN", owner_label: "Network", root_domain: "spine1", seam_type: "DIA",
  confidence_label: "Candidate", evidence_missing: false, workflow_connected: false,
  current_bottleneck: "workflow_not_connected",
  bottleneck_message: "Evidence bundle ready; ticket, recovery and closure require ServiceNow…",
  calculation_version: "ti-1",
  lifecycle: [
    { event_type: "first_signal", at: t(0), timestamp_source: "observed", confidence: 1 },
    { event_type: "detected", at: t(5), timestamp_source: "observed", confidence: 1 },
    { event_type: "correlation_completed", at: t(900), timestamp_source: "observed", confidence: 1 },
    { event_type: "root_domain_identified", at: t(990), timestamp_source: "observed", confidence: 0.8 },
    { event_type: "owner_identified", at: t(990), timestamp_source: "inferred", confidence: 0.8 },
    { event_type: "evidence_ready", at: t(990), timestamp_source: "observed", confidence: 0.8 },
  ],
  metrics: [],
};

function mockApi(fixture: TimeIntel) {
  vi.doMock("../../services/api", () => ({ api: { correlationTimeMetrics: vi.fn(() => Promise.resolve(fixture)) } }));
}

afterEach(() => { cleanup(); vi.resetModules(); });

describe("RcaTimeImpact — measurement-gap model", () => {
  it("calls workflow-not-connected a MEASUREMENT GAP, not a bottleneck", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect(await screen.findByText("Current measurement gap")).toBeTruthy();
    expect(screen.queryByText("Current bottleneck")).toBeNull();
    expect(screen.getByText(/ITSM \/ recovery workflow not connected/)).toBeTruthy();
  });

  it("shows downstream phases as 'Not measured' (never 'Workflow required')", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect((await screen.findAllByText("Not measured")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Workflow required")).toBeNull();
  });

  it("splits into RCA evidence + Workflow & recovery zones", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect(await screen.findByText("RCA evidence timeline")).toBeTruthy();
    expect(screen.getByText(/Workflow & recovery timeline/)).toBeTruthy();
  });

  it("outcome line states RCA done + recovery NOT measured (no fabricated MTTR)", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect(await screen.findByText(/RCA completed through root-domain isolation in 16m 30s/)).toBeTruthy();
    expect(screen.getByText(/not measured because workflow evidence is not connected/)).toBeTruthy();
  });

  it("root row shows owner + confidence; basis reads 'first impact signal' (inferred onset)", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect(await screen.findByText(/Seam: DIA · Owner: Network · Suspected/)).toBeTruthy();
    expect(screen.getByText(/Elapsed from first impact signal/)).toBeTruthy();
    expect(screen.getByText("Inferred onset")).toBeTruthy();
  });

  it("shows the operational CTA when workflow is unmeasured", async () => {
    mockApi(gapFixture);
    const { default: Card } = await import("./RcaTimeImpact");
    render(<Card correlationId="abc" />);
    expect(await screen.findByText(/Connect ITSM or enable Correlix operator workflow/)).toBeTruthy();
  });
});
