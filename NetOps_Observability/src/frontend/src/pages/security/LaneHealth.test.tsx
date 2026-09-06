// LaneHealth.test.tsx — the producer lane's health strip on Security Overview.
//
// The assertions that matter are the ones that keep the panel from lying about
// the lane: a lane that is switched off must not read as an idle lane, a queued
// scan must not read as a finished one, a scan that assessed nothing must not
// read as a clean estate, and every control must hit the route it claims to.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const securityLaneStatus = vi.fn();
const securityScan = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityLaneStatus: (...a: unknown[]) => securityLaneStatus(...a),
    securityScan: (...a: unknown[]) => securityScan(...a),
  },
}));

import LaneHealth from "./LaneHealth";

const ROW = {
  tenant_id: "acme",
  tenant_seg: "t_acme",
  last_scan_id: "scan-t_acme-20260901T101500.000Z",
  last_scan_at: "2026-09-01T10:15:00Z",
  outcome: "ok",
  trigger: "ticker",
  duration_ms: 433,
  findings_emitted: 66,
  findings_truncated: 0,
  devices_assessed: 2,
};

const STATUS = {
  enabled: true,
  interval_seconds: 900,
  max_findings_per_tenant: 5000,
  topic: "netops.security",
  metrics: {
    scan_runs_total: 3,
    emitted_posture: 54,
    emitted_exposure: 10,
    emitted_signal: 2,
    ungroundable_total: 0,
    findings_truncated_total: 0,
    emit_failures_total: 0,
    dead_lettered_total: 0,
    lost_total: 0,
  },
  tenants: [ROW],
};

afterEach(cleanup);
beforeEach(() => {
  securityLaneStatus.mockReset();
  securityScan.mockReset();
  securityLaneStatus.mockResolvedValue(STATUS);
});

describe("LaneHealth — reading the lane", () => {
  it("reads /api/security/lane/status and renders the tenant's last run", async () => {
    render(<LaneHealth />);
    const table = await screen.findByRole("table", { name: /last run per tenant/i });
    expect(securityLaneStatus).toHaveBeenCalledTimes(1);
    expect(within(table).getByText("t_acme")).toBeTruthy();
    expect(within(table).getByText("ok")).toBeTruthy();
    expect(within(table).getByText("66")).toBeTruthy();
    expect(within(table).getByText("433 ms")).toBeTruthy();
  });

  it("renders the grounding counters, marking the ones that mean lost evidence", async () => {
    securityLaneStatus.mockResolvedValue({
      ...STATUS,
      metrics: { ...STATUS.metrics, ungroundable_total: 4, lost_total: 1 },
    });
    render(<LaneHealth />);
    const counters = await screen.findByRole("table", { name: /lane counters/i });
    const refused = within(counters).getByText("Refused grounding").closest("tr")!;
    expect(within(refused).getByText("4")).toBeTruthy();
    const lost = within(counters).getByText("No durable copy").closest("tr")!;
    expect(within(lost).getByText("1")).toBeTruthy();
  });

  it("a 404 says the lane is NOT ENABLED — never an idle or empty lane", async () => {
    securityLaneStatus.mockRejectedValue(new Error("404 Not Found: "));
    render(<LaneHealth />);
    // The 2026-09-06 word sweep moved WHY a disabled lane is not an empty
    // result into ai/skills/explain/lane.not-enabled.md. The claim is still on
    // screen; the reasoning is one click away, and BOTH are pinned here.
    expect(await screen.findByText(/not enabled here/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about the security lane/i })).toBeTruthy();
    expect(screen.getByText(/FEATURE_SECURITY_LANE/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /scan now/i })).toBeNull();
  });

  it("a 403 names the permission instead of rendering an empty lane", async () => {
    securityLaneStatus.mockRejectedValue(new Error("403 Forbidden: "));
    render(<LaneHealth />);
    expect(await screen.findByText(/needs administration access/i)).toBeTruthy();
  });

  it("a failed read says the lane's state is UNKNOWN, not idle", async () => {
    securityLaneStatus.mockRejectedValue(new Error("500 Internal Server Error: "));
    render(<LaneHealth />);
    expect(await screen.findByText(/unknown, not idle/i)).toBeTruthy();
  });

  it("an enabled lane with no recorded run says nothing was assessed", async () => {
    securityLaneStatus.mockResolvedValue({ ...STATUS, tenants: [] });
    render(<LaneHealth />);
    expect(await screen.findByText(/recorded no run yet/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about a lane that has never run/i })).toBeTruthy();
  });

  it("a degraded run lists what reported UNASSESSED rather than clear", async () => {
    securityLaneStatus.mockResolvedValue({
      ...STATUS,
      tenants: [{ ...ROW, outcome: "partial", errors: ["advisory-feed: feed unavailable"] }],
    });
    render(<LaneHealth />);
    expect(await screen.findByText(/reported unassessed, not clear/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about checks that reported unassessed/i })).toBeTruthy();
    expect(screen.getByText("advisory-feed: feed unavailable")).toBeTruthy();
  });

  it("a skipped run says the row still carries the last real result", async () => {
    securityLaneStatus.mockResolvedValue({ ...STATUS, tenants: [{ ...ROW, outcome: "skipped" }] });
    render(<LaneHealth />);
    expect(await screen.findByText("skipped")).toBeTruthy();
    expect(await screen.findByRole("button", { name: /Ask Iris about a skipped run/i })).toBeTruthy();
  });
});

describe("LaneHealth — Scan now", () => {
  it("POSTs /api/security/scan and reports the run's result count", async () => {
    const done = {
      ...STATUS,
      tenants: [{ ...ROW, trigger: "manual", findings_emitted: 12, devices_assessed: 5, last_scan_at: new Date().toISOString() }],
    };
    securityLaneStatus.mockResolvedValueOnce(STATUS).mockResolvedValue(done);
    securityScan.mockResolvedValue({ queued: true, tenant_seg: "t_acme" });

    render(<LaneHealth />);
    fireEvent.click(await screen.findByRole("button", { name: /scan now/i }));

    await waitFor(() => expect(securityScan).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/12 findings published from 5 devices assessed/i)).toBeTruthy();
  });

  it("a run that assessed no device is NOT reported as a clear estate", async () => {
    const done = {
      ...STATUS,
      tenants: [{ ...ROW, findings_emitted: 0, devices_assessed: 0, last_scan_at: new Date().toISOString() }],
    };
    securityLaneStatus.mockResolvedValueOnce(STATUS).mockResolvedValue(done);
    securityScan.mockResolvedValue({ queued: true, tenant_seg: "t_acme" });

    render(<LaneHealth />);
    fireEvent.click(await screen.findByRole("button", { name: /scan now/i }));
    expect(await screen.findByRole("button", { name: /Ask Iris about a scan that assessed nothing/i })).toBeTruthy();
  });

  it("a scan whose result has not landed reads as QUEUED, never as finished", async () => {
    // Status keeps answering with the OLD run, so nothing may claim completion.
    securityLaneStatus.mockResolvedValue(STATUS);
    securityScan.mockResolvedValue({ queued: true, tenant_seg: "t_acme" });

    render(<LaneHealth />);
    fireEvent.click(await screen.findByRole("button", { name: /scan now/i }));
    expect(await screen.findByText(/Scan queued for t_acme/i)).toBeTruthy();
    expect(screen.queryByText(/findings published from/i)).toBeNull();
  });

  it("a 429 says a scan is already running rather than swallowing the refusal", async () => {
    securityScan.mockRejectedValue(new Error("429 Too Many Requests: "));
    render(<LaneHealth />);
    fireEvent.click(await screen.findByRole("button", { name: /scan now/i }));
    expect(await screen.findByText(/already queued or running for this tenant/i)).toBeTruthy();
  });

  it("a cross-tenant 400 tells the operator to scope into a tenant first", async () => {
    securityScan.mockRejectedValue(new Error('400 Bad Request: {"error":"a scan needs one tenant"}'));
    render(<LaneHealth />);
    fireEvent.click(await screen.findByRole("button", { name: /scan now/i }));
    expect(await screen.findByText(/a scan needs one tenant/i)).toBeTruthy();
  });
});
