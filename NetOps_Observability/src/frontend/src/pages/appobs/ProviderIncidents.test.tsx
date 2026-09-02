// ProviderIncidents.test.tsx (Wave 5 #16) — the provider-incident lane and the
// seam health strip render ONLY measured data, with honest empty states: no
// events names the support-plan requirement, no seam signals says "awaiting
// telemetry" — never a green guess.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { CloudProviderEventRow, CloudSeamTelemetryRow } from "../../services/api";

const h = vi.hoisted(() => {
  const event = (over: Partial<CloudProviderEventRow> = {}): CloudProviderEventRow => ({
    time: "2026-07-18T12:00:00Z", provider: "aws", service: "EC2",
    region: "us-west-2", category: "issue", status: "open",
    summary: "AWS EC2 OPERATIONAL ISSUE", severity: "high", ...over,
  });
  const seam = (over: Partial<CloudSeamTelemetryRow> = {}): CloudSeamTelemetryRow => ({
    seam_id: "vpn:vpn-0abc:52.1.2.3", state: "down", kind: "cloud_vpn_tunnel_down",
    severity: "critical", last_seen: "2026-07-18T12:00:00Z", events: 3,
    provider: "aws", evidence_class: "state_transition", ...over,
  });
  return {
    event, seam,
    mock: {
      cloudProviderEvents: vi.fn(async () => ({ events: [event()], count: 1, window_hours: 24 })),
      cloudSeamTelemetry: vi.fn(async () => ({ seams: [seam()], count: 1, window_hours: 24 })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import { ProviderIncidentsPanel, SeamHealthStrip, seamShortLabel } from "./ProviderIncidents";

const mock = h.mock;

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("ProviderIncidentsPanel", () => {
  it("renders the provider's own events with category labels", async () => {
    mock.cloudProviderEvents.mockResolvedValueOnce({
      events: [h.event(), h.event({ service: "RDS", category: "scheduledChange",
        severity: "warn", summary: "AWS RDS MAINTENANCE SCHEDULED" })],
      count: 2, window_hours: 24,
    });
    render(<ProviderIncidentsPanel />);
    expect(await screen.findByText("EC2")).toBeInTheDocument();
    expect(screen.getByText("Incident")).toBeInTheDocument();
    expect(screen.getByText("Maintenance")).toBeInTheDocument();
    expect(screen.getByText("AWS EC2 OPERATIONAL ISSUE")).toBeInTheDocument();
  });

  it("honest empty state names the support-plan requirement", async () => {
    mock.cloudProviderEvents.mockResolvedValueOnce({ events: [], count: 0, window_hours: 24 });
    render(<ProviderIncidentsPanel />);
    expect(await screen.findByText("No provider incidents reported in the window")).toBeInTheDocument();
    expect(screen.getByText(/Business or Enterprise support plan/)).toBeInTheDocument();
  });

  it("a failed read shows the load error, never an empty-success state", async () => {
    mock.cloudProviderEvents.mockRejectedValueOnce(new Error("503"));
    render(<ProviderIncidentsPanel />);
    expect(await screen.findByText("Unable to load provider incidents")).toBeInTheDocument();
  });
});

describe("SeamHealthStrip", () => {
  it("renders one chip per seam with its measured state", async () => {
    mock.cloudSeamTelemetry.mockResolvedValueOnce({
      seams: [h.seam(), h.seam({ seam_id: "dxbgp:vif-1:p1", state: "up", kind: "cloud_bgp_session_up" })],
      count: 2, window_hours: 24,
    });
    render(<SeamHealthStrip />);
    expect(await screen.findByText("vpn vpn-0abc · down")).toBeInTheDocument();
    expect(screen.getByText("dxbgp vif-1 · up")).toBeInTheDocument();
  });

  it("no seam signals → 'awaiting telemetry', never a green guess", async () => {
    mock.cloudSeamTelemetry.mockResolvedValueOnce({ seams: [], count: 0, window_hours: 24 });
    render(<SeamHealthStrip />);
    expect(await screen.findByText("Awaiting seam telemetry")).toBeInTheDocument();
    expect(screen.getByText(/built and collecting/)).toBeInTheDocument();
  });

  it("seamShortLabel reduces seam keys to readable chips", () => {
    expect(seamShortLabel("vpn:vpn-0abc:52.1.2.3")).toBe("vpn vpn-0abc");
    expect(seamShortLabel("dxconn:dxcon-1")).toBe("dxconn dxcon-1");
    expect(seamShortLabel("plainkey")).toBe("plainkey");
  });
});
