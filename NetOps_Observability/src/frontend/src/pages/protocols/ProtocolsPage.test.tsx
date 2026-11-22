// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const devices = vi.fn();
const correlations = vi.fn();
const igpAdjacencies = vi.fn();
const igpSummary = vi.fn();
const metricLine = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    devices: (...a: unknown[]) => devices(...a),
    correlations: (...a: unknown[]) => correlations(...a),
    igpAdjacencies: (...a: unknown[]) => igpAdjacencies(...a),
    igpSummary: (...a: unknown[]) => igpSummary(...a),
    igpHealth: () => Promise.resolve(null),
  },
}));
vi.mock("../../components/board/panels", () => ({
  Panel: ({ title, children }: { title: string; children: React.ReactNode }) => <section aria-label={title}>{children}</section>,
  MetricLine: ({ title }: { title: string }) => { metricLine(title); return <div data-testid="metric-line">{title}</div>; },
}));
vi.mock("../BgpOps", () => ({
  default: ({ embedded }: { embedded?: boolean }) => <div data-testid="bgp-ops" data-embedded={embedded ? "yes" : "no"} />,
}));

import ProtocolsPage from "./ProtocolsPage";

const cov = { events: true, live_series: true, lsdb: false, areas: false, spf_runs: false, timers: false };
const depth = {
  lsdb: { lsp_count: null, note: "n" }, areas: { areas: null, note: "n" },
  spf_runs: { runs: null, note: "n" }, timers: { rows: null, note: "n" },
};
const adjRow = (o: Record<string, unknown>) => ({
  device: "r1", peer: "10.0.0.2", ifname: "Gi1", current_state: "full", state_source: "live_series", up: true,
  flaps: 0, changes: 0, up_events: 0, down_events: 0, hold_seconds: null, timeline: [], ...o,
});

beforeEach(() => {
  window.location.hash = "#/analytics/protocols";
  devices.mockResolvedValue([{ id: "r1", name: "core-1", address: "10.1.1.1", source: "snmp", last_seen: "", labels: { site: "DC East" } }]);
  correlations.mockResolvedValue({ data: [{
    correlation_id: "corr-1", version: 1, state: "open", window_start: "", verdict_tier: "suspected", signal_count: 3,
    affected: JSON.stringify({ interfaces: ["10.1.1.1:if3"] }), top_hypothesis: "sig.ent.access.ospf-adjacency-flap",
  }] });
  igpAdjacencies.mockResolvedValue({
    protocol: "ospf", device: "", window_seconds: 86400, since: "s", now: "n", source: "both", limit: 2000, truncated: false,
    coverage: cov, notes: [], event_count: 1, ...depth,
    adjacencies: [adjRow({ up: false, current_state: "down", flaps: 2, last_change: "2026-11-22T01:00:00Z" }), adjRow({ peer: "10.0.0.3" })],
  });
  igpSummary.mockResolvedValue({ protocol: "ospf", window_seconds: 86400, since: "s", now: "n", coverage: cov, devices: [], notes: [], truncated: false });
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("Protocol Monitoring", () => {
  it("opens on BGP: the outage view embedded, with no second page title", async () => {
    render(<ProtocolsPage />);
    expect(screen.getByRole("heading", { name: "Protocol Monitoring" })).toBeTruthy();
    expect(screen.getByTestId("bgp-ops").dataset.embedded).toBe("yes");
    expect(screen.getByRole("tab", { name: "BGP" }).getAttribute("aria-selected")).toBe("true");
  });

  it("deep-links each tab and writes the tab to the address bar", async () => {
    window.location.hash = "#/analytics/protocols/isis";
    render(<ProtocolsPage />);
    expect(screen.getByRole("tab", { name: "IS-IS" }).getAttribute("aria-selected")).toBe("true");
    fireEvent.click(screen.getByRole("tab", { name: "OSPF" }));
    expect(window.location.hash).toBe("#/analytics/protocols/ospf");
  });

  it("leads OSPF with what needs attention: device name, site, why, and the open problem", async () => {
    window.location.hash = "#/analytics/protocols/ospf";
    render(<ProtocolsPage />);
    const panel = await screen.findByLabelText("Needs attention");
    await waitFor(() => expect(within(panel).getByText("core-1")).toBeTruthy());
    expect(within(panel).getByText("DC East")).toBeTruthy();
    expect(within(panel).getByText("Down now")).toBeTruthy();
    const chip = await within(panel).findByRole("link");
    expect(chip.getAttribute("href")).toBe("#/investigate/rca?id=corr-1");
    // The steady adjacency is not listed first; it stays in "All adjacencies".
    expect(within(panel).queryByText(/10\.0\.0\.3/)).toBeNull();
  });

  it("keeps trend charts closed and unmounted until opened (a closed group does not poll)", async () => {
    window.location.hash = "#/analytics/protocols/ospf";
    render(<ProtocolsPage />);
    await screen.findByLabelText("Needs attention");
    expect(metricLine).not.toHaveBeenCalled();
    const details = screen.getByText("State trends").closest("details") as HTMLDetailsElement;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    await waitFor(() => expect(screen.getAllByTestId("metric-line").length).toBe(2));
  });

  it("drops no page when inventory and problems cannot be read", async () => {
    devices.mockRejectedValue(new Error("down"));
    correlations.mockRejectedValue(new Error("down"));
    window.location.hash = "#/analytics/protocols/ospf";
    render(<ProtocolsPage />);
    const panel = await screen.findByLabelText("Needs attention");
    await waitFor(() => expect(within(panel).getByText("r1")).toBeTruthy());
    expect(within(panel).queryByRole("link")).toBeNull();
  });
});
