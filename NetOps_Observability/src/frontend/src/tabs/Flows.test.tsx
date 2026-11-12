// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Flows.test.tsx — Explore → Flows at the screen (P1, 2026-11-12): the
// default "Right now" view built from the existing APIs, a link's drill-down,
// the RCA deep link, the chip filters, the Capacity tab's honesty about what
// it does not compute yet, and that only the visible tab re-reads.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, within, fireEvent, act } from "@testing-library/react";

vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));

const m = {
  devices: vi.fn(),
  deviceLocations: vi.fn(),
  flowsTopN: vi.fn(),
  flowsTimeseries: vi.fn(),
  topTalkers: vi.fn(),
  correlations: vi.fn(),
  metricsQuery: vi.fn(),
  metricsQueryRange: vi.fn(),
  flowsCoverage: vi.fn(),
  flowsByType: vi.fn(),
  flowsGeo: vi.fn(),
  flowsApps: vi.fn(),
  flowsServices: vi.fn(),
  flowsByProto: vi.fn(),
  appIdResolveBatch: vi.fn(),
};
vi.mock("../services/api", () => ({
  api: new Proxy({}, { get: (_t, k: string) => (...a: unknown[]) => (m as Record<string, (...x: unknown[]) => unknown>)[k](...a) }),
}));

import Flows from "./Flows";
import { resetCoverageCache } from "./flowEmpty";
import { _resetAppNamesForTest } from "../services/appNames";

const DEVICES = [
  { id: "edge-1-ab", name: "edge-1", address: "10.0.0.1", source: "snmp", last_seen: "" },
  { id: "core-1-cd", name: "core-1", address: "10.0.0.2", source: "snmp", last_seen: "" },
];
const IN_ROWS = [
  { k: "3", exporter: "10.0.0.1", in_if_name: "Gi0/3", in_if_name_basis: "resolved", bytes_total: "5000000", packets_total: 1, flows: 1 },
  { k: "9", exporter: "10.0.0.2", in_if_name: "", in_if_name_basis: "absent", bytes_total: "1000", packets_total: 1, flows: 1 },
];
const OUT_ROWS = [{ k: "3", exporter: "10.0.0.1", out_if_name: "Gi0/3", out_if_name_basis: "resolved", bytes_total: "2000000", packets_total: 1, flows: 1 }];
const series = (device: string, index: string, vals: number[]) => ({ metric: { device, index, ifName: "Gi0/3" }, values: vals.map((v, i) => [1000 + i * 60, String(v)]) });

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  cleanup();
  window.location.hash = "";
});
beforeEach(() => {
  for (const f of Object.values(m)) f.mockReset();
  resetCoverageCache();
  _resetAppNamesForTest();
  setVisibility("visible");
  window.location.hash = "#/explore/flows";
  m.devices.mockResolvedValue(DEVICES);
  m.deviceLocations.mockResolvedValue({ devices: [{ id: "edge-1-ab", name: "edge-1", site: "Dallas", source: "manual" }] });
  m.flowsTopN.mockImplementation((by: string) => {
    if (by === "in_if") return Promise.resolve({ data: IN_ROWS });
    if (by === "out_if") return Promise.resolve({ data: OUT_ROWS });
    if (by === "device") return Promise.resolve({ data: [{ k: "10.0.0.1", bytes_total: 1, packets_total: 1, flows: 1 }] });
    return Promise.resolve({ data: [] });
  });
  m.metricsQueryRange.mockImplementation((query: string) =>
    Promise.resolve({ status: "success", data: { resultType: "matrix", result: query.includes("_in_") ? [series("edge-1-ab", "3", [10e6, 20e6])] : [series("edge-1-ab", "3", [5e6, 80e6])] } }),
  );
  m.metricsQuery.mockImplementation((query: string) => {
    if (query.startsWith("sum(")) return Promise.resolve({ status: "success", data: { result: [{ metric: {}, value: [0, "123000000"] }] } });
    if (query.includes("_over_time")) {
      const v = query.startsWith("max") ? (query.includes("_in_") ? "95" : "40") : "20";
      return Promise.resolve({ status: "success", data: { result: [{ metric: { device: "edge-1-ab", index: "3", ifName: "Gi0/3" }, value: [0, v] }] } });
    }
    return Promise.resolve({ status: "success", data: { result: [{ metric: { device: "edge-1-ab", index: "3" }, value: [0, "100000000"] }] } });
  });
  m.flowsTimeseries.mockResolvedValue({ data: [{ bucket: "2026-11-12 03:00:00", bytes_total: 600 }] });
  m.topTalkers.mockResolvedValue({ data: [{ src: "10.1.1.1", dst: "10.2.2.2", bytes_total: 900, packets_total: 9, flows: 3 }] });
  m.correlations.mockResolvedValue({
    data: [{
      correlation_id: "c-1", state: "open", window_start: new Date(Date.now() - 600_000).toISOString(), window_end: new Date().toISOString(),
      top_hypothesis: "undetermined", affected: JSON.stringify({ devices: ["edge-1"] }),
    }],
  });
  m.flowsCoverage.mockResolvedValue({ data: [{ flows: 10, exporters: 1, flows_sampling_reported: 0 }] });
  m.flowsByType.mockResolvedValue({ data: [{ flow_type: "netflow", flows: 10, exporters: 1 }] });
  m.flowsGeo.mockResolvedValue({ data: [], geo_enabled: false });
  m.flowsApps.mockResolvedValue({ apps: [], count: 0 });
  m.flowsServices.mockResolvedValue({ services: [], count: 0 });
  m.flowsByProto.mockResolvedValue({ data: [] });
  m.appIdResolveBatch.mockResolvedValue({});
});

describe("Flows — Right now", () => {
  it("leads with busiest links by name, with utilisation from the interface counters", async () => {
    render(<Flows rangeMinutes={60} />);
    expect(screen.getByRole("heading", { name: "Flows" })).toBeInTheDocument();
    const table = await screen.findByLabelText("Busiest links");
    await waitFor(() => expect(within(table).getByText("edge-1 · Gi0/3")).toBeInTheDocument());
    // In / Out are the flow volumes; utilisation is the busier direction / speed (80 Mbps of 100).
    expect(within(table).getByText("4.8 MB")).toBeInTheDocument();
    expect(within(table).getByText("1.9 MB")).toBeInTheDocument();
    await waitFor(() => expect(within(table).getByText("80%")).toBeInTheDocument());
    // A link whose device has no counters or speed reads a dash, never 0 %.
    expect(within(table).getByText("core-1 · interface 9")).toBeInTheDocument();
    // Built from the existing interface top-Ns, now and over twice the window.
    expect(m.flowsTopN).toHaveBeenCalledWith("in_if", 3600, 50, "", {});
    expect(m.flowsTopN).toHaveBeenCalledWith("out_if", 7200, 100, "", {});
    // The utilisation query reads only the devices in the table, by exact id.
    expect(m.metricsQueryRange.mock.calls.some(([q]) => String(q).includes('device=~"core-1-cd|edge-1-ab"'))).toBe(true);
    // The sampling sentence travels with the table.
    expect(await screen.findByTestId("flow-sampling-note")).toHaveTextContent(/shown as received/);
  });

  it("selecting a link shows its in/out timeline, talkers and the problems that name its device", async () => {
    render(<Flows rangeMinutes={60} />);
    const table = await screen.findByLabelText("Busiest links");
    fireEvent.click(await within(table).findByText("edge-1 · Gi0/3"));
    const detail = await screen.findByTestId("link-detail");
    expect(within(detail).getByRole("heading", { name: "edge-1 · Gi0/3" })).toBeInTheDocument();
    await waitFor(() => expect(m.flowsTimeseries).toHaveBeenCalledWith(3600, 60, "", { device: "10.0.0.1", in_if: "3" }));
    expect(m.flowsTimeseries).toHaveBeenCalledWith(3600, 60, "", { device: "10.0.0.1", out_if: "3" });
    await waitFor(() => expect(m.topTalkers).toHaveBeenCalledWith(3600, 10, "", { device: "10.0.0.1", if: "3" }, ""));
    expect(await within(detail).findByText("10.1.1.1")).toBeInTheDocument();
    const problem = await within(detail).findByRole("link", { name: /undetermined|possible|cause/i });
    expect(problem).toHaveAttribute("href", "#/investigate/rca?id=c-1");
    // The selection is in the route, so it can be shared.
    expect(window.location.hash).toBe("#/explore/flows?device=10.0.0.1&if=3");
  });

  it("opens from an RCA deep link with the link selected and the problem window marked", async () => {
    const from = new Date(Date.now() - 2 * 3600_000).toISOString();
    const to = new Date(Date.now() - 3600_000).toISOString();
    window.location.hash = `#/explore/flows?device=10.0.0.1&if=3&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
    render(<Flows rangeMinutes={15} />);
    expect(await screen.findByTestId("problem-banner")).toBeInTheDocument();
    const detail = await screen.findByTestId("link-detail");
    expect(within(detail).getByTestId("problem-window")).toBeInTheDocument();
    // The window reaches back past the problem start (2 h + the 5 min lead-in), not the shell's 15 min.
    await waitFor(() => expect(m.flowsTimeseries.mock.calls.some(([since]) => Number(since) >= 7500)).toBe(true));
  });
});

describe("Flows — refresh", () => {
  it("only the visible tab re-reads", async () => {
    render(<Flows rangeMinutes={60} />);
    await screen.findByLabelText("Busiest links");
    fireEvent.click(screen.getByRole("button", { name: "Capacity" }));
    await screen.findByLabelText("Link utilisation");
    for (const f of Object.values(m)) f.mockClear();
    // A tick (here: the tab coming back into view) re-reads Capacity only.
    act(() => { setVisibility("hidden"); });
    act(() => { setVisibility("visible"); });
    await waitFor(() => expect(m.metricsQuery.mock.calls.some(([q]) => String(q).startsWith("max_over_time"))).toBe(true));
    expect(m.flowsTopN.mock.calls.filter(([by]) => by === "in_if" || by === "out_if")).toEqual([]);
    expect(m.flowsTimeseries).not.toHaveBeenCalled();
  });
});

describe("Flows — Capacity", () => {
  it("lists per-link average and peak, grouped by site, and labels what is not computed yet", async () => {
    window.location.hash = "#/explore/flows/capacity";
    render(<Flows rangeMinutes={60} />);
    const table = await screen.findByLabelText("Link utilisation");
    await waitFor(() => expect(within(table).getByText("Dallas")).toBeInTheDocument());
    expect(within(table).getByText("edge-1 · Gi0/3")).toBeInTheDocument();
    expect(within(table).getAllByText("95%")).toHaveLength(2); // peak, and the inbound peak it came from
    expect(screen.getByTestId("capacity-next")).toHaveTextContent("Coming next: 95th percentile · headroom · days until 90%.");
  });
});

describe("Flows — Who is talking", () => {
  it("filters by name and by typed address, sending real flow filters", async () => {
    window.location.hash = "#/explore/flows/talking";
    render(<Flows rangeMinutes={60} />);
    await screen.findByRole("search", { name: "Filter flows" });
    // Device by NAME.
    const device = await screen.findByRole("combobox", { name: "Device" });
    await waitFor(() => expect(within(device).getByRole("option", { name: "edge-1 (10.0.0.1)" })).toBeInTheDocument());
    fireEvent.change(device, { target: { value: "10.0.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText("Device: edge-1 (10.0.0.1)")).toBeInTheDocument();
    await waitFor(() => expect(m.topTalkers).toHaveBeenCalledWith(3600, 25, "", { device: "10.0.0.1" }, ""));
    // Address or network, validated before it is sent.
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by" }), { target: { value: "addr" } });
    const addr = screen.getByRole("textbox", { name: "Address or network" });
    fireEvent.change(addr, { target: { value: "10.1.0.0/33" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/0 to 32/);
    fireEvent.change(addr, { target: { value: "10.1.0.0/16" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(m.topTalkers).toHaveBeenCalledWith(3600, 25, "", { device: "10.0.0.1", addr: "10.1.0.0/16" }, ""));
    // Removing the device chip removes its interface too, and the query follows.
    fireEvent.click(screen.getByRole("button", { name: "Remove Device: edge-1 (10.0.0.1)" }));
    await waitFor(() => expect(m.topTalkers).toHaveBeenLastCalledWith(3600, 25, "", { addr: "10.1.0.0/16" }, ""));
  });

  it("countries and networks stay hidden until their datasets are loaded", async () => {
    window.location.hash = "#/explore/flows/talking";
    render(<Flows rangeMinutes={60} />);
    await screen.findByRole("group", { name: "Flows view" });
    await waitFor(() => expect(m.flowsGeo).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Countries" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Networks" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Services and ports" })).toBeInTheDocument();
  });

  it("'Who is talking here' carries the link into the chips", async () => {
    render(<Flows rangeMinutes={60} />);
    fireEvent.click(await within(await screen.findByLabelText("Busiest links")).findByText("edge-1 · Gi0/3"));
    fireEvent.click(await screen.findByRole("button", { name: "Who is talking here" }));
    expect(window.location.hash).toBe("#/explore/flows/talking?device=10.0.0.1&if=3");
    await waitFor(() => expect(m.topTalkers).toHaveBeenCalledWith(3600, 25, "", { device: "10.0.0.1", if: "3" }, ""));
  });
});

describe("Flows — About this data", () => {
  it("opens a drawer with sources, sampling, the platform toggle and dataset status; device health and flags live elsewhere", async () => {
    render(<Flows rangeMinutes={60} />);
    fireEvent.click(screen.getByRole("button", { name: "About this data" }));
    const drawer = screen.getByRole("dialog", { name: "About this data" });
    expect(await within(drawer).findByText(/10 flows from 1 device/)).toBeInTheDocument();
    expect(within(drawer).getByTestId("about-sampling")).toHaveTextContent(/shown as received/);
    expect(within(drawer).getByTestId("platform-traffic")).toBeInTheDocument();
    expect(within(drawer).getByTestId("dataset-geo")).toHaveTextContent(/not loaded/);
    expect(within(drawer).getByRole("link", { name: /Device Monitoring/ })).toHaveAttribute("href", "#/analytics/device-monitoring");
    expect(within(drawer).getByRole("link", { name: /Security/ })).toHaveAttribute("href", "#/security/threat/behavior");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(drawer).toHaveAttribute("aria-hidden", "true"));
  });
});
