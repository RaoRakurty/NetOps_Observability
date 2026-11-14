// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Flows.test.tsx — Explore → Flows at the screen (P1 2026-11-12, P2 tracker
// 400): "Right now" on the link-level APIs (one links call, the series, what
// changed), a link's drill-down, the RCA deep link with its exact window, the
// chip filters, the Capacity tab's 95th percentile, headroom and forecast, and
// that only the visible tab re-reads.

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
  flowsLinks: vi.fn(),
  flowsLinkSeries: vi.fn(),
  flowsLinkMovers: vi.fn(),
  flowsCapacity: vi.fn(),
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
const WINDOW = { from: "", to: "", seconds: 3600, explicit: false, prev_from: "", retention_days: 7, starts_before_retention: false, prev_before_retention: false };
const BASIS = { flows: 3, flows_rate_reported: 0, sampling: "not_reported", bucket_time: "received" };
const LINKS = {
  window: WINDOW, count: 2, basis: BASIS,
  links: [
    {
      exporter: "10.0.0.1", ifindex: 3, if_name: "Gi0/3", if_name_basis: "resolved", device_id: "edge-1-ab", device_name: "edge-1", site: "Dallas",
      in_bytes: 5000000, out_bytes: 2000000, prev_in_bytes: 2000000, prev_out_bytes: 1500000, in_packets: 1, out_packets: 1, flows: 2,
      in_basis: "measured", out_basis: "measured", sampling: "not_reported",
    },
    {
      exporter: "10.0.0.2", ifindex: 9, if_name: "", if_name_basis: "absent", device_id: "core-1-cd", device_name: "core-1",
      in_bytes: 1000, out_bytes: null, prev_in_bytes: null, prev_out_bytes: null, in_packets: 1, out_packets: 0, flows: 1,
      in_basis: "partly_exported", in_unnamed_pct: 15, out_basis: "not_exported", sampling: "not_reported",
    },
  ],
};
const SERIES = {
  window: WINDOW, served: { from: "", to: "" }, step_seconds: 60, exporter: "10.0.0.1", ifindex: 3,
  t: [1000, 1060], in_bytes: [600, 900], out_bytes: [100, 200], in_packets: [1, 1], out_packets: [1, 1],
  last_bucket_complete: true, in_basis: "measured", out_basis: "measured", basis: BASIS,
};
const MOVERS = {
  window: WINDOW, exporter: "10.0.0.1", ifindex: 3, by: "talker", dir: "both", basis: BASIS,
  totals: { bytes: 7000000, prev_bytes: 3500000 },
  movers: [{ key: "198.51.100.7", bytes: 400, prev_bytes: 100, delta: 300, change: 3, status: "up" }],
};
const CAPACITY = {
  window: WINDOW, count: 2, total: 2, forecast: { days: 28, min_days: 14, min_r2: 0.5, threshold_pct: 90 },
  interfaces: [
    {
      device_id: "edge-1-ab", device_name: "edge-1", site: "Dallas", ifindex: "3", if_name: "Gi0/3", exporter: "10.0.0.1",
      speed_bps: 100e6, speed_basis: "reported", p95_in_bps: 25e6, p95_out_bps: 40e6, p95_bps: 40e6, peak_bps: 95e6,
      p95_in_pct: 25, p95_out_pct: 40, p95_pct: 40, peak_pct: 95, headroom_bps: 60e6, headroom_pct: 60,
      forecast: { status: "rising", days_to_90: 27, slope_pct_per_day: 1, fitted_pct: 63, r2: 1, history_days: 14, min_days: 14 },
    },
    {
      device_id: "core-1-cd", device_name: "core-1", ifindex: "", if_name: "ge0/1", speed_bps: null, speed_basis: "unknown",
      p95_in_bps: 5e6, p95_out_bps: null, p95_bps: 5e6, peak_bps: 9e6, p95_in_pct: null, p95_out_pct: null, p95_pct: null, peak_pct: null,
      headroom_bps: null, headroom_pct: null,
      forecast: { status: "speed_unknown", days_to_90: null, slope_pct_per_day: null, fitted_pct: null, r2: null, history_days: 0, min_days: 14 },
    },
  ],
};
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
  m.flowsLinks.mockResolvedValue(LINKS);
  m.flowsLinkSeries.mockResolvedValue(SERIES);
  m.flowsLinkMovers.mockResolvedValue(MOVERS);
  m.flowsCapacity.mockResolvedValue(CAPACITY);
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
    // Change against the previous window, from the same scan: 7 MB against 3.5 MB.
    expect(within(table).getByText("+100%")).toBeInTheDocument();
    // A link whose device has no counters or speed reads a dash, never 0 %; a
    // direction the router does not export says so instead of reading 0.
    expect(within(table).getByText("core-1 · interface 9")).toBeInTheDocument();
    expect(within(table).getByText("Not exported")).toBeInTheDocument();
    expect(screen.getByTestId("links-reads-low")).toBeInTheDocument();
    expect(screen.getByTestId("links-sampling")).toHaveTextContent(/does not report its sampling rate/);
    // ONE links call over the window — no interface top-Ns, no double-window query.
    expect(m.flowsLinks).toHaveBeenCalledWith({ since: 3600 }, 50, "", {});
    expect(m.flowsTopN.mock.calls.filter(([by]) => by === "in_if" || by === "out_if")).toEqual([]);
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
    await waitFor(() => expect(m.flowsLinkSeries).toHaveBeenCalledWith({ exporter: "10.0.0.1", ifIndex: "3", tenant: undefined }, { since: 3600 }, "", ""));
    expect(m.flowsTimeseries).not.toHaveBeenCalled();
    // What changed on the link, against the window before; Ports asks again.
    const changed = await within(detail).findByTestId("what-changed");
    expect(await within(changed).findByText("198.51.100.7")).toBeInTheDocument();
    expect(within(changed).getByText("+300%")).toBeInTheDocument();
    expect(m.flowsLinkMovers).toHaveBeenCalledWith({ exporter: "10.0.0.1", ifIndex: "3", tenant: undefined }, { since: 3600 }, "talker", "both", 10, "");
    fireEvent.click(within(changed).getByRole("button", { name: "Ports" }));
    await waitFor(() => expect(m.flowsLinkMovers.mock.calls.some((c) => c[2] === "port")).toBe(true));
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
    // The link APIs get an EXACT window around the problem (its hour plus 15 minutes either side), not the shell's 15 min.
    await waitFor(() => expect(m.flowsLinkSeries).toHaveBeenCalled());
    const win = m.flowsLinkSeries.mock.calls[0][1] as { from: number; to: number };
    expect(win.from).toBeLessThanOrEqual(Date.parse(from) - 15 * 60_000);
    expect(win.to).toBeGreaterThanOrEqual(Date.parse(to) + 15 * 60_000 - 1000);
    expect(m.flowsLinks.mock.calls[0][0]).toEqual(win);
  });
});

describe("Flows — refresh", () => {
  it("only the visible tab re-reads", async () => {
    render(<Flows rangeMinutes={60} />);
    await screen.findByLabelText("Busiest links");
    fireEvent.click(screen.getByRole("button", { name: "Capacity" }));
    await screen.findByLabelText("Link capacity");
    for (const f of Object.values(m)) f.mockClear();
    // A tick (here: the tab coming back into view) re-reads Capacity only.
    act(() => { setVisibility("hidden"); });
    act(() => { setVisibility("visible"); });
    await waitFor(() => expect(m.flowsCapacity).toHaveBeenCalled());
    expect(m.flowsLinks).not.toHaveBeenCalled();
    expect(m.flowsLinkSeries).not.toHaveBeenCalled();
  });
});

describe("Flows — Capacity", () => {
  it("lists each link's 95th percentile, peak, headroom and when it reaches 90 %, grouped by site", async () => {
    window.location.hash = "#/explore/flows/capacity";
    render(<Flows rangeMinutes={60} />);
    const table = await screen.findByLabelText("Link capacity");
    await waitFor(() => expect(within(table).getByText("Dallas")).toBeInTheDocument());
    expect(within(table).getByText("edge-1 · Gi0/3")).toBeInTheDocument();
    expect(within(table).getByText("40%")).toBeInTheDocument(); // the 95th percentile
    expect(within(table).getByText("95%")).toBeInTheDocument(); // the peak
    expect(within(table).getByText("60 Mbps free")).toBeInTheDocument();
    expect(within(table).getByText("In about 27 days")).toBeInTheDocument();
    expect(m.flowsCapacity).toHaveBeenCalledWith({ since: 3600 }, 100);
    // Nothing is "coming next" any more, and a link with no speed is set apart.
    expect(screen.queryByTestId("capacity-next")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Speed not reported (1)" }));
    expect(await screen.findByLabelText("Speed not reported")).toHaveTextContent(/Speed not reported/);
    expect(screen.getByTestId("capacity-method")).toHaveTextContent(/14 days/);
    // A row opens that link in Right now.
    fireEvent.click(within(table).getByText("edge-1 · Gi0/3"));
    await waitFor(() => expect(window.location.hash).toBe("#/explore/flows?device=10.0.0.1&if=3"));
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
    expect(within(drawer).getByTestId("about-method")).toHaveTextContent(/95th percentile/);
    expect(within(drawer).getByRole("link", { name: /Device Monitoring/ })).toHaveAttribute("href", "#/analytics/device-monitoring");
    expect(within(drawer).getByRole("link", { name: /Security/ })).toHaveAttribute("href", "#/security/threat/behavior");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(drawer).toHaveAttribute("aria-hidden", "true"));
  });
});
