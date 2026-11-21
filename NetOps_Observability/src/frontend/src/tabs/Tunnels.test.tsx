// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Tunnels.test.tsx — the Tunnels page.
//  · The summary tiles average MEASURED tunnels only (Paths redesign P0,
//    2026-11-20): rows with measured:false carry zeros, and averaging them in
//    read a fleet of unmeasured tunnels as a healthy 0 ms / 0 %.
//  · One row per SD-WAN tunnel with both ends, the folded state, the
//    controller's quality as of its own time, the case chip, and the site
//    matrix that filters the table (Paths P4, 2026-11-21).

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent, within } from "@testing-library/react";
import type { Tunnel, TunnelEnd, TunnelsResponse } from "../services/api";

const mockApi = vi.hoisted(() => ({ tunnels: vi.fn() }));
vi.mock("../services/api", () => ({ api: mockApi }));

import Tunnels, { tunnelKpis } from "./Tunnels";

function tun(over: Partial<Tunnel> = {}): Tunnel {
  return {
    id: "t1", type: "ipsec", local_device: "edge-1", local_addr: "10.0.0.1",
    remote_device: "edge-2", remote_addr: "10.0.0.2", status: "up",
    latency_ms: 0, jitter_ms: 0, loss_pct: 0, qoe: 0, uptime_s: 0, ts: "",
    ...over,
  } as Tunnel;
}

function end(over: Partial<TunnelEnd> = {}): TunnelEnd {
  return { device_id: "d", device: "edge", system_ip: "10.255.255.1", color: "mpls", state: "up", sessions: 1, up: 1, site: null, ...over };
}

const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

function sdwan(over: Partial<Tunnel> = {}): Tunnel {
  return tun({
    id: "sdwan|a|b|x", type: "sdwan", tunnel_id: "10.255.255.40/mpls|10.255.255.100/mpls",
    state: "up", status: "up", ends_reported: 2,
    a: end({ device: "cedge-40", system_ip: "10.255.255.40", site: { label: "Branch 40", source: "manual" } }),
    b: end({ device: "vedge-100", system_ip: "10.255.255.100", site: { label: "DC East", source: "manual" } }),
    latency_ms: 12.3, jitter_ms: 2, loss_pct: 0.5, qoe: 9, measured: true,
    quality: { latency_ms: 12.3, jitter_ms: 2, loss_pct: 0.5, qoe: 9, as_of: minsAgo(40), ends: 2, source: "controller_statistics" },
    case: null,
    ...over,
  });
}

function body(data: Tunnel[], over: Partial<TunnelsResponse> = {}): TunnelsResponse {
  return { data, rows: data.length, total: data.length, truncated: false,
    quality: { status: "ok", window_s: 10800 }, cases: { status: "ok" }, ...over };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("tunnelKpis", () => {
  it("averages latency and loss over measured rows only", () => {
    const k = tunnelKpis([
      tun({ id: "a", latency_ms: 40, loss_pct: 2 }),
      tun({ id: "b", latency_ms: 80, loss_pct: 0, measured: true }),
      tun({ id: "c", measured: false, status: "down" }),
      tun({ id: "d", measured: false }),
    ]);
    expect(k).toEqual({ up: 3, down: 1, disagree: 0, measured: 2, avgLatency: 60, avgLoss: 1 });
  });

  it("reports no average (null, never 0) when no row is measured", () => {
    const k = tunnelKpis([tun({ measured: false }), tun({ id: "x", measured: false })]);
    expect(k.measured).toBe(0);
    expect(k.avgLatency).toBeNull();
    expect(k.avgLoss).toBeNull();
  });

  it("counts a folded tunnel by its state: disagree is neither up nor down", () => {
    const k = tunnelKpis([sdwan({ state: "disagree", status: "down" }), sdwan({ id: "u" })]);
    expect(k).toMatchObject({ up: 1, down: 0, disagree: 1 });
  });
});

describe("Tunnels page tiles", () => {
  it("shows a dash and 'quality not measured' for an all-unmeasured overlay", async () => {
    mockApi.tunnels.mockResolvedValue(body([tun({ measured: false }), tun({ id: "y", measured: false })]));
    render(<Tunnels />);
    await waitFor(() => expect(screen.getByText("of 2")).toBeTruthy());
    const lat = screen.getByTestId("tunnels-avg-latency");
    expect(lat.textContent).toContain("—");
    expect(lat.textContent).toContain("quality not measured");
    expect(lat.textContent).not.toMatch(/\b0 ms/);
  });

  it("names how many tunnels the averages cover", async () => {
    mockApi.tunnels.mockResolvedValue(body([tun({ latency_ms: 30 }), tun({ id: "z", measured: false })]));
    render(<Tunnels />);
    await waitFor(() => expect(screen.getByTestId("tunnels-avg-latency").textContent).toContain("across 1 measured tunnel"));
    expect(screen.getByTestId("tunnels-avg-latency").textContent).toContain("30");
  });

  it("asks the server for the site matrix", async () => {
    mockApi.tunnels.mockResolvedValue(body([]));
    render(<Tunnels />);
    await waitFor(() => expect(mockApi.tunnels).toHaveBeenCalled());
    expect(mockApi.tunnels).toHaveBeenCalledWith(500, undefined, { matrix: true });
  });
});

describe("Tunnels rows (one per SD-WAN tunnel)", () => {
  it("renders both ends with device, colour and site", async () => {
    mockApi.tunnels.mockResolvedValue(body([sdwan()]));
    render(<Tunnels />);
    await waitFor(() => expect(screen.getByText("cedge-40")).toBeTruthy());
    const table = screen.getByLabelText("Tunnels");
    expect(within(table).getByText("vedge-100")).toBeTruthy();
    expect(within(table).getByText("Branch 40")).toBeTruthy();
    expect(within(table).getByText("DC East")).toBeTruthy();
    expect(within(table).getAllByText("mpls").length).toBe(2);
  });

  it("badges a tunnel whose ends disagree", async () => {
    mockApi.tunnels.mockResolvedValue(body([sdwan({ state: "disagree", status: "down" })]));
    render(<Tunnels />);
    const badge = await screen.findByTestId("tunnel-state");
    expect(badge.textContent).toBe("ends disagree");
    expect(badge.className).toContain("warn");
    expect(screen.getByTestId("tunnels-down").textContent).toContain("1 tunnel with ends disagreeing");
  });

  it("says when only one end reports", async () => {
    mockApi.tunnels.mockResolvedValue(body([sdwan({ ends_reported: 1, b: end({ device: "", device_id: null, system_ip: "10.255.255.100" }) })]));
    render(<Tunnels />);
    await screen.findByText("one end reporting");
    expect(screen.getByText("10.255.255.100")).toBeTruthy();
  });

  it("shows quality as of its own time, and a dash when unmeasured", async () => {
    mockApi.tunnels.mockResolvedValue(body([
      sdwan(),
      sdwan({ id: "u", tunnel_id: "x", measured: false, quality: null, latency_ms: 0, loss_pct: 0 }),
    ]));
    render(<Tunnels />);
    await waitFor(() => expect(screen.getAllByTestId("tunnel-asof").length).toBe(2));
    const cells = screen.getAllByTestId("tunnel-asof").map((c) => c.textContent);
    expect(cells.some((t) => /^as of \d\d:\d\d \(40 min ago\)$/.test(t ?? ""))).toBe(true);
    expect(cells).toContain("—");
    // The summary says how old the averaged reading is.
    expect(screen.getByTestId("tunnels-avg-loss").textContent).toMatch(/as of \d\d:\d\d \(40 min ago\)/);
  });

  it("links an open case to the RCA workspace", async () => {
    mockApi.tunnels.mockResolvedValue(body([sdwan({ case: { id: "3f2a-uuid", tier: "suspected", entity_id: "x" } })]));
    render(<Tunnels />);
    const chip = await screen.findByTestId("tunnel-case");
    expect(chip.getAttribute("href")).toBe("#/investigate/rca?id=3f2a-uuid");
    expect(chip.textContent).toBe("suspected case");
  });

  it("says in one line when quality or cases could not be read — never zeros", async () => {
    mockApi.tunnels.mockResolvedValue(body(
      [sdwan({ measured: false, quality: null, latency_ms: 0, loss_pct: 0 })],
      { quality: { status: "unavailable", window_s: 10800 }, cases: { status: "unavailable" } },
    ));
    render(<Tunnels />);
    const notes = await screen.findByTestId("tunnels-notes");
    expect(notes.textContent).toContain("Path quality could not be read");
    expect(notes.textContent).toContain("Open cases could not be read");
    expect(screen.queryByTestId("tunnel-case")).toBeNull();
    expect(screen.getByTestId("tunnels-avg-loss").textContent).not.toMatch(/0\.00/);
  });

  it("renders device and site names as text, never as HTML", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    mockApi.tunnels.mockResolvedValue(body([sdwan({ a: end({ device: evil, site: { label: evil, source: "manual" } }) })]));
    const { container } = render(<Tunnels />);
    await waitFor(() => expect(screen.getAllByText(evil).length).toBeGreaterThan(0));
    expect(container.querySelector("img")).toBeNull();
  });

  it("names where SD-WAN tunnels come from when there are none", async () => {
    mockApi.tunnels.mockResolvedValue(body([]));
    render(<Tunnels />);
    const empty = await screen.findByTestId("tunnels-empty");
    expect(within(empty).getByRole("link", { name: "Infrastructure › NMS Integrations" }).getAttribute("href")).toBe("#/infrastructure/nms");
  });
});

describe("site matrix", () => {
  const rows = [
    sdwan({ id: "1" }),
    sdwan({ id: "2", state: "down", status: "down",
      a: end({ device: "cedge-50", site: { label: "Branch 50", source: "manual" } }),
      b: end({ device: "vedge-101", site: { label: "DC East", source: "manual" } }) }),
  ];
  const matrix = {
    sites: [
      { key: "s1", label: "Branch 40", source: "manual", devices: 1 },
      { key: "s2", label: "DC East", source: "manual", devices: 2 },
      { key: "s3", label: "Branch 50", source: "manual", devices: 1 },
    ],
    cells: [
      { a: "s1", b: "s2", state: "up", tunnels: 1, up: 1, down: 0, disagree: 0, transports: [], measured: 1, worst_loss_pct: 0.5, worst_latency_ms: 12, quality_as_of: null, cases: [] },
      { a: "s2", b: "s3", state: "down", tunnels: 1, up: 0, down: 1, disagree: 0, transports: [], measured: 0, worst_loss_pct: null, worst_latency_ms: null, quality_as_of: null, cases: [] },
    ],
    sites_total: 3, unplaced_tunnels: 2, truncated: false,
  };

  it("draws a cell per site pair, toned by its worst state", async () => {
    mockApi.tunnels.mockResolvedValue(body(rows, { matrix }));
    render(<Tunnels />);
    await screen.findByTestId("tunnels-matrix");
    const cells = screen.getAllByTestId("tunnels-matrix-cell");
    // Two pairs, each drawn on both sides of the diagonal.
    expect(cells.length).toBe(4);
    const down = cells.filter((c) => c.getAttribute("data-state") === "down");
    expect(down.length).toBe(2);
    expect(down[0].className).toContain("t-bad");
    expect(screen.getByTestId("tunnels-matrix-foot").textContent).toContain("2 tunnels with an end at no site");
  });

  it("filters the table to a cell, and back", async () => {
    mockApi.tunnels.mockResolvedValue(body(rows, { matrix }));
    render(<Tunnels />);
    await screen.findByTestId("tunnels-matrix");
    await waitFor(() => expect(screen.getByText("2 of 2 tunnels")).toBeTruthy());
    const downCell = screen.getAllByTestId("tunnels-matrix-cell").find((c) => c.getAttribute("data-state") === "down")!;
    fireEvent.click(downCell);
    expect(screen.getByText("1 of 2 tunnels")).toBeTruthy();
    expect(screen.getByTestId("tunnels-cell-filter").textContent).toMatch(/DC East ↔ Branch 50|Branch 50 ↔ DC East/);
    fireEvent.click(screen.getByTestId("tunnels-cell-filter"));
    expect(screen.getByText("2 of 2 tunnels")).toBeTruthy();
  });

  it("says plainly when no tunnel is placed at a site", async () => {
    mockApi.tunnels.mockResolvedValue(body(rows, { matrix: { ...matrix, sites: [], cells: [] } }));
    render(<Tunnels />);
    expect((await screen.findByTestId("tunnels-matrix-empty")).textContent).toBe("No tunnel ends are placed at sites yet.");
  });
});
