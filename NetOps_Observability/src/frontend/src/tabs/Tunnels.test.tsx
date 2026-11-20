// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Tunnels.test.tsx — the summary tiles average MEASURED tunnels only (Paths
// redesign P0, 2026-11-20). SD-WAN rows from the overlay snapshot carry
// measured:false and zeros; averaging them in read a fleet of unmeasured
// tunnels as a healthy 0 ms / 0 %.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import type { Tunnel } from "../services/api";

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

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("tunnelKpis", () => {
  it("averages latency and loss over measured rows only", () => {
    const k = tunnelKpis([
      tun({ id: "a", latency_ms: 40, loss_pct: 2 }),
      tun({ id: "b", latency_ms: 80, loss_pct: 0, measured: true }),
      tun({ id: "c", measured: false, status: "down" }),
      tun({ id: "d", measured: false }),
    ]);
    expect(k).toEqual({ up: 3, down: 1, measured: 2, avgLatency: 60, avgLoss: 1 });
  });

  it("reports no average (null, never 0) when no row is measured", () => {
    const k = tunnelKpis([tun({ measured: false }), tun({ id: "x", measured: false })]);
    expect(k.measured).toBe(0);
    expect(k.avgLatency).toBeNull();
    expect(k.avgLoss).toBeNull();
  });
});

describe("Tunnels page tiles", () => {
  it("shows a dash and 'quality not measured' for an all-unmeasured overlay", async () => {
    mockApi.tunnels.mockResolvedValue({ data: [tun({ measured: false }), tun({ id: "y", measured: false })] });
    render(<Tunnels />);
    await waitFor(() => expect(screen.getByText("of 2")).toBeTruthy());
    const lat = screen.getByTestId("tunnels-avg-latency");
    expect(lat.textContent).toContain("—");
    expect(lat.textContent).toContain("quality not measured");
    expect(lat.textContent).not.toMatch(/\b0 ms/);
  });

  it("names how many tunnels the averages cover", async () => {
    mockApi.tunnels.mockResolvedValue({ data: [tun({ latency_ms: 30 }), tun({ id: "z", measured: false })] });
    render(<Tunnels />);
    await waitFor(() => expect(screen.getByTestId("tunnels-avg-latency").textContent).toContain("across 1 measured tunnel"));
    expect(screen.getByTestId("tunnels-avg-latency").textContent).toContain("30");
  });
});
