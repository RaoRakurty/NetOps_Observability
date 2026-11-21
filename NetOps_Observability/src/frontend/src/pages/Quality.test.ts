// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Quality.test.ts — the Link Quality tunnel scores cover MEASURED tunnels only
// (Paths P4, 2026-11-21). An SD-WAN tunnel with no controller reading carries
// measured:false and zeros; scoring it read unmeasured tunnels as perfect paths.

import { describe, it, expect } from "vitest";
import type { Tunnel } from "../services/api";
import { tunnelQualityStats } from "./Quality";

function tun(over: Partial<Tunnel> = {}): Tunnel {
  return {
    id: "t", type: "sdwan", local_device: "a", local_addr: "", remote_device: "b", remote_addr: "",
    status: "up", latency_ms: 0, jitter_ms: 0, loss_pct: 0, qoe: 0, uptime_s: 0, ts: "", ...over,
  } as Tunnel;
}

describe("tunnelQualityStats", () => {
  it("scores measured rows only; total and up count every row", () => {
    const s = tunnelQualityStats([
      tun({ id: "m", latency_ms: 300, jitter_ms: 60, loss_pct: 3, qoe: 4, measured: true }),
      tun({ id: "u1", measured: false }),
      tun({ id: "u2", measured: false, status: "down" }),
    ]);
    expect(s.total).toBe(3);
    expect(s.up).toBe(2);
    expect(s.measured).toBe(1);
    // Only the measured (bad) path is scored: the zeros do not lift the average.
    expect(s.avgHealth).toBeLessThan(20);
    expect(s.avgQoe).toBe(4);
    expect(s.worstLoss).toBe(3);
  });

  it("scores nothing when nothing is measured", () => {
    const s = tunnelQualityStats([tun({ measured: false }), tun({ id: "x", measured: false })]);
    expect(s.measured).toBe(0);
    expect(s.avgHealth).toBe(0);
    expect(s.avgQoe).toBe(0);
  });

  it("treats a row without the flag (IPsec/GRE from ClickHouse) as measured", () => {
    expect(tunnelQualityStats([tun({ type: "ipsec", latency_ms: 20 })]).measured).toBe(1);
  });
});
