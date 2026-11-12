// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi } from "vitest";

vi.mock("../components/EChart", () => ({ default: () => null }));

import { ifRateBps, ifUtilPct, ifSpeedBps, deviceAnySelector, overWindow } from "./ifUtilisation";

describe("ifUtilisation — one spelling of the interface queries", () => {
  it("reproduces exactly the queries Device Monitoring and Interface Performance drew inline", () => {
    // These literals are what the two pages carried before the extraction; the
    // helper must not change a byte of what VictoriaMetrics is asked.
    expect(ifRateBps("", "in")).toBe("rate(device_if_in_octets[5m]) * 8");
    expect(ifRateBps('{device="d1"}', "out")).toBe('rate(device_if_out_octets{device="d1"}[5m]) * 8');
    expect(`topk(10, ${ifUtilPct("", "in")})`).toBe("topk(10, rate(device_if_in_octets[5m]) * 8 * 100 / ((device_if_speed > 0) * 1000000))");
    const sel = '{device="d1",ifName="Gi0/1"}';
    expect(ifUtilPct(sel, "out")).toBe(`rate(device_if_out_octets${sel}[5m]) * 8 * 100 / ((device_if_speed${sel} > 0) * 1000000)`);
  });

  it("drops an interface with no reported speed rather than dividing by zero", () => {
    expect(ifSpeedBps("")).toBe("(device_if_speed > 0) * 1000000");
    expect(ifUtilPct("", "in")).toContain("(device_if_speed > 0)");
  });

  it("matches device ids exactly: sanitised, dots escaped, deduplicated", () => {
    expect(deviceAnySelector([])).toBe("");
    expect(deviceAnySelector(["", "  "])).toBe("");
    expect(deviceAnySelector(["edge-1-ab12", "edge-1-ab12", "core.dc1-ff00"])).toBe('{device=~"edge-1-ab12|core\\\\.dc1-ff00"}');
    // An injection attempt loses every character the sanitiser does not allow.
    expect(deviceAnySelector(['x"} or vector(1) #'])).toBe('{device=~"x or vector1"}');
  });

  it("bounds the window aggregate: never under 5 minutes, about 288 points", () => {
    expect(overWindow("max", "E", 60)).toBe("max_over_time((E)[300s:300s])");
    expect(overWindow("avg", "E", 3600)).toBe("avg_over_time((E)[3600s:300s])");
    expect(overWindow("max", "E", 7 * 86400)).toBe("max_over_time((E)[604800s:2100s])");
  });
});
