// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The Overview "Capacity outlook" panel reads /api/metrics/forecast, which since
// tracker 407 is the Capacity tab's fit. A rising line too noisy to date is
// "unsteady": the panel must not call it stable, and must not date it.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

const metricsForecast = vi.fn();
vi.mock("../services/api", () => ({
  api: { metricsForecast: (...a: unknown[]) => metricsForecast(...a) },
  getActiveScope: () => "",
  sessionTenantKey: () => "",
}));
vi.mock("../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));

import { CapacityOutlook } from "./FrontPage";

const row = (status: string, days = -1) => ({
  device: "edge-1", interface: "Gi0/1", current_util_pct: 61, slope_per_day_pct: 1,
  days_to_90: days, status, history_days: 14,
});

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("Capacity outlook panel", () => {
  it("says an unsteady rise has no steady trend — not 'All interfaces stable'", async () => {
    metricsForecast.mockResolvedValue({ class: "wan_util", interfaces: [row("unsteady"), row("stable")], count: 2, min_days: 14 });
    render(<CapacityOutlook />);
    expect(await screen.findByText("No steady trend")).toBeTruthy();
    expect(screen.getByText("1 interface rising too unevenly to date a 90% crossing.")).toBeTruthy();
    expect(screen.queryByText("All interfaces stable")).toBeNull();
  });
  it("still says 'All interfaces stable' when every row is stable", async () => {
    metricsForecast.mockResolvedValue({ class: "wan_util", interfaces: [row("stable")], count: 1, min_days: 14 });
    render(<CapacityOutlook />);
    expect(await screen.findByText("All interfaces stable")).toBeTruthy();
  });
  it("building baseline takes precedence over unsteady", async () => {
    metricsForecast.mockResolvedValue({ class: "wan_util", interfaces: [row("building_baseline"), row("unsteady")], count: 2, min_days: 14 });
    render(<CapacityOutlook />);
    expect(await screen.findByText("Building baseline")).toBeTruthy();
  });
  it("lists a trending interface with its date", async () => {
    metricsForecast.mockResolvedValue({ class: "wan_util", interfaces: [row("trending", 21.4), row("unsteady")], count: 2, min_days: 14 });
    render(<CapacityOutlook />);
    expect(await screen.findByText("~21d to 90%")).toBeTruthy();
  });
});
