// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import SloCard from "./SloCard";
import type { CloudSloResponse } from "../../services/api";

const measured: CloudSloResponse = {
  tenant_id: "t1", count: 1, max_slos: 20,
  slos: [{
    app_name: "shop", target_pct: 99.9, window_days: 30,
    status: {
      measurable: true, actual_pct: 99.95, budget_pct: 0.1,
      budget_remaining_pct: 50, burn_ratio: 0.5,
      resources_total: 2, resources_reporting: 2,
      basis: "measured from provider status checks on 2 of 2 resource(s) over 30d; ingestion gaps are not counted",
    },
  }],
};

const cloudSlos = vi.fn(() => Promise.resolve(measured));
const setCloudSlos = vi.fn(() => Promise.resolve(measured));
const resetCloudSlos = vi.fn(() => Promise.resolve({ ...measured, slos: [], count: 0 }));
vi.mock("../../services/api", () => ({
  api: {
    cloudSlos: () => cloudSlos(),
    setCloudSlos: (d: unknown) => setCloudSlos(d as never),
    resetCloudSlos: () => resetCloudSlos(),
  },
}));

afterEach(() => { cleanup(); cloudSlos.mockClear(); setCloudSlos.mockClear(); resetCloudSlos.mockClear(); });

describe("SloCard", () => {
  it("shows target vs actual vs budget remaining when measured", async () => {
    render(<SloCard appName="shop" />);
    expect(await screen.findByText("99.95%")).toBeInTheDocument();  // actual
    expect(screen.getByText("99.9%")).toBeInTheDocument();          // target
    expect(screen.getByText("50%")).toBeInTheDocument();            // budget remaining
    expect(screen.getByText(/2 of 2 resources reporting/)).toBeInTheDocument();
  });

  it("says 'not measurable' with the backend's basis when data is absent", async () => {
    cloudSlos.mockResolvedValueOnce({
      ...measured,
      slos: [{
        app_name: "shop", target_pct: 99.9, window_days: 30,
        status: {
          measurable: false, budget_pct: 0.1, resources_total: 0, resources_reporting: 0,
          basis: "not measurable — no cloud resources are attributed to this app",
        },
      }],
    });
    render(<SloCard appName="shop" />);
    expect((await screen.findAllByText("not measurable")).length).toBeGreaterThan(0);
    expect(screen.getByText(/no cloud resources are attributed/)).toBeInTheDocument();
  });

  it("offers to set a target when no SLO exists and saves via the whole-list PUT", async () => {
    cloudSlos.mockResolvedValueOnce({ ...measured, slos: [], count: 0 });
    render(<SloCard appName="billing" />);
    fireEvent.click(await screen.findByText("Set a target"));
    fireEvent.change(screen.getByLabelText("SLO target percent"), { target: { value: "99.5" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(setCloudSlos).toHaveBeenCalledWith([
      { app_name: "billing", target_pct: 99.5, window_days: 30 },
    ]));
  });

  it("refuses an out-of-bounds target locally", async () => {
    cloudSlos.mockResolvedValueOnce({ ...measured, slos: [], count: 0 });
    render(<SloCard appName="billing" />);
    fireEvent.click(await screen.findByText("Set a target"));
    fireEvent.change(screen.getByLabelText("SLO target percent"), { target: { value: "100" } });
    fireEvent.click(screen.getByText("Save"));
    expect(await screen.findByText(/between 50 and 99.999/)).toBeInTheDocument();
    expect(setCloudSlos).not.toHaveBeenCalled();
  });

  it("surfaces a 403 as an honest permissions message", async () => {
    setCloudSlos.mockRejectedValueOnce(new Error("403 Forbidden: no"));
    render(<SloCard appName="shop" />);
    fireEvent.click(await screen.findByText("Edit"));
    fireEvent.click(screen.getByText("Save"));
    expect(await screen.findByText(/requires an administrator/)).toBeInTheDocument();
  });

  it("removes the last objective via reset", async () => {
    render(<SloCard appName="shop" />);
    fireEvent.click(await screen.findByText("Remove"));
    await waitFor(() => expect(resetCloudSlos).toHaveBeenCalled());
    expect(setCloudSlos).not.toHaveBeenCalled();
  });
});
