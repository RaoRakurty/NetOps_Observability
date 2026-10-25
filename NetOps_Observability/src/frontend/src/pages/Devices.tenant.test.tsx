// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Devices under the All-tenants view (tracker 365): every row names its
// tenant (no tenant → Provider); in a narrowed scope, or for a single-tenant
// user, every row is that scope's and the column is not shown.
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import type { Device } from "../services/api";

const scope = vi.hoisted(() => ({ active: "" }));
const mockApi = vi.hoisted(() => ({
  devices: vi.fn(),
  alerts: vi.fn(),
  deviceLocations: vi.fn(),
  sites: vi.fn(),
  features: vi.fn(),
  getLicence: vi.fn(),
  upsertDevice: vi.fn(),
  deleteDevice: vi.fn(),
  setDeviceSite: vi.fn(),
  clearDeviceSite: vi.fn(),
  myScopes: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi, getActiveScope: () => scope.active }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import Devices from "./Devices";

function device(id: string, tenant_id?: string): Device {
  return {
    id, name: id, address: "10.0.0." + id.length, source: "snmp", last_seen: new Date().toISOString(),
    monitored: true, monitor_state: "monitored", monitor_reason: "monitored", monitor_methods: ["snmp"], tenant_id,
  };
}

function setup(allTenants: boolean, active = "") {
  scope.active = active;
  mockApi.devices.mockResolvedValue([device("plat-edge"), device("retail-edge", "t_retail")]);
  mockApi.alerts.mockResolvedValue([]);
  mockApi.deviceLocations.mockResolvedValue({ devices: [] });
  mockApi.sites.mockResolvedValue({ sites: [], active: "internal" });
  mockApi.features.mockResolvedValue({});
  mockApi.getLicence.mockRejectedValue(new Error("403"));
  mockApi.myScopes.mockResolvedValue({
    scopes: [
      { tenant_id: "global", tenant_name: "Provider", org_id: "global", org_name: "Global", region: "" },
      { tenant_id: "t_retail", tenant_name: "RETAIL", org_id: "global", org_name: "Global", region: "" },
    ],
    all_tenants: allTenants,
  });
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("the Tenant column", () => {
  it("labels every row under All tenants", async () => {
    setup(true);
    render(<Devices />);
    await waitFor(() => expect(screen.getByText("Tenant")).toBeTruthy());
    expect(await screen.findByTitle("Owned by RETAIL")).toBeTruthy();
    expect(screen.getByTitle("Owned by Provider")).toBeTruthy();
  });

  it("is hidden in a narrowed scope", async () => {
    setup(true, "t_retail");
    render(<Devices />);
    await screen.findAllByText("retail-edge");
    expect(screen.queryByTitle(/^Owned by /)).toBeNull();
  });

  it("is hidden for a single-tenant user", async () => {
    setup(false);
    render(<Devices />);
    await screen.findAllByText("retail-edge");
    expect(screen.queryByTitle(/^Owned by /)).toBeNull();
  });
});
