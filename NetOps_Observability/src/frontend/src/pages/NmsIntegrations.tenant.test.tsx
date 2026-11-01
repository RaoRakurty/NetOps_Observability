// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NmsIntegrations under the All-tenants view (tracker 365). On 2026-10-25 an
// operator deleted another tenant's vManage integration from an unlabelled
// cross-tenant list they took for the Provider's own. So:
//   1. under "All tenants" every row names its tenant (no tenant → Provider);
//   2. in a narrowed scope the column is not shown (every row is that scope's);
//   3. deleting or pausing ANOTHER tenant's integration names that tenant in
//      the confirm, and a refusal changes nothing; your own stays a plain ask.
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const scope = vi.hoisted(() => ({ active: "" }));
const mockApi = vi.hoisted(() => ({
  nmsConnectors: vi.fn(),
  nmsIntegrations: vi.fn(),
  nmsHealth: vi.fn(),
  nmsStates: vi.fn(),
  myScopes: vi.fn(),
  deleteNmsIntegration: vi.fn(),
  updateNmsIntegration: vi.fn(),
  pollNmsIntegration: vi.fn(),
  testNmsIntegration: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi, getActiveScope: () => scope.active }));
vi.mock("../components/AskIris", () => ({ default: () => <span /> }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));
vi.mock("../components/NmsControllerArt", () => ({ NmsDashArt: () => <span />, NmsMark: () => <span /> }));

import NmsIntegrations from "./NmsIntegrations";

const INTEGRATIONS = [
  { id: "nmsi-retail", tenantId: "t_retail", vendor: "vmanage", displayName: "SDWAN", enabled: true, baseUrl: "https://vmanage.retail", pollIntervalS: 300 },
  { id: "nmsi-prov", tenantId: "global", vendor: "vmanage", displayName: "Provider vManage", enabled: true, baseUrl: "https://vmanage.prov", pollIntervalS: 300 },
];
const SCOPES = [
  { tenant_id: "global", tenant_name: "Provider", org_id: "global", org_name: "Global", region: "" },
  { tenant_id: "t_retail", tenant_name: "RETAIL", org_id: "global", org_name: "Global", region: "us-east" },
];

function setup(allTenants: boolean, active = "") {
  scope.active = active;
  mockApi.nmsConnectors.mockResolvedValue({ connectors: [] });
  mockApi.nmsIntegrations.mockResolvedValue({ integrations: active === "global" ? [INTEGRATIONS[1]] : INTEGRATIONS });
  mockApi.nmsHealth.mockRejectedValue(new Error("no health"));
  mockApi.nmsStates.mockResolvedValue({ states: [] });
  mockApi.myScopes.mockResolvedValue({ scopes: SCOPES, all_tenants: allTenants });
  mockApi.deleteNmsIntegration.mockResolvedValue(undefined);
  mockApi.updateNmsIntegration.mockResolvedValue({});
}

let confirmSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  confirmSpy.mockRestore();
});

describe("the Tenant column", () => {
  it("names each row's tenant under All tenants", async () => {
    setup(true);
    render(<NmsIntegrations />);
    await waitFor(() => expect(screen.getAllByTestId("nms-tenant")).toHaveLength(2));
    expect(screen.getByRole("columnheader", { name: "Tenant" })).toBeTruthy();
    const row = screen.getByRole("button", { name: "SDWAN" }).closest("tr")!;
    expect(within(row).getByTestId("nms-tenant").textContent).toBe("RETAIL");
    const prov = screen.getByRole("button", { name: "Provider vManage" }).closest("tr")!;
    expect(within(prov).getByTestId("nms-tenant").textContent).toBe("Provider");
  });

  it("is hidden in the Provider scope, where every row is the Provider's", async () => {
    setup(true, "global");
    render(<NmsIntegrations />);
    await screen.findByRole("button", { name: "Provider vManage" });
    expect(screen.queryByRole("columnheader", { name: "Tenant" })).toBeNull();
    expect(screen.queryByText("SDWAN")).toBeNull();
  });

  it("is hidden for a single-tenant user", async () => {
    setup(false);
    render(<NmsIntegrations />);
    await screen.findByRole("button", { name: "SDWAN" });
    expect(screen.queryByTestId("nms-tenant")).toBeNull();
  });
});

describe("changing another tenant's integration", () => {
  it("the delete confirm names the owning tenant, and a refusal deletes nothing", async () => {
    setup(true);
    render(<NmsIntegrations />);
    fireEvent.click(await screen.findByRole("button", { name: "SDWAN" }));
    expect((await screen.findByTestId("nms-owner-note")).textContent)
      .toContain('This integration belongs to the tenant "RETAIL", not Provider.');
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    const text = String(confirmSpy.mock.calls[0][0]);
    expect(text).toContain('Delete "SDWAN"?');
    expect(text).toContain('belongs to the tenant "RETAIL"');
    expect(mockApi.deleteNmsIntegration).not.toHaveBeenCalled();
  });

  it("pausing another tenant's integration asks first, naming the tenant", async () => {
    setup(true);
    render(<NmsIntegrations />);
    fireEvent.click(await screen.findByRole("button", { name: "SDWAN" }));
    fireEvent.click(await screen.findByRole("button", { name: "Pause collection" }));
    expect(String(confirmSpy.mock.calls[0][0])).toContain('belongs to the tenant "RETAIL"');
    expect(mockApi.updateNmsIntegration).not.toHaveBeenCalled();
  });

  it("your own integration: a plain delete confirm and an immediate pause", async () => {
    setup(true);
    render(<NmsIntegrations />);
    fireEvent.click(await screen.findByRole("button", { name: "Provider vManage" }));
    expect(screen.queryByTestId("nms-owner-note")).toBeNull();
    fireEvent.click(await screen.findByRole("button", { name: "Pause collection" }));
    expect(confirmSpy).not.toHaveBeenCalled();
    await waitFor(() => expect(mockApi.updateNmsIntegration).toHaveBeenCalledWith("nmsi-prov", { enabled: false }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(String(confirmSpy.mock.calls[0][0])).not.toContain("belongs to the tenant");
  });
});
