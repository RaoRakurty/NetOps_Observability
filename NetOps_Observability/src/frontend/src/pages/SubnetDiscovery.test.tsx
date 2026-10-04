// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Subnet Discovery contract (Administration → Data sources, #/admin/discovery).
//
// 1. Audience gate. The page has two honest states — the platform operator's
//    config card, and the tenant explanation — and which one renders is decided
//    by WHO is looking. That decision must wait for auth to RESOLVE: rendering
//    the tenant copy while /api/auth/me is still in flight flashes
//    wrong-audience content at the platform operator.
// 2. SNMP credentials live in ONE place (SNMP Profiles). The card has no
//    community field, never sends `community` on save (the server refuses it
//    400), says which profiles the sweep will try — or warns when there are
//    none — and shows which profile answered for every device it found.
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { DiscoveryConfigEnvelope } from "../services/api";

const mockUseAuth = vi.fn();
vi.mock("../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));

const discoveryConfig = vi.fn();
const saveDiscoveryConfig = vi.fn();
const refreshDiscovery = vi.fn();
const listSnmpCreds = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    discoveryConfig: (...a: unknown[]) => discoveryConfig(...a),
    saveDiscoveryConfig: (...a: unknown[]) => saveDiscoveryConfig(...a),
    refreshDiscovery: (...a: unknown[]) => refreshDiscovery(...a),
    listSnmpCreds: (...a: unknown[]) => listSnmpCreds(...a),
  },
}));

import SubnetDiscovery from "./SubnetDiscovery";

const TENANT_COPY = /Your platform operator runs subnet discovery/i;
const PLATFORM = { user: { username: "root", platform_admin: true }, loading: false };

function envelope(over: Partial<DiscoveryConfigEnvelope> = {}): DiscoveryConfigEnvelope {
  return {
    config: { enabled: true, ranges: ["10.20.0.0/24"], allow_non_private: false, interval_sec: 300 },
    limits: { max_hosts: 4096, max_ranges: 32 },
    stats: { last_poll: new Date().toISOString(), devices: 1 },
    scan_profiles: { total: 3, v2c: 2, v3: 1 },
    found: [{ id: "dev-1", name: "edge-1", address: "10.20.0.5", vendor: "Cisco", credential_ref: "cred-core" }],
    ...over,
  };
}

beforeEach(() => {
  discoveryConfig.mockResolvedValue(envelope());
  saveDiscoveryConfig.mockImplementation(async (c: { enabled: boolean; ranges: string[]; allow_non_private?: boolean }) => ({
    config: { enabled: c.enabled, ranges: c.ranges, allow_non_private: !!c.allow_non_private, interval_sec: 300 },
  }));
  refreshDiscovery.mockResolvedValue({ status: "scheduled" });
  listSnmpCreds.mockResolvedValue([{ id: "cred-core", name: "core-ro", version: "v2c" }]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  location.hash = "";
});

describe("Subnet Discovery auth-audience gate", () => {
  it("renders NEITHER audience's content while auth is still resolving", () => {
    mockUseAuth.mockReturnValue({ user: null, loading: true });
    render(<SubnetDiscovery />);
    expect(screen.queryByText(TENANT_COPY)).toBeNull();
    expect(screen.queryByRole("heading", { name: "Subnet discovery", level: 2 })).toBeNull();
    expect(discoveryConfig).not.toHaveBeenCalled();
  });

  it("shows the config card to the resolved platform operator", async () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    render(<SubnetDiscovery />);
    expect(await screen.findByRole("heading", { name: "Subnet discovery", level: 2 })).toBeTruthy();
    expect(screen.queryByText(TENANT_COPY)).toBeNull();
  });

  it("shows the honest tenant explanation to a resolved tenant user", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "t-user", platform_admin: false }, loading: false });
    render(<SubnetDiscovery />);
    expect(await screen.findByText(TENANT_COPY)).toBeTruthy();
    expect(screen.getByRole("link", { name: "SNMP Profiles" }).getAttribute("href")).toBe("#/admin/snmp");
    expect(screen.getByRole("link", { name: "Devices" }).getAttribute("href")).toBe("#/infrastructure/devices");
    expect(screen.queryByRole("heading", { name: "Subnet discovery", level: 2 })).toBeNull();
    // The tenant never triggers the requireCrossTenant config read.
    expect(discoveryConfig).not.toHaveBeenCalled();
  });
});

describe("Subnet Discovery card — credentials live in SNMP Profiles", () => {
  beforeEach(() => mockUseAuth.mockReturnValue(PLATFORM));

  it("presents the workflow as three numbered steps", async () => {
    render(<SubnetDiscovery />);
    const steps = await screen.findByRole("list", { name: "Set up subnet discovery" });
    const items = within(steps).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(within(items[0]).getByRole("heading", { name: "Add SNMP credentials" })).toBeTruthy();
    expect(within(items[1]).getByRole("heading", { name: "Choose subnets" })).toBeTruthy();
    expect(within(items[2]).getByRole("heading", { name: "Turn on scanning" })).toBeTruthy();
    expect(items.map((li) => li.querySelector(".disc-step-num")?.textContent)).toEqual(["1", "2", "3"]);
    // Step 1 says what the sweep will try, and links to where credentials live.
    expect(within(items[0]).getByText("3 SNMP profiles will be tried (2 v2c, 1 v3), in name order.")).toBeTruthy();
    expect(within(items[0]).getByRole("link", { name: "Open SNMP Profiles" }).getAttribute("href")).toBe("#/admin/snmp");
  });

  it("has no community / password input anywhere", async () => {
    const { container } = render(<SubnetDiscovery />);
    await screen.findByRole("list", { name: "Set up subnet discovery" });
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(screen.queryByText(/communit/i)).toBeNull();
    expect(screen.queryByPlaceholderText(/public/i)).toBeNull();
  });

  it("warns plainly when there are no SNMP profiles to try", async () => {
    discoveryConfig.mockResolvedValue(envelope({ scan_profiles: { total: 0, v2c: 0, v3: 0 }, found: [] }));
    render(<SubnetDiscovery />);
    const steps = await screen.findByRole("list", { name: "Set up subnet discovery" });
    const step1 = within(steps).getAllByRole("listitem")[0];
    expect(within(step1).getByRole("alert").textContent).toMatch(/Nothing can be found until you add one/);
    expect(within(step1).getByRole("link", { name: "Add an SNMP profile" }).getAttribute("href")).toBe("#/admin/snmp");
    expect(screen.queryByText(/will be tried/)).toBeNull();
    expect(screen.getByText("Needs attention")).toBeTruthy();
    expect(screen.getByText("No devices found yet.")).toBeTruthy();
  });

  it("lists found devices with the SNMP profile that answered", async () => {
    render(<SubnetDiscovery />);
    const table = await screen.findByRole("table", { name: "Devices found" });
    expect(within(table).getByRole("columnheader", { name: "Answered with" })).toBeTruthy();
    const row = within(table).getByText("edge-1").closest("tr")!;
    expect(within(row).getByText("10.20.0.5")).toBeTruthy();
    expect(within(row).getByText("Cisco")).toBeTruthy();
    // credential_ref resolved to the profile's name.
    expect(await within(row).findByText("core-ro")).toBeTruthy();
  });

  it("falls back to the raw profile reference when profile names cannot be read", async () => {
    listSnmpCreds.mockRejectedValue(new Error("403 Forbidden: no"));
    render(<SubnetDiscovery />);
    const table = await screen.findByRole("table", { name: "Devices found" });
    expect(await within(table).findByText("cred-core")).toBeTruthy();
  });

  it("saves without ever sending a community", async () => {
    render(<SubnetDiscovery />);
    const input = await screen.findByLabelText("Subnets to scan, comma-separated");
    fireEvent.change(input, { target: { value: "10.20.0.0/24, 10.30.5.0/26" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(saveDiscoveryConfig).toHaveBeenCalledTimes(1));
    const body = saveDiscoveryConfig.mock.calls[0][0] as Record<string, unknown>;
    expect(body).not.toHaveProperty("community");
    expect(body).toEqual({ enabled: true, ranges: ["10.20.0.0/24", "10.30.5.0/26"], allow_non_private: false });
    expect(await screen.findByText("Saved. A scan has been scheduled.")).toBeTruthy();
  });

  it("reports save and scan failures in operator words, not raw envelopes", async () => {
    saveDiscoveryConfig.mockRejectedValue(new Error("400 Bad Request: {\"error\":\"only private subnets can be scanned\"}"));
    refreshDiscovery.mockRejectedValue(new Error(""));
    render(<SubnetDiscovery />);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByText("Only private subnets can be scanned.")).toBeTruthy());
    expect(screen.queryByText(/400 Bad Request/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    expect(await screen.findByText("The scan could not be started.")).toBeTruthy();
  });
});
