// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Network Scan → "Scans for a customer" (tenant-owned discovery scopes,
// 2026-11-10). Contract:
// 1. The platform administrator sees every customer's scan and adds one in four
//    numbered steps; step 2 offers ONLY the chosen customer's own SNMP profiles
//    (owner decision D2) and the saved body is exactly what the server accepts.
// 2. A customer sees "Your scans" read-only: no add, change or remove control,
//    and it never asks for the tenant list.
// 3. A device the platform scan also holds is flagged in plain words, because
//    its telemetry is attributed to nobody until one copy is removed.
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { DiscoveryScopesEnvelope } from "../../services/api";

const discoveryScopes = vi.fn();
const createDiscoveryScope = vi.fn();
const updateDiscoveryScope = vi.fn();
const deleteDiscoveryScope = vi.fn();
const listSnmpCreds = vi.fn();
const listTenants = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    discoveryScopes: (...a: unknown[]) => discoveryScopes(...a),
    createDiscoveryScope: (...a: unknown[]) => createDiscoveryScope(...a),
    updateDiscoveryScope: (...a: unknown[]) => updateDiscoveryScope(...a),
    deleteDiscoveryScope: (...a: unknown[]) => deleteDiscoveryScope(...a),
    listSnmpCreds: (...a: unknown[]) => listSnmpCreds(...a),
    listTenants: (...a: unknown[]) => listTenants(...a),
  },
}));

import CustomerScans from "./CustomerScans";

function envelope(): DiscoveryScopesEnvelope {
  return {
    scopes: [
      {
        id: "ds-0000000000000001", tenant_id: "t_retail", tenant_name: "RETAIL-WALMART", name: "RETAIL edges",
        ranges: ["10.70.0.80/30"], allow_non_private: false, credential_refs: ["p-retail"], enabled: true,
        status: { last_sweep: new Date().toISOString(), answering: 2, stale: 0 },
        found: [
          { id: "cedge-81-aa", name: "cEDGE-81", address: "10.70.0.81", vendor: "cisco", credential_ref: "p-retail", also_found_by_platform: true },
          { id: "cedge-82-bb", name: "cEDGE-82", address: "10.70.0.82", vendor: "cisco", credential_ref: "p-retail", also_found_by_platform: false },
        ],
        found_total: 2,
      },
    ],
    limits: { max_hosts: 4096, per_customer: 16, max_credential_refs: 16 },
  };
}

beforeEach(() => {
  discoveryScopes.mockResolvedValue(envelope());
  listSnmpCreds.mockResolvedValue([
    { id: "p-retail", name: "RETAIL edges ro", version: "v2c", tenant_id: "t_retail" },
    { id: "p-retail-v3", name: "RETAIL v3", version: "v3", tenant_id: "t_retail" },
    { id: "p-acme", name: "Acme ro", version: "v2c", tenant_id: "t_acme" },
    { id: "p-plat", name: "Platform ro", version: "v2c" },
  ]);
  listTenants.mockResolvedValue([
    { id: "global", name: "Provider", slug: "global" },
    { id: "t_retail", name: "RETAIL-WALMART", slug: "retail" },
    { id: "t_acme", name: "Acme", slug: "acme" },
  ]);
  createDiscoveryScope.mockResolvedValue({});
  updateDiscoveryScope.mockResolvedValue({});
  deleteDiscoveryScope.mockResolvedValue(undefined);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe("Scans for a customer — platform administrator", () => {
  it("lists each customer's scan with the profile that answered and the duplicate flag", async () => {
    render(<CustomerScans platformAdmin />);
    expect(await screen.findByRole("heading", { name: "Scans for a customer", level: 2 })).toBeTruthy();
    const scan = await screen.findByRole("region", { name: "Scan RETAIL edges" });
    expect(within(scan).getByText(/RETAIL-WALMART ·/)).toBeTruthy();
    expect(within(scan).getByText("On")).toBeTruthy();
    const table = within(scan).getByRole("table", { name: "Devices found by RETAIL edges" });
    const row81 = within(table).getByText("cEDGE-81").closest("tr")!;
    expect(within(row81).getByText("Also found by the platform scan")).toBeTruthy();
    expect(await within(row81).findByText("RETAIL edges ro")).toBeTruthy();
    const row82 = within(table).getByText("cEDGE-82").closest("tr")!;
    expect(within(row82).queryByText("Also found by the platform scan")).toBeNull();
    // The banner says what the duplicate costs, in plain words.
    expect(within(scan).getByRole("note").textContent).toMatch(/1 device is also in the platform's own list\. Telemetry from it is not attributed to anyone until one copy is removed/);
  });

  it("adds a scan in four numbered steps, offering only the chosen customer's own profiles", async () => {
    render(<CustomerScans platformAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "New scan for a customer" }));
    const steps = screen.getByRole("list", { name: "Set up a scan for a customer" });
    const items = within(steps).getAllByRole("listitem");
    expect(items.map((li) => within(li).getByRole("heading").textContent)).toEqual([
      "Choose the customer", "SNMP profiles", "Choose the addresses", "Turn it on",
    ]);
    expect(items.map((li) => li.querySelector(".disc-step-num")?.textContent)).toEqual(["1", "2", "3", "4"]);
    const select = within(items[0]).getByLabelText("Customer") as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3)); // placeholder + 2 customers, never the Provider
    expect(Array.from(select.options).map((o) => o.textContent)).not.toContain("Provider");
    fireEvent.change(select, { target: { value: "t_retail" } });
    const group = within(items[1]).getByRole("group", { name: "The customer's SNMP profiles" });
    const offered = within(group).getAllByRole("checkbox").map((c) => c.closest("label")!.textContent);
    expect(offered).toEqual(["RETAIL edges ro (v2c)", "RETAIL v3 (v3)"]); // not Acme's, not the platform's
    fireEvent.click(within(group).getAllByRole("checkbox")[0]);
    fireEvent.change(within(items[0]).getByLabelText("Name of this scan"), { target: { value: "Branch edges" } });
    fireEvent.change(within(items[2]).getByLabelText("Addresses to scan, comma-separated"), { target: { value: "10.70.0.81/32, 10.70.1.0/28" } });
    expect(within(items[2]).getByText("17 / 4,096 addresses")).toBeTruthy();
    fireEvent.click(within(items[3]).getByRole("button", { name: "Add scan" }));
    await waitFor(() => expect(createDiscoveryScope).toHaveBeenCalledTimes(1));
    expect(createDiscoveryScope.mock.calls[0][0]).toEqual({
      tenant_id: "t_retail", name: "Branch edges", ranges: ["10.70.0.81/32", "10.70.1.0/28"],
      allow_non_private: false, credential_refs: ["p-retail"], enabled: true,
    });
    expect(await screen.findByText("Scan added. It runs within a few minutes.")).toBeTruthy();
  });

  it("warns when the chosen customer has no SNMP profile, and will not save an empty or oversized scan", async () => {
    listSnmpCreds.mockResolvedValue([{ id: "p-plat", name: "Platform ro", version: "v2c" }]);
    render(<CustomerScans platformAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "New scan for a customer" }));
    const select = screen.getByLabelText("Customer") as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3));
    fireEvent.change(select, { target: { value: "t_acme" } });
    expect(screen.getByText(/This customer has no SNMP profile yet/)).toBeTruthy();
    const add = screen.getByRole("button", { name: "Add scan" }) as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Name of this scan"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Addresses to scan, comma-separated"), { target: { value: "10.0.0.0/8" } });
    expect(add.disabled).toBe(true); // over the shared limit
  });

  it("changes a scan without ever sending a customer, and removes one after confirming", async () => {
    render(<CustomerScans platformAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Change scan RETAIL edges" }));
    expect(screen.getByText(/a scan's customer cannot be changed/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateDiscoveryScope).toHaveBeenCalledTimes(1));
    const [id, body] = updateDiscoveryScope.mock.calls[0];
    expect(id).toBe("ds-0000000000000001");
    expect(body).not.toHaveProperty("tenant_id");

    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    fireEvent.click(await screen.findByRole("button", { name: "Remove scan RETAIL edges" }));
    expect(confirm).toHaveBeenCalled();
    expect(deleteDiscoveryScope).not.toHaveBeenCalled();
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Remove scan RETAIL edges" }));
    await waitFor(() => expect(deleteDiscoveryScope).toHaveBeenCalledWith("ds-0000000000000001"));
  });

  it("reports a refused save in operator words", async () => {
    createDiscoveryScope.mockRejectedValue(new Error('400 Bad Request: {"error":"the scans together would probe 5000 addresses per sweep"}'));
    render(<CustomerScans platformAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "New scan for a customer" }));
    const select = screen.getByLabelText("Customer") as HTMLSelectElement;
    await waitFor(() => expect(select.options.length).toBe(3));
    fireEvent.change(select, { target: { value: "t_retail" } });
    fireEvent.change(screen.getByLabelText("Name of this scan"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Addresses to scan, comma-separated"), { target: { value: "10.70.0.0/29" } });
    fireEvent.click(screen.getByRole("button", { name: "Add scan" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText(/400 Bad Request/)).toBeNull();
  });
});

describe("Your scans — a customer", () => {
  it("is read-only and never asks for the tenant list", async () => {
    render(<CustomerScans platformAdmin={false} />);
    expect(await screen.findByRole("heading", { name: "Your scans", level: 2 })).toBeTruthy();
    const scan = await screen.findByRole("region", { name: "Scan RETAIL edges" });
    const row81 = within(scan).getByText("cEDGE-81").closest("tr")!;
    expect(within(row81).getByText("Also found by the platform scan")).toBeTruthy();
    expect(within(scan).getByRole("note")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New scan for a customer" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Change scan/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Remove scan/ })).toBeNull();
    expect(screen.queryByText(/RETAIL-WALMART ·/)).toBeNull(); // no customer column for the customer itself
    expect(listTenants).not.toHaveBeenCalled();
  });

  it("says plainly when there is no scan yet", async () => {
    discoveryScopes.mockResolvedValue({ scopes: [] });
    render(<CustomerScans platformAdmin={false} />);
    expect(await screen.findByText("Your platform operator has not set up a scan for you.")).toBeTruthy();
  });

  it("renders nothing when the server refuses the read", async () => {
    discoveryScopes.mockRejectedValue(new Error("403 Forbidden: infrastructure read permission required"));
    const { container } = render(<CustomerScans platformAdmin={false} />);
    await waitFor(() => expect(discoveryScopes).toHaveBeenCalled());
    await waitFor(() => expect(container.textContent).toBe(""));
  });
});
