// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Devices.visual.test.tsx — the Devices page is the exemplar of the visual
// language kit (docs/design/visual-language.md, phase 2):
//
//   1. a page header: level-1 "Devices" with the fleet count;
//   2. health as ONE status chip per row — icon + word + semantic tone;
//   3. toolbar pill dropdowns that really filter (health, site, vendor);
//   4. descriptive values (vendor, source) neutral — no hue of their own;
//   5. an outlined "Open" row action that opens the device.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { Device } from "../services/api";

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
  configDriftList: vi.fn(),
  myScopes: vi.fn().mockResolvedValue({ scopes: [], all_tenants: false }),
}));

vi.mock("../services/api", () => ({ api: mockApi, getActiveScope: () => "" }));
vi.mock("./DeviceDetailPage", () => ({ default: ({ device }: { device: Device }) => <div>detail of {device.name}</div> }));

import Devices, { syncLabel, neutralShade } from "./Devices";

function device(over: Partial<Device> = {}): Device {
  return {
    id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp", vendor: "cisco",
    last_seen: new Date().toISOString(), monitored: true, monitor_state: "monitored",
    monitor_methods: ["snmp"], reachability: "up",
    ...over,
  };
}

function setup(devices: Device[]) {
  mockApi.devices.mockResolvedValue(devices);
  mockApi.alerts.mockResolvedValue([]);
  mockApi.deviceLocations.mockResolvedValue({ devices: [] });
  mockApi.sites.mockResolvedValue({ sites: [], active: "internal" });
  mockApi.features.mockResolvedValue({});
  mockApi.getLicence.mockRejectedValue(new Error("403"));
  mockApi.configDriftList.mockRejectedValue(new Error("off"));
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const fleet = [
  device({ id: "c40", name: "cEDGE-40", address: "10.255.255.40", reachability: "up", configured_location: "Site 40", model: "C8000V" }),
  device({ id: "c80", name: "cEDGE-80", address: "10.255.255.80", reachability: "partial", configured_location: "Site 80" }),
  device({ id: "v100", name: "vEdge-100", address: "10.255.255.100", reachability: "down", vendor: "viptela", configured_location: "Site 100" }),
];

describe("the Devices page in the visual language", () => {
  it("opens with a level-1 header carrying the fleet count", async () => {
    setup(fleet);
    render(<Devices />);
    expect(await screen.findByRole("heading", { level: 1, name: "Devices" })).toBeTruthy();
    expect((await screen.findByLabelText("3 items")).textContent).toBe("3");
  });

  it("shows health as one chip per row — the word, with a semantic tone", async () => {
    setup(fleet);
    const { container } = render(<Devices />);
    await screen.findByText("cEDGE-40");
    const tones = (word: string) =>
      [...container.querySelectorAll(".dtv-row .kit-status")].filter((c) => c.textContent === word).map((c) => (c as HTMLElement).dataset.tone);
    expect(tones("Up")).toEqual(["ok"]);
    expect(tones("Degraded")).toEqual(["warn"]);
    expect(tones("Down")).toEqual(["bad"]);
  });

  it("shows the hostname with its management address under it", async () => {
    setup(fleet);
    render(<Devices />);
    expect(await screen.findByText("cEDGE-40")).toBeTruthy();
    expect(screen.getByText("10.255.255.40")).toBeTruthy();
    // Vendor · model is plain, neutral text.
    expect(screen.getByText("Cisco · C8000V").className).toContain("kit-muted");
  });

  it("filters by health, by site and by vendor from the toolbar pills", async () => {
    setup(fleet);
    render(<Devices />);
    await screen.findByText("cEDGE-40");

    fireEvent.change(screen.getByRole("combobox", { name: "Filter by health" }), { target: { value: "down" } });
    await waitFor(() => expect(screen.queryByText("cEDGE-40")).toBeNull());
    expect(screen.getByText("vEdge-100")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by health" }), { target: { value: "all" } });

    fireEvent.change(screen.getByRole("combobox", { name: "Filter by site" }), { target: { value: "Site 80" } });
    await waitFor(() => expect(screen.queryByText("cEDGE-40")).toBeNull());
    expect(screen.getByText("cEDGE-80")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by site" }), { target: { value: "" } });

    fireEvent.change(screen.getByRole("combobox", { name: "Filter by vendor" }), { target: { value: "Viptela" } });
    await waitFor(() => expect(screen.queryByText("cEDGE-80")).toBeNull());
    expect(screen.getByText("vEdge-100")).toBeTruthy();
  });

  it("offers only the sites and vendors the fleet has, with their counts", async () => {
    setup(fleet);
    render(<Devices />);
    await screen.findByText("cEDGE-40");
    const vendor = screen.getByRole("combobox", { name: "Filter by vendor" }) as HTMLSelectElement;
    expect([...vendor.options].map((o) => o.textContent)).toEqual(["All vendors", "Cisco · 2", "Viptela · 1"]);
  });

  it("opens the device from the outlined Open action", async () => {
    setup(fleet);
    render(<Devices />);
    const row = (await screen.findByText("cEDGE-40")).closest(".dtv-row") as HTMLElement;
    fireEvent.click(within(row).getByRole("button", { name: "Open" }));
    expect(await screen.findByText("detail of cEDGE-40")).toBeTruthy();
  });
});

describe("states and descriptive values", () => {
  it("maps config sync to status kinds", () => {
    expect(syncLabel(undefined).kind).toBe("neutral");
    expect(syncLabel({ device_id: "d", state: "in_sync", last_capture_at: "2026-11-24T00:00:00Z" } as never).kind).toBe("in-sync");
    expect(syncLabel({ device_id: "d", state: "drifted", last_capture_at: "2026-11-24T00:00:00Z" } as never).kind).toBe("bad");
    expect(syncLabel({ device_id: "d", state: "failed", last_capture_at: "2026-11-24T00:00:00Z" } as never).kind).toBe("failed");
  });

  it("tells descriptive slices apart by shades of one neutral, never a hue", () => {
    for (let i = 0; i < 8; i++) {
      const c = neutralShade("x", i);
      expect(c).toMatch(/^color-mix\(in srgb, var\(--fg-muted, var\(--muted\)\) \d+%, transparent\)$/);
    }
  });
});
