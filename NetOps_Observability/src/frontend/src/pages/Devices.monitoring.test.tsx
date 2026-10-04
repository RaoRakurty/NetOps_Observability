// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Devices.monitoring.test.tsx — the inventory page's half of the owner's
// 2026-10-03 rule: every device with an address is monitored, up to the licence
// limit, first found first. The rest stay in the list, marked over the limit.
//
// Four things are tested here:
//
//   1. THERE IS NO SWITCH. No row offers a control to start or stop monitoring.
//   2. EACH ROW SAYS ITS STATE — monitored, over the licence limit, or not
//      monitored — in plain words.
//   3. THE BANNER COUNTS what is not collected and names the limit, so nothing
//      is silently dropped. It is built from the (tenant-scoped) device rows.
//   4. THE SOFT OVERAGE (paid tiers) still reads as a billing fact.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import type { Device } from "../services/api";

const mockApi = vi.hoisted(() => ({
  devices: vi.fn(),
  alerts: vi.fn(),
  deviceLocations: vi.fn(),
  sites: vi.fn(),
  features: vi.fn(),
  // Best-effort on the page: most operators cannot read the licence at all, so
  // the fleet table must render identically whether this resolves or rejects.
  getLicence: vi.fn(),
  upsertDevice: vi.fn(),
  deleteDevice: vi.fn(),
  setDeviceSite: vi.fn(),
  clearDeviceSite: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import Devices, { overLimitSentence, monitoringLabel } from "./Devices";

function device(over: Partial<Device> = {}): Device {
  return {
    id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp",
    last_seen: new Date().toISOString(), monitored: true, monitor_state: "monitored",
    monitor_reason: "monitored: this device is in the inventory, has a management address and is within the licence",
    monitor_methods: ["snmp"],
    ...over,
  };
}

function overLimitDevice(id: string): Device {
  return device({
    id, name: id, monitored: false, monitor_state: "over_limit", monitor_limit: 25, monitor_methods: undefined,
    monitor_reason: "not monitored: licence limit of 25 devices reached — this device was found after the first 25",
  });
}

function setup(devices: Device[]) {
  mockApi.devices.mockResolvedValue(devices);
  mockApi.alerts.mockResolvedValue([]);
  mockApi.deviceLocations.mockResolvedValue({ devices: [] });
  mockApi.sites.mockResolvedValue({ sites: [], active: "internal" });
  mockApi.features.mockResolvedValue({});
  mockApi.getLicence.mockRejectedValue(new Error("403 Forbidden: administration:admin required"));
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("there is no monitoring switch", () => {
  it("offers no control to start or stop monitoring on any row", async () => {
    setup([device({ id: "d1" }), overLimitDevice("d2"), device({ id: "d3", address: "", monitored: false, monitor_state: "no_address" })]);
    render(<Devices />);
    await screen.findByText("Discovered 3 · Monitored 1");
    expect(screen.queryByRole("button", { name: /^(Monitor|Stop)$/ })).toBeNull();
    expect(screen.queryByTitle(/Start collecting|Stop collecting/)).toBeNull();
  });
});

describe("the monitoring badge", () => {
  it("says each row's state in plain words", async () => {
    setup([
      device({ id: "d1", monitor_methods: ["gnmi", "snmp"] }),
      overLimitDevice("d2"),
      device({ id: "d3", address: "", monitored: false, monitor_state: "no_address", monitor_methods: undefined }),
    ]);
    render(<Devices />);
    expect(await screen.findByText("Monitored")).toBeTruthy();
    const over = screen.getByText("Over licence limit");
    expect(over.className).toContain("warn");
    expect(screen.getByText("Not monitored")).toBeTruthy();
    // Two methods on ONE device are shown, and are still one monitored device.
    expect(screen.getByText("gnmi · snmp")).toBeTruthy();
    // The server's own reason is the hover text.
    expect(over.parentElement?.getAttribute("title")).toContain("licence limit of 25");
  });

  it("labels states for the filter", () => {
    expect(monitoringLabel(device())).toBe("Monitored");
    expect(monitoringLabel(overLimitDevice("x"))).toBe("Over licence limit");
    expect(monitoringLabel(device({ monitored: false, monitor_state: "not_polled" }))).toBe("Not monitored");
  });
});

describe("the over-limit banner", () => {
  it("counts the devices not monitored and names the limit", async () => {
    const fleet = [device({ id: "d1" })];
    for (let i = 0; i < 12; i++) fleet.push(overLimitDevice(`o${i}`));
    setup(fleet);
    render(<Devices />);
    const banner = await screen.findByRole("status");
    expect(banner.textContent).toContain("12 devices are not monitored: licence limit of 25 reached");
    // The 14px step of the type scale.
    expect((banner as HTMLElement).style.fontSize).toBe("14px");
    // Nothing is dropped: every row is still in the table.
    expect(screen.getByText("Discovered 13 · Monitored 1")).toBeTruthy();
  });

  it("is singular for one device", () => {
    expect(overLimitSentence(1, 25)).toBe("1 device is not monitored: licence limit of 25 reached");
    expect(overLimitSentence(3)).toBe("3 devices are not monitored: licence limit reached");
  });

  it("does not appear when every device is monitored", async () => {
    setup([device({ id: "d1" }), device({ id: "d2" })]);
    render(<Devices />);
    await screen.findByText("Discovered 2 · Monitored 2");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("does not count a device that only has no address", async () => {
    setup([device({ id: "d1", address: "", monitored: false, monitor_state: "no_address" })]);
    render(<Devices />);
    await screen.findByText("Discovered 1 · Monitored 0");
    expect(screen.queryByRole("status")).toBeNull();
  });
});

describe("errors", () => {
  it("shows an operator sentence, never the raw api envelope", async () => {
    setup([]);
    mockApi.devices.mockRejectedValue(new Error('502 Bad Gateway: {"error":"dial tcp 172.18.0.9:8080: connect: connection refused"}'));
    render(<Devices />);
    expect(await screen.findByText("The service did not answer.")).toBeTruthy();
    expect(screen.queryByText(/172\.18\.0\.9/)).toBeNull();
  });
});

// ── the soft-overage banner (owner decision, 2026-09-05) ────────────────────

describe("the paid-tier overage banner", () => {
  const licenceView = (soft: boolean) =>
    ({
      scope: "platform",
      managed_by: "provider",
      managed_by_detail: "",
      state: {
        source: "file", tier: soft ? "team" : "community",
        ceilings: {
          devices: soft ? 250 : 25, tenants: 1, orgs: 1, retention_days: 7,
          watched_prefixes: 5, skills: 0, provider_tokens_per_day: 0,
        },
        phase: "valid", in_grace: false, degraded: false,
      },
      ceilings: [],
      features: [],
      overages: [{
        ceiling: "devices", label: "monitored devices", unit: "monitored_devices",
        current: soft ? 262 : 37, limit: soft ? 250 : 25, over: 12, soft, message: "…",
      }],
      expiry_semantics: "",
      days_to_expiry: null,
      grace_days_left: null,
    }) as never;

  it("says a PAID overage is recorded, never that anything was blocked", async () => {
    setup([]);
    mockApi.getLicence.mockResolvedValue(licenceView(true));
    render(<Devices />);
    expect(await screen.findByText("Above your monitored-device allowance")).toBeTruthy();
    const banner = screen.getByRole("note");
    expect(banner.textContent).toContain("true-up");
    expect(within(banner).getByRole("button", { name: /Ask Iris about the monitored-device allowance/ })).toBeTruthy();
  });

  it("leaves the hard case to the device-row banner, so it is said once", async () => {
    setup([device({ id: "d1" }), overLimitDevice("d2")]);
    mockApi.getLicence.mockResolvedValue(licenceView(false));
    render(<Devices />);
    expect(await screen.findByRole("status")).toBeTruthy();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("shows no licence banner at all when the caller cannot read the licence", async () => {
    setup([]);
    render(<Devices />);
    await screen.findByText("Inventory & Devices");
    expect(screen.queryByRole("note")).toBeNull();
  });
});
