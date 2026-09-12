// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Devices.monitoring.test.tsx — the inventory page's half of the C4 rule.
//
// The product decision this page has to carry is one sentence: DISCOVERED IS
// NOT LICENSED. A network with five hundred discovered devices and twelve
// monitored ones is using twelve of its allowance, and a page that shows only
// "500 devices" beside a limit of 25 teaches the operator the opposite.
//
// So three things are tested here and nothing else is:
//
//   1. BOTH NUMBERS ARE ON THE SCREEN, named for what they are.
//   2. THE SWITCH IS REAL. The row's control calls the server; the page does
//      not decide anything about the licence itself.
//   3. A REFUSAL IS AN UPGRADE CARD, NOT AN ERROR. Nothing broke, nothing was
//      deleted, and the operator is told what to do about it.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
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
  setDeviceMonitoring: vi.fn(),
  upsertDevice: vi.fn(),
  deleteDevice: vi.fn(),
  setDeviceSite: vi.fn(),
  clearDeviceSite: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));
vi.mock("../components/Icon", () => ({ default: () => <span /> }));

import Devices, { monitoringRemedy } from "./Devices";

function device(over: Partial<Device> = {}): Device {
  return {
    id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp",
    last_seen: new Date().toISOString(), monitored: false,
    monitor_reason: "found by subnet discovery and not yet enabled for monitoring",
    ...over,
  };
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

describe("discovered is not licensed", () => {
  it("shows the discovered count and the monitored count as different numbers", async () => {
    setup([
      device({ id: "d1", monitored: true, monitor_methods: ["snmp"] }),
      device({ id: "d2" }),
      device({ id: "d3" }),
    ]);
    render(<Devices />);
    expect(await screen.findByText("Discovered 3 · Monitored 1")).toBeTruthy();
    expect(screen.getByText("Discovered devices")).toBeTruthy();
    expect(screen.getByText("Monitored devices")).toBeTruthy();
  });

  it("labels each row with whether Correlix is collecting from it", async () => {
    setup([
      device({ id: "d1", monitored: true, monitor_methods: ["gnmi", "snmp"] }),
      device({ id: "d2" }),
    ]);
    render(<Devices />);
    expect(await screen.findByText("Monitored")).toBeTruthy();
    expect(screen.getByText("Not monitored")).toBeTruthy();
    // Two telemetry methods on ONE device: shown, but still one monitored
    // device on the count above.
    expect(screen.getByText("gnmi · snmp")).toBeTruthy();
    expect(screen.getByText("Discovered 2 · Monitored 1")).toBeTruthy();
  });
});

describe("the monitoring switch", () => {
  it("asks the server to start collecting", async () => {
    setup([device({ id: "d1" })]);
    mockApi.setDeviceMonitoring.mockResolvedValue({
      device_id: "d1", monitored: true, reason: "monitoring was enabled", decided: true,
    });
    render(<Devices />);
    fireEvent.click(await screen.findByTitle(/Start collecting/));
    await waitFor(() => expect(mockApi.setDeviceMonitoring).toHaveBeenCalledWith("d1", true));
  });

  it("asks the server to stop, and says the device stays", async () => {
    setup([device({ id: "d1", monitored: true })]);
    mockApi.setDeviceMonitoring.mockResolvedValue({
      device_id: "d1", monitored: false, reason: "monitoring was turned off", decided: true,
    });
    render(<Devices />);
    const stop = await screen.findByTitle(/Stop collecting/);
    expect(stop.getAttribute("title")).toContain("stays in the inventory");
    fireEvent.click(stop);
    await waitFor(() => expect(mockApi.setDeviceMonitoring).toHaveBeenCalledWith("d1", false));
  });

  it("renders a ceiling refusal as an upgrade card, not as a failure", async () => {
    setup([device({ id: "d1" })]);
    mockApi.setDeviceMonitoring.mockRejectedValue(new Error(
      '402 Payment Required: {"error":"licence_ceiling","ceiling":"devices",' +
      '"unit":"monitored_devices","current":25,"limit":25,"tier":"community","lifted_by":"team",' +
      '"message":"your Community licence covers 25 monitored devices and 25 are in use"}',
    ));
    render(<Devices />);
    fireEvent.click(await screen.findByTitle(/Start collecting/));

    // The card, with the server's own sentence and the remedy.
    expect(await screen.findByLabelText("Licence limit")).toBeTruthy();
    expect(screen.getByText(/covers 25 monitored devices/)).toBeTruthy();
    expect(screen.getByText(/Disable monitoring on another device/)).toBeTruthy();
    expect(screen.getByText(/Nothing has been removed and nothing has stopped/)).toBeTruthy();
    // And the device is still on the page: the cap is on monitoring, not on
    // seeing.
    expect(screen.getByText("Discovered 1 · Monitored 0")).toBeTruthy();
  });
});

describe("monitoringRemedy", () => {
  it("names the limit, the counts and what to do about it", () => {
    const text = monitoringRemedy({
      kind: "ceiling", ceiling: "devices", current: 25, limit: 25,
      tier: "community", liftedBy: "team", message: "…",
    });
    expect(text).toContain("Community monitoring limit reached");
    expect(text).toContain("25 of 25 monitored devices are currently enabled");
    expect(text).toContain("Disable monitoring on another device");
    expect(text).toContain("upgrade your licence");
    expect(text).toContain("Nothing was deleted");
  });

  it("stays a sentence when the platform sends no counts", () => {
    const text = monitoringRemedy({ kind: "ceiling", ceiling: "devices", tier: "community", message: "…" });
    expect(text).toContain("Community monitoring limit reached.");
    expect(text).not.toContain("undefined");
  });
});

// ── the soft-overage banner (owner decision, 2026-09-05) ────────────────────
//
// An operator enabling their 260th device should learn that it is being
// recorded HERE, where they are doing it — not only on a Licence page they may
// never open.

describe("the monitored-device overage banner", () => {
  const overage = (soft: boolean) => ({
    ceiling: "devices",
    label: "monitored devices",
    unit: "monitored_devices",
    current: 262,
    limit: 250,
    over: 12,
    soft,
    message: "…",
  });

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
      overages: [overage(soft)],
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
    expect(banner.textContent).toContain("nothing has been blocked, disabled or deleted");
    // The C4 wording, reused verbatim from the ceiling itself.
    expect(banner.textContent).toContain("monitored devices");
    // The sentence "Discovery does not consume your monitoring allowance" left
    // the banner in the 2026-09-06 word sweep; it is now the authored answer
    // behind the banner's (i) (ai/skills/explain/devices.allowance.md).
    expect(within(banner).getByRole("button", { name: /Ask Iris about the monitored-device allowance/ })).toBeTruthy();
  });

  it("keeps the honest hard wording where the ceiling really does bite", async () => {
    setup([]);
    mockApi.getLicence.mockResolvedValue(licenceView(false));
    render(<Devices />);
    expect(await screen.findByText("Over the monitored-device ceiling")).toBeTruthy();
    const banner = screen.getByRole("note");
    expect(banner.textContent).toContain("nothing has been removed");
    expect(banner.textContent).not.toContain("true-up");
  });

  it("shows no banner at all when the caller cannot read the licence", async () => {
    setup([]); // getLicence rejects with 403 in the default fixture
    render(<Devices />);
    await screen.findByText("Inventory & Devices");
    expect(screen.queryByRole("note")).toBeNull();
  });
});
