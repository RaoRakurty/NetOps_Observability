// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Devices.sources.test.tsx — tracker 389: the Devices page shows the value the
// workspace's source order picks (the one Iris cites) and, when the sources
// disagree, a quiet neutral marker carrying the sentence Iris states.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
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

import Devices from "./Devices";

const SENTENCE = "Sources disagree on the software version: using 20.6.1 from the controller (vmanage) — the controller (vmanage) ranks first under the platform default source order (controller > discovered > declared > manual); the device itself (SNMP) reports 20.6.2; a manual entry reports 9.9.9.";

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

const base: Device = {
  id: "edge-1", name: "edge-1", address: "10.255.255.20", source: "nms:controller", vendor: "Cisco",
  model: "vedge-cloud", software_version: "20.6.1", last_seen: new Date().toISOString(),
  monitored: true, monitor_state: "monitored", monitor_methods: ["snmp"], reachability: "up",
};

describe("source disagreements on the Devices page", () => {
  it("shows the winning value with a neutral marker carrying the sentence Iris states", async () => {
    setup([{
      ...base,
      source_disagreements: [{
        fact: "software_version", label: "software version", value: "20.6.1", source: "the controller (vmanage)",
        others: [{ value: "20.6.2", source: "the device itself (SNMP)" }, { value: "9.9.9", source: "a manual entry" }],
        text: SENTENCE,
      }],
    }]);
    render(<Devices />);
    expect(await screen.findByText("20.6.1")).toBeTruthy();
    const note = screen.getByTestId("srcnote-version-edge-1");
    expect(note.getAttribute("title")).toBe(SENTENCE);
    expect(note.getAttribute("aria-label")).toContain("Sources disagree on the software version");
    expect(note.getAttribute("aria-label")).toContain("a manual entry reports 9.9.9");
    // Information, not an alarm: the neutral marker class, never a status tone.
    expect(note.className).toBe("kit-srcnote");
    expect(note.closest("[data-tone]")).toBeNull();
    // Only the disagreeing fact carries a marker.
    expect(screen.queryByTestId("srcnote-vendor-edge-1")).toBeNull();
  });

  it("shows no marker when the sources agree", async () => {
    setup([base]);
    render(<Devices />);
    expect(await screen.findByText("20.6.1")).toBeTruthy();
    expect(screen.queryByTestId("srcnote-version-edge-1")).toBeNull();
  });
});
