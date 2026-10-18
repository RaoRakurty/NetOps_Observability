// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Sensors (Administration → Discovery → Sensors): each collector carries the
// platform switch that turns it on, with what is RUNNING shown honestly until
// a restart applies a change. A switched-off collector that does not register
// still gets a row — otherwise there would be nothing to turn back on.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type { CollectorStatus, PlatformFeature, PlatformFeatures } from "../services/api";

const apiMock = vi.hoisted(() => ({
  collectors: vi.fn(),
  platformFeatures: vi.fn(),
  setPlatformFeature: vi.fn(),
  restartPlatform: vi.fn(),
}));
vi.mock("../services/api", () => ({ api: apiMock }));

import Collectors, { COLLECTOR_SWITCH, switchState } from "./Collectors";

const feat = (o: Partial<PlatformFeature>): PlatformFeature => ({
  env: "X", label: "X", group: "Collection", help: "", apply: "restart", risky: false,
  running: false, desired: false, restart_pending: false, source: "default", install_value: null, ...o,
});
const coll = (o: Partial<CollectorStatus>): CollectorStatus =>
  ({ name: "snmpv2c", kind: "protocol", enabled: true, healthy: true, targets: 8, reachable: 8, ...o }) as CollectorStatus;
const features = (fs: PlatformFeature[], o: Partial<PlatformFeatures> = {}): PlatformFeatures =>
  ({ features: fs, restart_pending: false, can_restart: true, store_load_error: "", ...o });

const SNMP = feat({ env: "ENABLE_SNMP_COLLECTION", label: "SNMP polling", running: true, desired: true });
const GNMI = feat({ env: "ENABLE_GNMI_COLLECTION", label: "gNMI streaming telemetry" });
const TRAPS = feat({ env: "FEATURE_SNMP_TRAPS", label: "SNMP traps" });

beforeEach(() => {
  for (const f of Object.values(apiMock)) f.mockReset();
  apiMock.collectors.mockResolvedValue([coll({ name: "snmpv2c" }), coll({ name: "gnmi", enabled: false, healthy: false, targets: 0 })]);
  apiMock.platformFeatures.mockResolvedValue(features([SNMP, GNMI, TRAPS]));
  apiMock.setPlatformFeature.mockResolvedValue({});
});
afterEach(() => cleanup());

describe("Sensors switches", () => {
  it("maps every collector to the switch that turns it on (SNMP transports share one)", () => {
    expect(COLLECTOR_SWITCH).toMatchObject({
      snmpv2c: "ENABLE_SNMP_COLLECTION", snmpv3: "ENABLE_SNMP_COLLECTION", snmpmetrics: "ENABLE_SNMP_METRICS",
      gnmi: "ENABLE_GNMI_COLLECTION", netconf: "ENABLE_NETCONF_COLLECTION", snmptrap: "FEATURE_SNMP_TRAPS",
    });
  });

  it("states what is running, and what a pending change becomes after the restart", () => {
    expect(switchState(feat({ running: true, desired: true }))).toBe("On");
    expect(switchState(feat({ running: false, desired: false }))).toBe("Off");
    expect(switchState(feat({ running: false, desired: true, restart_pending: true }))).toBe("On after restart");
    expect(switchState(feat({ running: true, desired: false, restart_pending: true }))).toBe("Off after restart");
  });

  it("Turn on sends the switch, unacknowledged (none of these is a risky switch)", async () => {
    render(<Collectors />);
    fireEvent.click(await screen.findByRole("button", { name: "Turn on gNMI streaming telemetry" }));
    await waitFor(() => expect(apiMock.setPlatformFeature).toHaveBeenCalledWith("ENABLE_GNMI_COLLECTION", true, undefined));
    expect(apiMock.platformFeatures).toHaveBeenCalledTimes(2); // re-read after the save
  });

  it("a switched-off collector that did not register still has a row to turn it on", async () => {
    render(<Collectors />);
    expect(await screen.findByTestId("sensor-off-FEATURE_SNMP_TRAPS")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Turn on SNMP traps" })).toBeTruthy();
  });

  it("a running switch with no collector row of its own is never shown as off", async () => {
    apiMock.platformFeatures.mockResolvedValue(features([SNMP, GNMI, TRAPS, feat({ env: "ENABLE_SNMP_METRICS", label: "SNMP metrics", running: true, desired: true })]));
    render(<Collectors />);
    const enabledCell = (id: string) => (screen.getByTestId(id) as HTMLTableRowElement).cells[1].textContent;
    await screen.findByTestId("sensor-off-ENABLE_SNMP_METRICS");
    expect(enabledCell("sensor-off-ENABLE_SNMP_METRICS")).toBe("no separate status");
    expect(enabledCell("sensor-off-FEATURE_SNMP_TRAPS")).toBe("off");
  });

  it("with NO collector registered (everything off) the switches are still there to turn one on", async () => {
    apiMock.collectors.mockResolvedValue([]);
    render(<Collectors />);
    expect(await screen.findByRole("button", { name: "Turn on gNMI streaming telemetry" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Turn on SNMP traps" })).toBeTruthy();
    expect(screen.queryByText("No collectors registered.")).toBeNull();
  });

  it("offers the restart when a change is waiting for one", async () => {
    apiMock.platformFeatures.mockResolvedValue(features([SNMP, { ...GNMI, desired: true, restart_pending: true }], { restart_pending: true }));
    apiMock.restartPlatform.mockResolvedValue({ status: "restarting" });
    render(<Collectors />);
    expect(await screen.findByTestId("sensor-restart-banner")).toBeTruthy();
    expect(screen.getByText("On after restart")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Restart now" }));
    await waitFor(() => expect(apiMock.restartPlatform).toHaveBeenCalled());
  });

  it("a refused change shows the server's own reason", async () => {
    apiMock.setPlatformFeature.mockRejectedValue(new Error('403 Forbidden: {"error":"step-up required: sign in again with your second factor"}'));
    render(<Collectors />);
    fireEvent.click(await screen.findByRole("button", { name: "Turn on gNMI streaming telemetry" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toMatch(/step-up required: sign in again/i);
  });

  it("without the switch API (403) the page still lists collectors, with no Switch column", async () => {
    apiMock.platformFeatures.mockRejectedValue(new Error("403 Forbidden: platform administrator only"));
    render(<Collectors />);
    expect(await screen.findByText("SNMP v2c")).toBeTruthy();
    expect(screen.queryByRole("columnheader", { name: "Switch" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Turn on/ })).toBeNull();
  });
});
