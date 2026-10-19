// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The device page shows a controller's view of a device it reports (owner
// 2026-10-19): an API-only device gets it INSTEAD of the direct-collection
// figures it can never have; an SNMP twin merged with a controller record gets
// it beside them; an ordinary SNMP device gets none. Every controller figure
// reads with a lookback — vManage publishes 30–60 minutes late.
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { Device } from "../../services/api";

const { queries } = vi.hoisted(() => ({ queries: [] as string[] }));
vi.mock("../../components/board/panels", () => ({
  labelSelector: (o: Record<string, string>) => `{device="${o.device}"}`,
  fmtBps: (n: number) => String(n),
  fmtPct: (n: number) => `${n}%`,
  MetricStat: ({ label, query }: { label: string; query: string }) => { queries.push(query); return <div data-testid="stat">{label}</div>; },
  MetricLine: ({ title, query }: { title: string; query: string }) => { queries.push(query); return <div data-testid="line">{title}</div>; },
}));
vi.mock("../InterfacePerformance", () => ({ default: () => null }));
vi.mock("../DeviceNeighbors", () => ({ default: () => null }));
vi.mock("../config/DeviceConfigPanel", () => ({ default: () => null }));
vi.mock("../capture/DevicePcapPanel", () => ({ default: () => null }));
vi.mock("./VrfInterfaces", () => ({ default: () => null }));

import DeviceDetailPage from "../DeviceDetailPage";
import { controllerOf, controllerOnly } from "./ControllerOverview";

const base = { name: "vEdge-20", address: "10.255.255.20", vendor: "cisco", last_seen: new Date().toISOString(), type: "router" };
const apiDev = { ...base, id: "ctl-vmanage-0a1b2c3d4e5f", source: "api", labels: { source_system: "vmanage", system_ip: "10.255.255.20" } } as unknown as Device;
const twin = { ...base, id: "vedge-20-1e95f00f", address: "192.168.222.104", source: "snmp", labels: { source_system: "vmanage", system_ip: "10.255.255.20" } } as unknown as Device;
const plain = { ...base, id: "core-1-aa", address: "10.0.0.1", source: "snmp", labels: {} } as unknown as Device;

afterEach(() => { cleanup(); queries.length = 0; });

describe("controller view on the device page", () => {
  it("helpers", () => {
    expect(controllerOf(apiDev)).toEqual({ system: "vmanage", label: "vManage" });
    expect(controllerOf(twin)?.label).toBe("vManage");
    expect(controllerOf(plain)).toBeNull();
    expect(controllerOnly(apiDev)).toBe(true);
    expect(controllerOnly(twin)).toBe(false);
  });

  it("an API-only device shows the controller's view and none of the direct-collection figures", () => {
    render(<DeviceDetailPage device={apiDev} onClose={() => {}} />);
    expect(screen.getByRole("region", { name: "From vManage" })).toBeTruthy();
    expect(screen.queryByText("Reachability (1h)")).toBeNull();
    expect(queries.some((q) => q.includes("device_if_oper_status"))).toBe(false);
    // Lookback on every scalar; every query is scoped to THIS device's id.
    const stats = queries.filter((q) => q.includes("controller_metric_") && !q.startsWith("controller_metric_") && !q.startsWith("sum by"));
    expect(stats.length).toBeGreaterThan(0);
    for (const q of stats) expect(q).toContain("[3h]");
    for (const q of queries) expect(q).toContain('device="ctl-vmanage-0a1b2c3d4e5f"');
    expect(screen.getByText(/30–60 minutes late/)).toBeTruthy();
  });

  it("an SNMP twin merged with a controller record shows both", () => {
    render(<DeviceDetailPage device={twin} onClose={() => {}} />);
    expect(screen.getByText("Reachability (1h)")).toBeTruthy();
    expect(screen.getByRole("region", { name: "From vManage" })).toBeTruthy();
  });

  it("an ordinary SNMP device shows no controller view", () => {
    render(<DeviceDetailPage device={plain} onClose={() => {}} />);
    expect(screen.queryByRole("region", { name: /From / })).toBeNull();
    expect(queries.some((q) => q.includes("controller_metric_"))).toBe(false);
  });
});
