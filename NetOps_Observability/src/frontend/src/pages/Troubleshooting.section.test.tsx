// Troubleshooting.section.test.tsx — the two-section Troubleshooting page.
//
// What is pinned here:
//  · the section switch is registered on the page and is a toggle-button group
//    (aria-pressed), defaulting to the collection-pipeline board
//  · picking "Protocol diagnostics" mounts the real panel (route/tab
//    registration — not a stub)
//  · the deep link #/investigate/troubleshooting?section=protocol lands on the
//    diagnostics; anything unrecognized falls back to the board
//
// The metric board itself is stubbed: it is charted elsewhere and its ECharts
// dependency has nothing to do with the registration this file asserts.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, act } from "@testing-library/react";

vi.mock("../components/board/panels", () => ({
  Group: ({ title, children }: { title: string; children?: unknown }) => (
    <section aria-label={title}>{children as never}</section>
  ),
  Panel: ({ title, children }: { title: string; children?: unknown }) => (
    <section aria-label={title}>{children as never}</section>
  ),
  MetricLine: ({ title }: { title: string }) => <div>{title}</div>,
  MetricTop: ({ title }: { title: string }) => <div>{title}</div>,
  MetricStat: ({ label }: { label: string }) => <div>{label}</div>,
  fmtNum: (n: number) => String(n),
}));
vi.mock("../components/ui", () => ({
  StatStrip: ({ children }: { children?: unknown }) => <div>{children as never}</div>,
  Stat: ({ label }: { label: string }) => <div>{label}</div>,
  StatTone: undefined,
}));

const flowsByType = vi.fn();
const searchLogs = vi.fn();
const devices = vi.fn();
const permissions = vi.fn();
const protocolDiagCatalog = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    flowsByType: (...a: unknown[]) => flowsByType(...a),
    searchLogs: (...a: unknown[]) => searchLogs(...a),
    devices: (...a: unknown[]) => devices(...a),
    permissions: (...a: unknown[]) => permissions(...a),
    protocolDiagCatalog: (...a: unknown[]) => protocolDiagCatalog(...a),
    protocolDiagCollect: vi.fn(),
    protocolDiagAnalyze: vi.fn(),
  },
}));

import Troubleshooting, { sectionFromHash } from "./Troubleshooting";

beforeEach(() => {
  for (const m of [flowsByType, searchLogs, devices, permissions, protocolDiagCatalog]) m.mockReset();
  flowsByType.mockResolvedValue({ data: [] });
  searchLogs.mockResolvedValue({ hits: { total: { value: 0 } } });
  devices.mockResolvedValue([]);
  permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
  protocolDiagCatalog.mockResolvedValue({
    ruleset_version: "correlix-protocoldiag-2026-08-27",
    vendor: "cisco-iosxe", vendor_display: "Cisco IOS-XE",
    protocols: ["bgp", "ospf", "isis"],
    issues: { bgp: [], ospf: [], isis: [] },
  });
  if (typeof location !== "undefined") location.hash = "#/investigate/troubleshooting";
});
afterEach(() => cleanup());

describe("sectionFromHash", () => {
  it("reads the protocol deep link and falls back to the board", () => {
    expect(sectionFromHash("#/investigate/troubleshooting?section=protocol")).toBe("protocol");
    expect(sectionFromHash("#/investigate/troubleshooting")).toBe("pipeline");
    expect(sectionFromHash("#/investigate/troubleshooting?section=nonsense")).toBe("pipeline");
  });
});

describe("the section switch", () => {
  it("defaults to the collection-pipeline board", async () => {
    // awaited so the board's own async stat loaders settle inside act()
    await act(async () => { render(<Troubleshooting rangeMinutes={60} />); });
    const group = screen.getByRole("group", { name: "Troubleshooting section" });
    expect(group.querySelector('button[aria-pressed="true"]')?.textContent).toBe("Collection pipeline");
    expect(screen.getByText("Monitored devices")).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Protocol" })).toBeNull();
  });

  it("mounts the protocol diagnostics panel when picked", async () => {
    await act(async () => { render(<Troubleshooting rangeMinutes={60} />); });
    fireEvent.click(screen.getByRole("button", { name: "Protocol diagnostics" }));
    expect(await screen.findByRole("group", { name: "Protocol" })).toBeInTheDocument();
    expect(screen.getByLabelText("Protocol diagnostics")).toBeInTheDocument();
    expect(screen.queryByText("Monitored devices")).toBeNull();
  });

  it("opens on the diagnostics from the deep link", async () => {
    location.hash = "#/investigate/troubleshooting?section=protocol";
    await act(async () => { render(<Troubleshooting rangeMinutes={60} />); });
    expect(await screen.findByRole("group", { name: "Protocol" })).toBeInTheDocument();
  });
});
