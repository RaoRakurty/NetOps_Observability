// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// StackHealth.test.tsx — Platform → Tools → Stack Health, and the Collection
// section that the retired collection-pipeline board's facts moved into.
//
// Owner, 2026-09-07: Troubleshooting had a second section, and a bookmarked
// `?section=pipeline` reopened it on every refresh ("It looks like stale
// page"). The board is deleted; what no other screen carried — the fleet
// counts, one row per collector, and the flow sources — is here.
//
// What is pinned:
//  · the section renders the four counts, the collector rows and the flow
//    sources from the real api calls;
//  · absent is not zero: a metric family with no series renders "—";
//  · the 403 refusal still hides the whole page, Collection included — the
//    section must not become a way around the platform gate.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, within } from "@testing-library/react";

const mocks = vi.hoisted(() => ({
  stackHealth: vi.fn(), metricsQuery: vi.fn(), flowsByType: vi.fn(), searchLogs: vi.fn(),
}));
vi.mock("../services/api", () => ({ api: { ...mocks } }));

import StackHealth from "./StackHealth";

const instant = (result: unknown[]) => ({ status: "success", data: { resultType: "vector", result } });
const scalar = (v: number) => instant([{ metric: {}, value: [1, String(v)] }]);
const byCollector = (pairs: [string, number][]) =>
  instant(pairs.map(([collector, v]) => ({ metric: { collector }, value: [1, String(v)] })));

beforeEach(() => {
  Object.values(mocks).forEach((m) => m.mockReset());
  mocks.stackHealth.mockResolvedValue({
    overall: "healthy", up: 2, degraded: 0, down: 0,
    components: [
      { name: "opensearch", category: "search", status: "up", latency_ms: 4, detail: "" },
      { name: "kafka", category: "bus", status: "up", latency_ms: 2, detail: "" },
    ],
  });
  mocks.metricsQuery.mockImplementation((q: string) => {
    if (q.includes('collector="snmpmetrics"')) return Promise.resolve(scalar(12));
    if (q.startsWith("sum(collector_targets_reachable")) return Promise.resolve(scalar(11));
    if (q.startsWith("sum by (collector) (collector_targets_reachable")) {
      return Promise.resolve(byCollector([["snmpmetrics", 11]]));
    }
    if (q.startsWith("sum by (collector) (collector_targets)")) {
      return Promise.resolve(byCollector([["snmpmetrics", 12], ["gnmi", 0]]));
    }
    if (q.startsWith("max by (collector) (collector_poll_duration_ms")) {
      return Promise.resolve(byCollector([["snmpmetrics", 42]]));
    }
    return Promise.resolve(instant([]));
  });
  mocks.flowsByType.mockResolvedValue({ data: [{ flow_type: "netflow", flows: 90, exporters: 3 }] });
  mocks.searchLogs.mockResolvedValue({ hits: { total: { value: 7 } } });
});
afterEach(() => cleanup());

const collection = () => document.querySelector('[data-section="collection"]') as HTMLElement;

describe("Stack Health", () => {
  it("still shows the platform's own backends", async () => {
    render(<StackHealth />);
    expect(await screen.findByText("opensearch")).toBeInTheDocument();
    expect(screen.getByText("kafka")).toBeInTheDocument();
  });

  it("refuses the whole page — Collection included — when the api says 403", async () => {
    mocks.stackHealth.mockRejectedValue(new Error("403 forbidden"));
    render(<StackHealth />);
    expect(await screen.findByText(/platform administrators only/)).toBeInTheDocument();
    expect(collection()).toBeNull();
  });
});

describe("the Collection section", () => {
  it("carries the retired board's four counts", async () => {
    render(<StackHealth />);
    const sec = within(await waitFor(() => { const s = collection(); expect(s).not.toBeNull(); return s; }));
    expect(await sec.findByText("Monitored devices")).toBeInTheDocument();
    expect(sec.getByText("Reachable (SNMP)")).toBeInTheDocument();
    expect(sec.getByText("Flows (1h)")).toBeInTheDocument();
    expect(sec.getByText("Traps (1h)")).toBeInTheDocument();
    const stat = (label: string) =>
      sec.getByText(label).parentElement?.querySelector(".ds-stat-num")?.textContent;
    expect(stat("Monitored devices")).toBe("12");
    expect(stat("Reachable (SNMP)")).toBe("11");
    expect(stat("Flows (1h)")).toBe("90");
    expect(stat("Traps (1h)")).toBe("7");
  });

  it("lists one row per collector — what the four charts said, read now", async () => {
    render(<StackHealth />);
    const sec = within(await waitFor(() => collection() as HTMLElement));
    expect(await sec.findByText("snmpmetrics")).toBeInTheDocument();
    expect(sec.getByText("11 / 12 reachable")).toBeInTheDocument();
    expect(sec.getByText("42 ms")).toBeInTheDocument();
    // gnmi is configured with nothing and reached nothing: it has no poll time,
    // and "—" is the honest reading, not "0 ms".
    expect(sec.getByText("gnmi")).toBeInTheDocument();
    expect(sec.getByText("— / 0 reachable")).toBeInTheDocument();
    expect(sec.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("lists the flow sources with their exporter counts", async () => {
    render(<StackHealth />);
    const sec = within(await waitFor(() => collection() as HTMLElement));
    expect(await sec.findByText("NETFLOW")).toBeInTheDocument();
    expect(sec.getByText("3 exporters")).toBeInTheDocument();
  });

  it("says nothing arrived rather than showing an empty list", async () => {
    mocks.flowsByType.mockResolvedValue({ data: [] });
    mocks.metricsQuery.mockResolvedValue(instant([]));
    render(<StackHealth />);
    const sec = within(await waitFor(() => collection() as HTMLElement));
    expect(await sec.findByText("No collector reported.")).toBeInTheDocument();
    expect(sec.getByText("No flows in the last hour.")).toBeInTheDocument();
  });

  it("names what failed instead of rendering a blank section", async () => {
    mocks.flowsByType.mockRejectedValue(new Error("clickhouse unreachable"));
    render(<StackHealth />);
    const sec = within(await waitFor(() => collection() as HTMLElement));
    expect(await sec.findByText(/[Cc]lickhouse unreachable/)).toBeInTheDocument();
  });

  // The words the board spent teaching "reachable 0 with monitored above 0
  // points at the devices" are an authored explain file now.
  it("keeps the explanation behind the (i), not on the screen", async () => {
    render(<StackHealth />);
    const sec = within(await waitFor(() => collection() as HTMLElement));
    expect(sec.getByRole("button", { name: "Ask Iris about Reachable versus monitored" })).toBeInTheDocument();
    expect(await sec.findByRole("button", { name: "Ask Iris about Exported versus indexed flows" }))
      .toBeInTheDocument();
    expect(sec.queryByText(/points at the devices/)).toBeNull();
  });
});
