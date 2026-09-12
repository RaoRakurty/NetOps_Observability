// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// healthCells.test.tsx — the owner's finding: a CRITICAL Azure
// cloud_resource_health "down" row rendered EMPTY metric / baseline / current.
//
// Acceptance (both directions, because the fix must not cost the other kind):
//   · a STATE event renders its declared state + the provider's reason — never a
//     blank triplet;
//   · a METRIC ANOMALY still renders its metric / current / baseline exactly as
//     before.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import {
  healthMetricCell, healthCurrentCell, healthBaselineCell, healthReasonCell,
} from "./healthCells";
import type { HealthSignal } from "./types";

afterEach(cleanup);

// the real shape the Azure Resource Health poller emits: no metric_name, no
// value, no baseline — a declared state plus reasonType (cloud-ingest/azure.py).
const stateEvent: HealthSignal = {
  time: "2026-07-15T10:00:00.000Z", app: "correlix-demoapp", resource: "vm-web-1",
  signal: "cloud_resource_health", state: "down",
  metric: "—", current: "—", baseline: "—",
  severity: "critical", source: "azure", reason: "Customer Initiated",
};

const metricAnomaly: HealthSignal = {
  time: "2026-07-15T10:00:00.000Z", app: "billing", resource: "i-abc",
  signal: "cloud_health", state: "degraded",
  metric: "CPUUtilization", current: "94%", baseline: "31%",
  severity: "warning", source: "aws", reason: "",
};

describe("a provider STATE event", () => {
  it("renders the declared state instead of an empty value cell", () => {
    render(<>{healthCurrentCell(stateEvent)}</>);
    expect(screen.getByText("Down")).toBeTruthy();
  });

  it("renders the provider's reason instead of an empty cell", () => {
    render(<>{healthReasonCell(stateEvent)}</>);
    expect(screen.getByText("Customer Initiated")).toBeTruthy();
  });

  it("says the row has no measurement rather than showing a blank metric", () => {
    render(<>{healthMetricCell(stateEvent)}</>);
    const cell = screen.getByText("state change");
    expect(cell.getAttribute("title")).toMatch(/reports a state, not a measurement/i);
  });

  it("explains that a declared state has no baseline", () => {
    render(<>{healthBaselineCell(stateEvent)}</>);
    expect(screen.getByText("—").getAttribute("title")).toMatch(/no baseline/i);
  });

  it("is honest when the provider declared a state with no reason", () => {
    render(<>{healthReasonCell({ ...stateEvent, reason: "" })}</>);
    expect(screen.getByText("no reason stated")).toBeTruthy();
  });

  it("never leaves the whole metric/current/reason triplet blank", () => {
    const { container } = render(<>
      {healthMetricCell(stateEvent)}{healthCurrentCell(stateEvent)}{healthReasonCell(stateEvent)}
    </>);
    expect(container.textContent).toBe("state changeDownCustomer Initiated");
  });
});

describe("a METRIC anomaly is unchanged", () => {
  it("still renders its metric name", () => {
    render(<>{healthMetricCell(metricAnomaly)}</>);
    expect(screen.getByText("CPUUtilization")).toBeTruthy();
  });

  it("still renders its current reading and baseline", () => {
    render(<>{healthCurrentCell(metricAnomaly)}{healthBaselineCell(metricAnomaly)}</>);
    expect(screen.getByText("94%")).toBeTruthy();
    expect(screen.getByText("31%")).toBeTruthy();
  });

  it("shows no reason — a measured anomaly has no provider reasonType", () => {
    const { container } = render(<>{healthReasonCell(metricAnomaly)}</>);
    expect(container.textContent).toBe("—");
    // and it must NOT borrow the state-event's "no reason stated" wording
    expect(screen.queryByText("no reason stated")).toBeNull();
  });
});
