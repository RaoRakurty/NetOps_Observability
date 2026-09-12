// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import {
  EMPTY_MONITOR_DRAFT, describeMonitor, draftToInput, monitorStateLabel,
  monitorStateTone, rowToInput, validateMonitorDraft,
} from "./monitors";
import type { CloudMonitorRow } from "../../services/api";

const draft = (over: Partial<typeof EMPTY_MONITOR_DRAFT> = {}) =>
  ({ ...EMPTY_MONITOR_DRAFT, name: "High CPU", threshold: "90", ...over });

describe("validateMonitorDraft", () => {
  it("accepts a sound threshold draft and a thresholdless anomaly draft", () => {
    expect(validateMonitorDraft(draft())).toBe("");
    expect(validateMonitorDraft(draft({ mode: "anomaly", threshold: "" }))).toBe("");
  });
  it("mirrors the backend refusals", () => {
    expect(validateMonitorDraft(draft({ name: " " }))).not.toBe("");
    expect(validateMonitorDraft(draft({ name: "x".repeat(81) }))).not.toBe("");
    expect(validateMonitorDraft(draft({ metric: "up" }))).not.toBe("");
    expect(validateMonitorDraft(draft({ threshold: "" }))).not.toBe("");
    expect(validateMonitorDraft(draft({ threshold: "abc" }))).not.toBe("");
  });
});

describe("draftToInput / rowToInput", () => {
  it("threshold draft keeps condition+threshold; anomaly strips both", () => {
    expect(draftToInput(draft())).toEqual({
      name: "High CPU", metric: "cloud_cpu_util", mode: "threshold",
      enabled: true, condition: "above", threshold: 90,
    });
    const a = draftToInput(draft({ mode: "anomaly" }));
    expect(a.condition).toBeUndefined();
    expect(a.threshold).toBeUndefined();
  });
  it("keeps an explicit resource scope, drops a blank one", () => {
    expect(draftToInput(draft({ resourceId: " i-1 " })).resource_id).toBe("i-1");
    expect(draftToInput(draft()).resource_id).toBeUndefined();
  });
  it("rowToInput round-trips a row for enable/disable", () => {
    const row: CloudMonitorRow = {
      id: "1", tenant_id: "t", name: "n", metric: "cloud_cpu_util",
      mode: "threshold", condition: "below", threshold: 5, enabled: true,
      last_state: "ok",
    };
    expect(rowToInput(row, false)).toEqual({
      name: "n", metric: "cloud_cpu_util", mode: "threshold",
      condition: "below", threshold: 5, enabled: false,
    });
  });
});

describe("describeMonitor", () => {
  const base: CloudMonitorRow = {
    id: "1", tenant_id: "t", name: "n", metric: "cloud_cpu_util",
    mode: "threshold", condition: "above", threshold: 90, enabled: true,
    last_state: "never_evaluated",
  };
  it("speaks the metric label and scope", () => {
    expect(describeMonitor(base)).toBe("CPU utilization on every cloud resource — alert when above 90");
    expect(describeMonitor({ ...base, resource_id: "i-9", mode: "anomaly" }))
      .toMatch(/CPU utilization on i-9 — alert on deviation/);
  });
});

describe("monitor state display", () => {
  it("never renders an absent verdict as ok", () => {
    expect(monitorStateLabel("never_evaluated")).toBe("never evaluated");
    expect(monitorStateLabel("no_data")).toBe("no data");
    expect(monitorStateTone("never_evaluated")).not.toBe("var(--ok)");
    expect(monitorStateTone("no_data")).not.toBe("var(--ok)");
    expect(monitorStateTone("firing")).toBe("var(--crit)");
    expect(monitorStateTone("ok")).toBe("var(--ok)");
  });
});
