// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// viewContext.test.ts — N-E4: what is in view rides along with every Iris ask,
// under any explicit context, ids only, shapes checked (the server re-checks).

import { describe, it, expect, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import {
  currentIrisView, resetIrisViewForTest, setIrisView, useIrisView, validView,
  viewChipLabel, viewContextKeys, withViewContext,
} from "./viewContext";

const CORR = "3e0400bc-aa22-543b-95e4-1b6afa9cf75e";

beforeEach(() => resetIrisViewForTest());

describe("shapes", () => {
  it("accepts a UUID incident and a hostname-shaped device", () => {
    expect(validView({ kind: "incident", id: CORR, label: "P-3e04" })).not.toBeNull();
    expect(validView({ kind: "device", id: "cEdge-80", label: "cEdge-80" })).not.toBeNull();
  });
  it("refuses junk ids", () => {
    expect(validView({ kind: "incident", id: "not-a-uuid", label: "x" })).toBeNull();
    expect(validView({ kind: "device", id: "a b<script>", label: "x" })).toBeNull();
    expect(validView({ kind: "device", id: "x".repeat(200), label: "x" })).toBeNull();
  });
});

describe("withViewContext", () => {
  it("adds the incident in view as correlation_id", () => {
    setIrisView({ kind: "incident", id: CORR, label: "P-3e04" });
    expect(withViewContext(undefined)).toEqual({ correlation_id: CORR });
  });
  it("adds the device in view as device_id, never its label", () => {
    setIrisView({ kind: "device", id: "dev-1", label: "cEdge-80 (Dallas)" });
    const ctx = withViewContext({ route: "devices/inventory" });
    expect(ctx).toEqual({ device_id: "dev-1", route: "devices/inventory" });
    expect(JSON.stringify(ctx)).not.toContain("Dallas");
  });
  it("never overrides an explicit subject or topic", () => {
    setIrisView({ kind: "device", id: "dev-1", label: "x" });
    expect(withViewContext({ correlation_id: CORR })).toEqual({ correlation_id: CORR });
    expect(withViewContext({ topic: "kpi.mttr" })).toEqual({ device_id: "dev-1", topic: "kpi.mttr" });
  });
  it("adds nothing when nothing is in view", () => {
    expect(withViewContext({ route: "x/y" })).toEqual({ route: "x/y" });
    expect(viewContextKeys(null)).toEqual({});
  });
});

describe("useIrisView", () => {
  it("registers while mounted and clears on unmount", () => {
    const { unmount } = renderHook(() => useIrisView({ kind: "device", id: "dev-1", label: "edge-1" }));
    expect(currentIrisView()?.id).toBe("dev-1");
    unmount();
    expect(currentIrisView()).toBeNull();
  });
  it("does not clear a view another page set over it", () => {
    const first = renderHook(() => useIrisView({ kind: "device", id: "dev-1", label: "edge-1" }));
    const second = renderHook(() => useIrisView({ kind: "incident", id: CORR, label: "P-3e04" }));
    first.unmount();
    expect(currentIrisView()?.id).toBe(CORR);
    second.unmount();
    expect(currentIrisView()).toBeNull();
  });
});

describe("chip", () => {
  it("names the kind and the label", () => {
    expect(viewChipLabel({ kind: "device", id: "dev-1", label: "edge-1" })).toBe("Device · edge-1");
    expect(viewChipLabel({ kind: "incident", id: CORR, label: "P-3e04" })).toBe("Incident · P-3e04");
    expect(viewChipLabel(null)).toBeUndefined();
  });
});
