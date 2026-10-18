// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it, vi, beforeEach } from "vitest";
import { buildDeviceNames, deviceDisplayName, loadDeviceNames, resetDeviceNamesForTest } from "./deviceNames";
import { seriesLabel } from "../components/board/panels";
import { api, type Device } from "../services/api";

const dev = (id: string, name: string, address = ""): Device => ({ id, name, address, source: "snmp", last_seen: "" }) as Device;

describe("device display names (owner 2026-10-18: no '<name>-<random id>' in charts)", () => {
  it("shows the inventory name for a metric's device id", () => {
    const n = buildDeviceNames([dev("cedge-40-b99e47eb", "cedge-40")]);
    expect(deviceDisplayName("cedge-40-b99e47eb", n)).toBe("cedge-40");
  });

  it("tells two devices with the same name apart by address", () => {
    const n = buildDeviceNames([dev("edge-1-aaaa0001", "edge-1", "10.0.0.1"), dev("edge-1-bbbb0002", "edge-1", "10.0.0.2")]);
    expect(deviceDisplayName("edge-1-aaaa0001", n)).toBe("edge-1 (10.0.0.1)");
    expect(deviceDisplayName("edge-1-bbbb0002", n)).toBe("edge-1 (10.0.0.2)");
  });

  it("falls back to the id for a device the caller cannot see, and never strips by pattern", () => {
    const n = buildDeviceNames([dev("core-a1b2c3d4", "core-a1b2c3d4")]);
    expect(deviceDisplayName("unknown-12345678", n)).toBe("unknown-12345678");
    expect(deviceDisplayName("core-a1b2c3d4", n)).toBe("core-a1b2c3d4"); // a real name that ends in hex stays whole
    expect(deviceDisplayName("x-1", null)).toBe("x-1");
  });

  it("labels chart series by name — with and without explicit label keys", () => {
    const n = buildDeviceNames([dev("cedge-40-b99e47eb", "cedge-40")]);
    const s = { metric: { device: "cedge-40-b99e47eb", ifName: "Gi1" }, values: [] };
    expect(seriesLabel(s, ["device", "ifName"], n)).toBe("cedge-40 · Gi1");
    expect(seriesLabel(s, undefined, n)).toBe("cedge-40 · Gi1");
    expect(seriesLabel(s, ["device", "ifName"])).toBe("cedge-40-b99e47eb · Gi1"); // before names load
  });

  describe("loading", () => {
    beforeEach(() => resetDeviceNamesForTest());
    it("reads inventory once within the cache window and retries after a failure", async () => {
      const spy = vi.spyOn(api, "devices").mockRejectedValueOnce(new Error("502")).mockResolvedValue([dev("a-1", "a")]);
      await expect(loadDeviceNames(1000)).rejects.toThrow();
      const n = await loadDeviceNames(2000);
      await loadDeviceNames(3000);
      expect(n.get("a-1")).toBe("a");
      expect(spy).toHaveBeenCalledTimes(2);
      spy.mockRestore();
    });
  });
});
