// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it, vi, beforeEach } from "vitest";
import { buildDeviceLabels, buildDeviceNames, deviceDisplayName, loadDeviceNames, nameDeviceIn, resetDeviceNamesForTest } from "./deviceNames";
import { seriesLabel as boardSeriesLabel } from "../pages/panels";
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

describe("buildDeviceLabels — a device named by its management address", () => {
  it("resolves an id and a unique address to the device's name", () => {
    const l = buildDeviceLabels([dev("vedge-20-02efdcad", "vEdge-20", "192.168.222.103"), dev("cedge-81-dde8d64d", "cEDGE-81", "192.168.222.107")]);
    expect(l.get("vedge-20-02efdcad")).toBe("vEdge-20");
    expect(l.get("192.168.222.103")).toBe("vEdge-20");
    expect(l.get("192.168.222.107")).toBe("cEDGE-81");
  });

  it("an address two devices share names nobody", () => {
    const l = buildDeviceLabels([dev("a", "A", "10.0.0.1"), dev("b", "B", "10.0.0.1")]);
    expect(l.get("10.0.0.1")).toBeUndefined();
    expect(l.get("a")).toBe("A");
  });
});

describe("the internal device id never reaches operator text (owner 2026-11-23)", () => {
  it("swaps the exact id token for the name, wherever it stands", () => {
    expect(nameDeviceIn("cedge-40-fdf7b64f if9 inbound traffic anomaly (z>3)", "cedge-40-fdf7b64f", "cEDGE-40"))
      .toBe("cEDGE-40 if9 inbound traffic anomaly (z>3)");
    expect(nameDeviceIn("BGP down on pe1-0a0b (peer 10.0.0.2); pe1-0a0b isolated", "pe1-0a0b", "pe1"))
      .toBe("BGP down on pe1 (peer 10.0.0.2); pe1 isolated");
  });

  it("never touches a longer token that merely contains the id, and never strips by pattern", () => {
    expect(nameDeviceIn("pe1-0a0bc down", "pe1-0a0b", "pe1")).toBe("pe1-0a0bc down");
    expect(nameDeviceIn("x.pe1-0a0b down", "pe1-0a0b", "pe1")).toBe("x.pe1-0a0b down");
    // A real hostname that ends in hex is left alone when it is not the id.
    expect(nameDeviceIn("edge-cafe01 down", "edge-cafe01-1a2b", "edge-cafe01")).toBe("edge-cafe01 down");
  });

  it("no id, no name, or name === id leaves the text as it is", () => {
    expect(nameDeviceIn("a-1 down", undefined, "a")).toBe("a-1 down");
    expect(nameDeviceIn("a-1 down", "a-1", undefined)).toBe("a-1 down");
    expect(nameDeviceIn("a-1 down", "a-1", "a-1")).toBe("a-1 down");
    expect(nameDeviceIn("", "a-1", "a")).toBe("");
  });

  it("board panel series labels read the hostname once inventory has loaded", () => {
    const n = buildDeviceNames([dev("cedge-40-b99e47eb", "cEDGE-40")]);
    expect(boardSeriesLabel({ device: "cedge-40-b99e47eb", ifName: "Gi1" }, n)).toBe("cEDGE-40·Gi1");
    expect(boardSeriesLabel({ device: "cedge-40-b99e47eb", index: "3" }, n)).toBe("cEDGE-40·3");
    expect(boardSeriesLabel({ device: "cedge-40-b99e47eb" }, n)).toBe("cEDGE-40");
    expect(boardSeriesLabel({ device: "cedge-40-b99e47eb" })).toBe("cedge-40-b99e47eb"); // before names load
  });
});
