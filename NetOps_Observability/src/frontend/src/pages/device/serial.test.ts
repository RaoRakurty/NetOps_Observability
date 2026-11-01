// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix
import { describe, it, expect } from "vitest";
import { deviceSerial } from "./serial";

describe("deviceSerial", () => {
  it("prefers the device's own serial and says how it was read", () => {
    expect(deviceSerial({ serial_number: "FOC2130Z0RD", serial_source: "snmp", labels: { serial: "ASSET-9" } }))
      .toEqual({ serial: "FOC2130Z0RD", from: "Read from the device over SNMP" });
    expect(deviceSerial({ serial_number: "JN11", serial_source: "ssh" })?.from).toBe("Read from the device's command line");
  });
  it("treats an unlabelled serial as entered or imported, never as probed", () => {
    expect(deviceSerial({ serial_number: "X1", serial_source: "" })?.from).toBe("Entered or imported");
  });
  it("falls back to a controller's or the source of truth's serial, naming it", () => {
    expect(deviceSerial({ labels: { serial: "SSI123", source_system: "vmanage" } }))
      .toEqual({ serial: "SSI123", from: "Reported by vManage" });
    expect(deviceSerial({ labels: { serial: "NB-1" } })?.from).toBe("From the source of truth");
  });
  it("is null when nothing reports one", () => {
    expect(deviceSerial({ labels: {} })).toBeNull();
    expect(deviceSerial({ serial_number: "  " })).toBeNull();
  });
});
