// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The device's serial number and where it came from, for the inventory list
// and the device page. The DEVICE's own answer (serial_number) wins; an
// importer's or a controller's serial (labels.serial) is shown only when the
// device has not reported one, and the tooltip always says which it is — the
// two are different claims (models.Device.SerialNumber).

import type { Device } from "../../services/api";

export type SerialView = { serial: string; from: string };

const CONTROLLER: Record<string, string> = { vmanage: "vManage" };

export function deviceSerial(d: Pick<Device, "serial_number" | "serial_source" | "labels">): SerialView | null {
  const own = (d.serial_number || "").trim();
  if (own) {
    switch (d.serial_source) {
      case "snmp": return { serial: own, from: "Read from the device over SNMP" };
      case "ssh": return { serial: own, from: "Read from the device's command line" };
      case "gnmi": return { serial: own, from: "Read from the device over gNMI" };
      default: return { serial: own, from: "Entered or imported" };
    }
  }
  const label = (d.labels?.serial || "").trim();
  if (!label) return null;
  const sys = (d.labels?.source_system || "").trim().toLowerCase();
  return { serial: label, from: sys ? `Reported by ${CONTROLLER[sys] ?? sys}` : "From the source of truth" };
}
