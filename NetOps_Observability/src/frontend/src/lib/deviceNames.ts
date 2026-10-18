// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// deviceNames — the ONE way a metric's `device` label becomes something an
// operator reads.
//
// The `device` label on every collected series is the device ID, which is
// `<sysName>-<address hash>` (internal/discovery ScanDeviceID): sysNames repeat
// across sites and tenants, so the hash keeps two "edge-1"s apart. Charts used
// to print that id raw ("cedge-40-b99e47eb"). The name comes from inventory —
// never from stripping a suffix with a regex: a real hostname can end in hex.
//
// Inventory is read through the caller's own tenant-scoped /api/devices, so a
// name can only ever come from a device the caller may already see; an id with
// no visible device falls back to the id itself.

import { useEffect, useState } from "react";
import { api, type Device } from "../services/api";

export type DeviceNames = ReadonlyMap<string, string>;

const TTL_MS = 60_000;
let cached: { at: number; names: Promise<DeviceNames> } | null = null;

/** id → display name. Two visible devices with the same name are told apart by
 *  their address ("edge-1 (10.0.0.1)"); a device with no name shows its id. */
export function buildDeviceNames(devices: readonly Device[]): DeviceNames {
  const count = new Map<string, number>();
  for (const d of devices) {
    const n = (d.name || "").trim();
    if (n) count.set(n, (count.get(n) ?? 0) + 1);
  }
  const out = new Map<string, string>();
  for (const d of devices) {
    const n = (d.name || "").trim();
    if (!d.id) continue;
    if (!n) out.set(d.id, d.id);
    else if ((count.get(n) ?? 0) > 1 && d.address) out.set(d.id, `${n} (${d.address})`);
    else out.set(d.id, n);
  }
  return out;
}

/** The display name for a metric's device id; the id itself when unknown. */
export function deviceDisplayName(id: string | undefined, names: DeviceNames | null): string {
  if (!id) return "";
  return names?.get(id) ?? id;
}

/** One shared, short-lived read of the caller's inventory. A failed read is not
 *  cached, so the next caller tries again. */
export function loadDeviceNames(now: number = Date.now()): Promise<DeviceNames> {
  if (cached && now - cached.at < TTL_MS) return cached.names;
  const names = api.devices().then((d) => buildDeviceNames(d ?? []));
  cached = { at: now, names };
  names.catch(() => { cached = null; });
  return names;
}

/** Test seam: forget the cached inventory. */
export function resetDeviceNamesForTest(): void {
  cached = null;
}

/** React hook: the id→name map, or null until it has loaded. */
export function useDeviceNames(): DeviceNames | null {
  const [names, setNames] = useState<DeviceNames | null>(null);
  useEffect(() => {
    let alive = true;
    loadDeviceNames().then((n) => { if (alive) setNames(n); }).catch(() => { /* ids stay as-is */ });
    return () => { alive = false; };
  }, []);
  return names;
}
