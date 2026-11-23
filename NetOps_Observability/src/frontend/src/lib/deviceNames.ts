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

/** id, address or name → display name, for evidence that names a device by its
 *  management address (an engine interface key `10.0.0.1:if3`) rather than its id.
 *  An address two devices share names nobody. */
export function buildDeviceLabels(devices: readonly Device[]): DeviceNames {
  const names = buildDeviceNames(devices);
  const out = new Map<string, string>(names);
  const addrCount = new Map<string, number>();
  for (const d of devices) {
    const a = (d.address || "").trim();
    if (a) addrCount.set(a, (addrCount.get(a) ?? 0) + 1);
  }
  for (const d of devices) {
    const a = (d.address || "").trim();
    const n = d.id ? names.get(d.id) : undefined;
    if (a && n && addrCount.get(a) === 1 && !out.has(a)) out.set(a, n);
  }
  return out;
}

/** The display name for a metric's device id; the id itself when unknown. */
export function deviceDisplayName(id: string | undefined, names: DeviceNames | null): string {
  if (!id) return "";
  return names?.get(id) ?? id;
}

const ID_RUNE = /[A-Za-z0-9._-]/;

/** Swap every WHOLE-TOKEN occurrence of a device id in operator text (an alert
 *  summary, an incident title stored before the engine named devices) for the
 *  name. Only the exact id the record carries is swapped, and only for a name
 *  inventory gave — never a suffix stripped by pattern (a real hostname can end
 *  in hex). "pe1-0a0b if3 down" → "pe1 if3 down"; "pe1-0a0bc" is left alone.
 *  Owner, 2026-11-23: the internal id stays internal. */
export function nameDeviceIn(text: string, id: string | undefined, name: string | undefined): string {
  if (!text || !id || !name || name === id || !text.includes(id)) return text;
  let out = "";
  let rest = text;
  for (;;) {
    const i = rest.indexOf(id);
    if (i < 0) return out + rest;
    const end = i + id.length;
    const before = i === 0 || !ID_RUNE.test(rest[i - 1]);
    const after = end === rest.length || !ID_RUNE.test(rest[end]);
    out += rest.slice(0, i) + (before && after ? name : id);
    rest = rest.slice(end);
  }
}

/** One shared, short-lived read of the caller's inventory. A failed read is not
 *  cached, so the next caller tries again. */
export function loadDeviceNames(now: number = Date.now()): Promise<DeviceNames> {
  if (cached && now - cached.at < TTL_MS) return cached.names;
  // Started inside a promise: any failure, even a synchronous one, leaves the
  // raw ids on screen and never breaks the page that asked.
  const names = Promise.resolve().then(() => api.devices()).then((d) => buildDeviceNames(d ?? []));
  cached = { at: now, names };
  names.catch(() => { cached = null; });
  return names;
}

/** Test seam: forget the cached inventory. */
export function resetDeviceNamesForTest(): void {
  cached = null;
  cachedLabels = null;
  cachedPlaces = null;
}

let cachedLabels: { at: number; labels: Promise<DeviceNames> } | null = null;

/** Shared short-lived read for buildDeviceLabels; a failed read is not cached. */
export function loadDeviceLabels(now: number = Date.now()): Promise<DeviceNames> {
  if (cachedLabels && now - cachedLabels.at < TTL_MS) return cachedLabels.labels;
  // Started inside a promise: any failure, even a synchronous one, leaves the
  // raw keys on screen and never breaks the page that asked.
  const labels = Promise.resolve().then(() => api.devices()).then((d) => buildDeviceLabels(d ?? []));
  cachedLabels = { at: now, labels };
  labels.catch(() => { cachedLabels = null; });
  return labels;
}

/** React hook: the id/address→name map, or null until it has loaded. */
export function useDeviceLabels(): DeviceNames | null {
  const [labels, setLabels] = useState<DeviceNames | null>(null);
  useEffect(() => {
    let alive = true;
    loadDeviceLabels().then((n) => { if (alive) setLabels(n); }).catch(() => { /* raw keys stay */ });
    return () => { alive = false; };
  }, []);
  return labels;
}

/** Where a device is: its display name and its site. */
export type DevicePlace = { name: string; site: string };
export type DevicePlaces = ReadonlyMap<string, DevicePlace>;

/** The site an operator reads for a device: the operator's own site label
 *  first, then a location label, then the site id the device or its controller
 *  reports ("site-id 100"), else "". Never invented. */
export function deviceSite(d: Pick<Device, "labels" | "reported_site_id">): string {
  const op = (d.labels?.site || d.labels?.location || "").trim();
  if (op) return op;
  const rep = (d.reported_site_id || "").trim();
  return rep ? `site-id ${rep}` : "";
}

/** id → {name, site}, names told apart exactly as buildDeviceNames does. */
export function buildDevicePlaces(devices: readonly Device[]): DevicePlaces {
  const names = buildDeviceNames(devices);
  const out = new Map<string, DevicePlace>();
  for (const d of devices) {
    if (!d.id) continue;
    out.set(d.id, { name: names.get(d.id) ?? d.id, site: deviceSite(d) });
  }
  return out;
}

let cachedPlaces: { at: number; places: Promise<DevicePlaces> } | null = null;

/** Shared short-lived read for buildDevicePlaces; a failed read is not cached. */
export function loadDevicePlaces(now: number = Date.now()): Promise<DevicePlaces> {
  if (cachedPlaces && now - cachedPlaces.at < TTL_MS) return cachedPlaces.places;
  const places = Promise.resolve().then(() => api.devices()).then((d) => buildDevicePlaces(d ?? []));
  cachedPlaces = { at: now, places };
  places.catch(() => { cachedPlaces = null; });
  return places;
}

/** React hook: the id→{name, site} map, or null until it has loaded. A failed
 *  read leaves raw ids on screen and never breaks the page. */
export function useDevicePlaces(): DevicePlaces | null {
  const [places, setPlaces] = useState<DevicePlaces | null>(null);
  useEffect(() => {
    let alive = true;
    loadDevicePlaces().then((p) => { if (alive) setPlaces(p); }).catch(() => { /* raw ids stay */ });
    return () => { alive = false; };
  }, []);
  return places;
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
