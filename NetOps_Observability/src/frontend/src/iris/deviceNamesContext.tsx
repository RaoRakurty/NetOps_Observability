// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// deviceNamesContext — how an Iris answer names devices (owner, 2026-11-23:
// "keep the hostname as it is; internal ids stay internal, never shown").
//
// The rows, series and provenance an answer carries name a device by its
// internal id (`<sysName>-<address hash>`) or an interface by `<id>:<if>`.
// PresentationPlanRenderer reads the caller's own inventory once
// (lib/deviceNames useDeviceLabels — tenant-scoped /api/devices) and provides
// it here; every component under it turns a displayed value into the name with
// nameDevicesIn — an exact known id only, never a suffix stripped by pattern.
// The raw values stay in the data: links, drill-downs and queries keep the id.
// Outside a provider (or before the inventory loads, or when it fails) the map
// is null and the value is shown as it is.

import { createContext, useContext } from "react";
import { nameDevicesIn, type DeviceNames } from "../lib/deviceNames";

export const IrisDeviceNamesContext = createContext<DeviceNames | null>(null);

/** The id/address → name map of the answer being shown, or null. */
export function useIrisDeviceNames(): DeviceNames | null {
  return useContext(IrisDeviceNamesContext);
}

/** The naming function for presentation.entityLabel; undefined without names. */
export function namer(names: DeviceNames | null | undefined): ((v: string) => string) | undefined {
  if (!names || names.size === 0) return undefined;
  return (v: string) => nameDevicesIn(v, names);
}

/** A displayed value with every known device id in it named. */
export function named(text: string, names: DeviceNames | null | undefined): string;
export function named(text: string | null, names: DeviceNames | null | undefined): string | null;
export function named(text: string | null, names: DeviceNames | null | undefined): string | null {
  if (text === null) return null;
  return nameDevicesIn(text, names);
}
