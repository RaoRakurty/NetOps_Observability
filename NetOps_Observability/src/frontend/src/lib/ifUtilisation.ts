// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ifUtilisation — the ONE place the interface throughput and utilisation
// queries are written (Flows page redesign P1, 2026-11-12). Device Monitoring,
// Interface Performance and the Flows page used to each spell the same
// PromQL inline; three copies drift. Every query here reads the SNMP interface
// counters the collectors already store (device_if_* with labels device =
// device id, index = ifIndex, ifName), and device_if_speed is ifHighSpeed in
// Mbps — hence the * 1000000.
//
// Utilisation only exists where the speed is known: `device_if_speed > 0`
// drops every interface with no reported speed, so a missing speed is an
// absent series, never a 0 % or a divide-by-zero infinity.

import { sanitizeLabel } from "../components/board/panels";

export type IfDirection = "in" | "out";

/** Interface throughput in bits per second, per series. */
export function ifRateBps(sel: string, dir: IfDirection): string {
  return `rate(device_if_${dir}_octets${sel}[5m]) * 8`;
}

/** Interface utilisation in percent of the reported speed, per series. */
export function ifUtilPct(sel: string, dir: IfDirection): string {
  return `${ifRateBps(sel, dir)} * 100 / ((device_if_speed${sel} > 0) * 1000000)`;
}

/** The reported interface speed in bits per second (absent when unknown). */
export function ifSpeedBps(sel: string): string {
  return `(device_if_speed${sel} > 0) * 1000000`;
}

/**
 * A selector matching any of the given device ids exactly. Ids are sanitised
 * like every interpolated label value, then their regex metacharacters escaped
 * (only "." survives the sanitiser), so `edge.1` cannot match `edgex1`.
 * Returns "" for no ids — callers must not run a fleet-wide query by accident,
 * so they check for "" first.
 */
export function deviceAnySelector(ids: readonly string[]): string {
  const alts = [...new Set(ids.map((id) => sanitizeLabel(id).trim()).filter(Boolean))].map((id) => id.replace(/\./g, "\\\\."));
  return alts.length ? `{device=~"${alts.join("|")}"}` : "";
}

/**
 * A per-series aggregate of an expression over the trailing window, as an
 * instant query: avg or max of the 5-minute rate across the window. The
 * subquery step keeps the point count bounded (≈ 288) at any window length.
 */
export function overWindow(fn: "avg" | "max", expr: string, windowSeconds: number): string {
  const w = Math.max(300, Math.round(windowSeconds));
  const step = Math.max(300, Math.round(w / 288));
  return `${fn}_over_time((${expr})[${w}s:${step}s])`;
}
