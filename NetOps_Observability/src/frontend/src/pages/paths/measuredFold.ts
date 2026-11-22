// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// measuredFold.ts — the prober's measured paths (GET /api/probe/paths, with the
// path health of GET /api/paths/health) attached to the rows of Investigate →
// Paths. Until 2026-11-22 they had a tab of their own ("Measured paths") that
// only said whether a path was measured, apart from the circuit or tunnel it
// measured. Now each WAN circuit and tunnel row carries its own path, and the
// paths no row claims are listed apart under each tab. Pure: every rule here is
// unit-tested.
//
// HOW A PATH FINDS ITS ROW. A path is keyed by its destination address. The
// prober's targets are the workspace's own devices (the setup steps offer each
// branch edge's management address) and its own catalogue entries, so:
//   * a WAN circuit row claims a path to its measurement TARGET (the peer, the
//     ISP next-hop or the anchor: the address its SLA columns are measured to)
//     and a path to its ROUTER;
//   * a tunnel row claims a path to the device at either END.
// A destination becomes a device only through the caller's own inventory (the
// tenant-scoped /api/devices), matched on the exact address, never on a guess.
// Two visible devices with the same address name nobody.
//
// HONESTY. A path that never reached its target says so first; then loss that
// lasts to the end of the path (the first-loss rule of probePathView.ts); then a
// changed route; then the path-health verdict against the path's own baseline.
// A path with nothing wrong reads "Reached". No path reads as a dash, never as
// healthy.

import type { Device, PathHealthItem, ProbePath } from "../../services/api";
import { firstLossIndex } from "./probePathView";

/** What is wrong with a measured path, worst first. */
export type PathVerdict = "unreached" | "loss" | "changed" | "degraded" | "ok";

const VERDICT_ORDER: Record<PathVerdict, number> = { unreached: 0, loss: 1, changed: 2, degraded: 3, ok: 4 };

export interface MeasuredPath {
  /** Stable per path: vantage, destination and method. */
  key: string;
  path: ProbePath;
  /** The destination host (no port, no brackets, lower case). */
  dst: string;
  /** The inventory device at the destination, when exactly one visible device has that address. */
  device?: string;
  /** The path's health against its own baseline, when the resolver has one. */
  health?: PathHealthItem;
  verdict: PathVerdict;
  /** Index into path.hops of the first-loss hop; -1 when there is none. */
  firstLoss: number;
}

export interface MeasuredIndex {
  all: MeasuredPath[];
  byDst: ReadonlyMap<string, MeasuredPath[]>;
  /** Keyed by lower-case device name. */
  byDevice: ReadonlyMap<string, MeasuredPath[]>;
}

/** Where a row's path goes, in the operator's words. */
export interface AttachedPath {
  m: MeasuredPath;
  /** Where it goes relative to its row; "other" for a path no row claims. */
  role: "target" | "router" | "end-a" | "end-b" | "other";
}

/** "10.0.0.1:443" / "[2001:db8::1]:443" / " 10.0.0.1 " → the bare, lower-case host. */
export function hostOf(addr: string | null | undefined): string {
  let s = (addr ?? "").trim().toLowerCase();
  if (!s) return "";
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    return close > 0 ? s.slice(1, close) : s.slice(1);
  }
  // One colon is host:port; more than one is a bare IPv6 address.
  const first = s.indexOf(":");
  if (first >= 0 && first === s.lastIndexOf(":")) s = s.slice(0, first);
  return s;
}

const nameKey = (n: string | null | undefined): string => (n ?? "").trim().toLowerCase();

/** The verdict of one measured path (see the file comment for the order). */
export function verdictOf(p: ProbePath, health?: PathHealthItem): PathVerdict {
  if (!p.reached) return "unreached";
  if (firstLossIndex(p) >= 0) return "loss";
  if (p.changed) return "changed";
  if (health && (health.health_state === "degraded" || health.health_state === "severe")) return "degraded";
  return "ok";
}

export function pathKey(p: ProbePath): string {
  return `${p.vantage_id ?? ""}|${hostOf(p.dst)}|${p.method ?? ""}`;
}

function push<K>(m: Map<K, MeasuredPath[]>, k: K, v: MeasuredPath): void {
  const list = m.get(k);
  if (list) list.push(v);
  else m.set(k, [v]);
}

/**
 * Index the paths by destination and by the inventory device at it. `devices`
 * and `health` may be empty (a read that failed): the paths are still indexed by
 * destination, and a path with no health is judged on its trace alone.
 */
export function buildMeasuredIndex(
  paths: readonly ProbePath[] | null | undefined,
  health: readonly PathHealthItem[] | null | undefined,
  devices: readonly Device[] | null | undefined,
): MeasuredIndex {
  const healthByDst = new Map<string, PathHealthItem>();
  for (const h of Array.isArray(health) ? health : []) {
    const k = hostOf(h.dst);
    if (k && !healthByDst.has(k)) healthByDst.set(k, h);
  }
  // address → device name; an address two visible devices share names nobody.
  const nameByAddr = new Map<string, string | null>();
  for (const d of Array.isArray(devices) ? devices : []) {
    const a = hostOf(d.address);
    const n = (d.name || d.id || "").trim();
    if (!a || !n) continue;
    const have = nameByAddr.get(a);
    nameByAddr.set(a, have === undefined || have === n ? n : null);
  }
  const all: MeasuredPath[] = [];
  const byDst = new Map<string, MeasuredPath[]>();
  const byDevice = new Map<string, MeasuredPath[]>();
  const seen = new Set<string>();
  for (const p of Array.isArray(paths) ? paths : []) {
    if (!p || !p.dst) continue;
    const key = pathKey(p);
    if (seen.has(key)) continue;
    seen.add(key);
    const dst = hostOf(p.dst);
    const h = healthByDst.get(dst);
    const device = nameByAddr.get(dst) ?? undefined;
    const m: MeasuredPath = {
      key, path: { ...p, hops: p.hops ?? [] }, dst, device, health: h,
      verdict: verdictOf({ ...p, hops: p.hops ?? [] }, h), firstLoss: firstLossIndex({ hops: p.hops ?? [], reached: p.reached }),
    };
    all.push(m);
    push(byDst, dst, m);
    if (device) push(byDevice, nameKey(device), m);
  }
  all.sort(byWorst);
  return { all, byDst, byDevice };
}

/** Worst first; ties by destination so the order is stable. */
export function byWorst(a: MeasuredPath, b: MeasuredPath): number {
  return VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict] || a.dst.localeCompare(b.dst) || a.key.localeCompare(b.key);
}

function attach(out: AttachedPath[], seen: Set<string>, list: MeasuredPath[] | undefined, role: AttachedPath["role"]): void {
  for (const m of list ?? []) {
    if (seen.has(m.key)) continue;
    seen.add(m.key);
    out.push({ m, role });
  }
}

const sortAttached = (xs: AttachedPath[]): AttachedPath[] => xs.sort((a, b) => byWorst(a.m, b.m));

/** A WAN circuit row's paths: to its measurement target, then to its router. */
export function wanRowPaths(
  idx: MeasuredIndex | null | undefined,
  row: { device: string; target?: string; has_target?: boolean },
): AttachedPath[] {
  if (!idx) return [];
  const out: AttachedPath[] = [];
  const seen = new Set<string>();
  if (row.has_target !== false && row.target) attach(out, seen, idx.byDst.get(hostOf(row.target)), "target");
  attach(out, seen, idx.byDevice.get(nameKey(row.device)), "router");
  return sortAttached(out);
}

/** A tunnel row's paths: to the device at End A and at End B. */
export function tunnelRowPaths(
  idx: MeasuredIndex | null | undefined,
  t: { local_device?: string; remote_device?: string; a?: { device?: string } | null; b?: { device?: string } | null },
): AttachedPath[] {
  if (!idx) return [];
  const out: AttachedPath[] = [];
  const seen = new Set<string>();
  const a = t.a?.device || t.local_device;
  const b = t.b?.device || t.remote_device;
  if (a) attach(out, seen, idx.byDevice.get(nameKey(a)), "end-a");
  if (b) attach(out, seen, idx.byDevice.get(nameKey(b)), "end-b");
  return sortAttached(out);
}

/** The paths none of `claimed` names, worst first. */
export function unclaimedPaths(idx: MeasuredIndex | null | undefined, claimed: ReadonlySet<string>): MeasuredPath[] {
  if (!idx) return [];
  return idx.all.filter((m) => !claimed.has(m.key));
}

export interface VerdictText {
  text: string;
  tone: "good" | "warn" | "bad";
}

/** The path's state in a few words, for a chip. */
export function verdictText(m: MeasuredPath): VerdictText {
  switch (m.verdict) {
    case "unreached":
      return { text: "Not reached", tone: "bad" };
    case "loss":
      return { text: `Loss from hop ${m.path.hops[m.firstLoss]?.ttl ?? m.firstLoss + 1}`, tone: "warn" };
    case "changed":
      return { text: "Route changed", tone: "warn" };
    case "degraded":
      return { text: m.health?.health_state === "severe" ? "Severe" : "Degraded", tone: m.health?.health_state === "severe" ? "bad" : "warn" };
    default:
      return { text: "Reached", tone: "good" };
  }
}

/** "7 hops" — the hop count the trace saw. */
export function hopsText(m: MeasuredPath): string {
  const n = m.path.hops.length;
  return `${n} hop${n === 1 ? "" : "s"}`;
}

/** Where the path goes, relative to its row. */
export function roleText(a: AttachedPath, row?: { a?: string; b?: string }): string {
  switch (a.role) {
    case "target":
      return "To the measurement target";
    case "router":
      return "To the router";
    case "end-a":
      return row?.a ? `To End A (${row.a})` : "To End A";
    case "end-b":
      return row?.b ? `To End B (${row.b})` : "To End B";
    case "other":
      return `To ${destText(a.m)}`;
  }
}

/** The destination as a person reads it: the device name, with its address. */
export function destText(m: MeasuredPath): string {
  return m.device ? `${m.device} (${m.path.dst})` : m.path.dst;
}
