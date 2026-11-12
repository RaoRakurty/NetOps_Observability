// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowsModel — the pure view models behind Explore → Flows (P1, 2026-11-12).
//
// The unit of the page is a LINK: one interface on one device (the exporter
// and the ifIndex its flows name). Interface utilisation is the anchor — it is
// what a NOC watches — and the flows explain it: who was talking on that link,
// which applications, and which problems overlapped the window.
//
// Everything here is a pure function of what the existing APIs returned, so
// every rule the screen depends on is unit-tested (flowsModel.test.ts):
//
//   · a link is (exporter, ifIndex); the IPFIX "no interface" sentinels are
//     never a link;
//   · "change vs the previous window" is the double-window total minus the
//     current one, and reads "—" when the previous window is not known — it is
//     never guessed;
//   · utilisation exists only where the interface reports a speed;
//   · flow totals are shown as the API scaled them. Nothing here multiplies by
//     a sampling rate (tracker 387: "do not multiply").

import type { CorrObject, Device, FlowFilters, PromInstantSeries, PromSeries } from "../../services/api";
import type { TopNRow } from "../flowNames";
import { IANA_PROTO_NAMES } from "../../proto";
import type { DeepLink } from "../../lib/flowsLink";

// ── route + deep link: lib/flowsLink.ts (shared with the RCA workspace) ────

export { tabFromHash, hashQuery, tabHash, parseDeepLink, flowsHref } from "../../lib/flowsLink";
export type { FlowsTab, DeepLink } from "../../lib/flowsLink";

// ── window ───────────────────────────────────────────────────────────────────

export const MIN_WINDOW_S = 300;
export const MAX_WINDOW_S = 30 * 86_400;
/** How much time before a problem's start the timeline shows. */
export const PROBLEM_LEAD_S = 300;

export type FlowsWindow = {
  /** Seconds back from now that every flow query covers. */
  since: number;
  /** The problem window from a deep link, marked on the timeline. */
  problem?: { from: number; to: number };
};

/**
 * The flow APIs answer "the last N seconds", so a problem window from a deep
 * link is covered by reaching back to a little before its start; the window
 * itself is then marked, not cut out (exact from/to windows come with P2).
 */
export function flowsWindow(rangeSeconds: number, link: DeepLink, now: number = Date.now()): FlowsWindow {
  const clamp = (s: number) => Math.min(MAX_WINDOW_S, Math.max(MIN_WINDOW_S, Math.round(s)));
  if (link.from !== undefined && link.from < now) {
    return {
      since: clamp(Math.ceil((now - link.from) / 1000) + PROBLEM_LEAD_S),
      problem: { from: link.from, to: Math.min(link.to ?? now, now) },
    };
  }
  return { since: clamp(rangeSeconds) };
}

// ── links ────────────────────────────────────────────────────────────────────

/** IPFIX "no interface" values: never a link. */
export const IF_SENTINELS = new Set(["0", "4294967295"]);

export type LinkRow = {
  key: string;
  exporter: string;
  ifIndex: string;
  /** The device's own name for the interface (IF-MIB), "" when not reported. */
  ifName: string;
  inBytes: number;
  outBytes: number;
  totalBytes: number;
  /** Bytes in the previous window of the same length; null = not known. */
  prevBytes: number | null;
  /** (now − previous) / previous; null when previous is unknown or zero. */
  change: number | null;
  deviceId?: string;
  deviceName?: string;
  /** From the interface counters, not the flows. */
  speedBps?: number;
  inBps?: number;
  outBps?: number;
  utilPct?: number;
  spark?: number[];
};

export const linkKey = (exporter: string, ifIndex: string) => `${exporter}|${ifIndex}`;

const num = (v: unknown): number => {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
};

function ifNameOf(r: TopNRow, by: "in_if" | "out_if"): string {
  const basis = by === "in_if" ? r.in_if_name_basis : r.out_if_name_basis;
  const name = (by === "in_if" ? r.in_if_name : r.out_if_name) ?? "";
  return basis === "resolved" ? name.trim() : "";
}

function isSentinel(r: TopNRow, by: "in_if" | "out_if"): boolean {
  const basis = by === "in_if" ? r.in_if_name_basis : r.out_if_name_basis;
  return basis === "sentinel" || IF_SENTINELS.has(String(r.k));
}

/**
 * Busiest links from the two interface top-Ns (?by=in_if and ?by=out_if): a
 * flow that ENTERED on the interface is its inbound traffic, one that LEFT on
 * it is its outbound. Rows group per exporter, since one ifIndex on two
 * devices is two ports.
 */
export function mergeLinks(inRows: readonly TopNRow[] = [], outRows: readonly TopNRow[] = []): LinkRow[] {
  const m = new Map<string, LinkRow>();
  const add = (r: TopNRow, by: "in_if" | "out_if") => {
    const exporter = (r.exporter ?? "").trim();
    const ifIndex = String(r.k ?? "").trim();
    if (!exporter || !ifIndex || isSentinel(r, by)) return;
    const key = linkKey(exporter, ifIndex);
    const row = m.get(key) ?? {
      key, exporter, ifIndex, ifName: "", inBytes: 0, outBytes: 0, totalBytes: 0, prevBytes: null, change: null,
    };
    if (by === "in_if") row.inBytes += num(r.bytes_total);
    else row.outBytes += num(r.bytes_total);
    row.ifName = row.ifName || ifNameOf(r, by);
    row.totalBytes = row.inBytes + row.outBytes;
    m.set(key, row);
  };
  for (const r of inRows) add(r, "in_if");
  for (const r of outRows) add(r, "out_if");
  return [...m.values()].sort((a, b) => b.totalBytes - a.totalBytes || a.key.localeCompare(b.key));
}

/**
 * The previous equal window, from a query over twice the window: previous =
 * double − current. A link missing from the double-window answer (its top-N
 * was cut short) has an unknown previous, not a zero one.
 */
export function withPrevious(cur: readonly LinkRow[], doubleWindow: readonly LinkRow[]): LinkRow[] {
  const dbl = new Map(doubleWindow.map((r) => [r.key, r.totalBytes]));
  return cur.map((r) => {
    const d = dbl.get(r.key);
    if (d === undefined) return { ...r, prevBytes: null, change: null };
    const prev = Math.max(0, d - r.totalBytes);
    return { ...r, prevBytes: prev, change: prev > 0 ? (r.totalBytes - prev) / prev : null };
  });
}

/** "+12%", "−30%", "Same", "New" (nothing before), or "—" (not known). */
export function changeLabel(r: Pick<LinkRow, "prevBytes" | "change" | "totalBytes">): string {
  if (r.prevBytes === null) return "—";
  if (r.prevBytes === 0) return r.totalBytes > 0 ? "New" : "—";
  const pct = Math.round((r.change ?? 0) * 100);
  if (pct === 0) return "Same";
  return pct > 0 ? `+${pct}%` : `−${Math.abs(pct)}%`;
}

/** Joins each link's exporter address to the inventory device that has it. */
export function attachDevices(rows: readonly LinkRow[], devices: readonly Device[], names: ReadonlyMap<string, string>): LinkRow[] {
  const byAddr = new Map<string, Device>();
  for (const d of devices) if (d.address) byAddr.set(d.address, d);
  return rows.map((r) => {
    const d = byAddr.get(r.exporter);
    if (!d) return r;
    return { ...r, deviceId: d.id, deviceName: names.get(d.id) ?? (d.name || d.id) };
  });
}

/** "edge-1 · Gi0/0/1" — the device's name and the interface's, by name first. */
export function linkLabel(r: Pick<LinkRow, "exporter" | "ifIndex" | "ifName" | "deviceName">): string {
  return `${r.deviceName || r.exporter} · ${r.ifName || `interface ${r.ifIndex}`}`;
}

// ── interface counters (utilisation) ─────────────────────────────────────────

const seriesKeys = (m: Record<string, string> = {}): string[] => {
  const out: string[] = [];
  if (m.device && m.index) out.push(`${m.device}|${m.index}`);
  if (m.device && m.ifName) out.push(`${m.device}|name:${m.ifName}`);
  return out;
};

function indexBy<T extends { metric: Record<string, string> }>(series: readonly T[]): Map<string, T> {
  const m = new Map<string, T>();
  for (const s of series) for (const k of seriesKeys(s.metric)) if (!m.has(k)) m.set(k, s);
  return m;
}

function lookup<T>(m: Map<string, T>, deviceId: string, ifIndex: string, ifName: string): T | undefined {
  return m.get(`${deviceId}|${ifIndex}`) ?? (ifName ? m.get(`${deviceId}|name:${ifName}`) : undefined);
}

const lastValue = (s?: PromSeries): number | undefined => {
  if (!s?.values?.length) return undefined;
  const v = Number(s.values[s.values.length - 1][1]);
  return Number.isFinite(v) ? v : undefined;
};

const instantValue = (s?: PromInstantSeries): number | undefined => {
  if (!s?.value) return undefined;
  const v = Number(s.value[1]);
  return Number.isFinite(v) ? v : undefined;
};

/**
 * Adds what the interface counters say about each link: in/out bits per second
 * now, the reported speed, utilisation (the busier direction, in percent of
 * the speed) and a sparkline of in+out over the window. A link whose device is
 * not in inventory, or whose interface reports no speed, keeps no utilisation.
 */
export function attachUtil(
  rows: readonly LinkRow[],
  inSeries: readonly PromSeries[],
  outSeries: readonly PromSeries[],
  speed: readonly PromInstantSeries[],
): LinkRow[] {
  const inIdx = indexBy(inSeries);
  const outIdx = indexBy(outSeries);
  const spIdx = indexBy(speed);
  return rows.map((r) => {
    if (!r.deviceId) return r;
    const si = lookup(inIdx, r.deviceId, r.ifIndex, r.ifName);
    const so = lookup(outIdx, r.deviceId, r.ifIndex, r.ifName);
    const sp = instantValue(lookup(spIdx, r.deviceId, r.ifIndex, r.ifName));
    const inBps = lastValue(si);
    const outBps = lastValue(so);
    const out: LinkRow = { ...r };
    if (inBps !== undefined) out.inBps = inBps;
    if (outBps !== undefined) out.outBps = outBps;
    if (sp !== undefined && sp > 0) {
      out.speedBps = sp;
      const busiest = Math.max(inBps ?? -1, outBps ?? -1);
      if (busiest >= 0) out.utilPct = (busiest / sp) * 100;
    }
    const spark = sumSeries(si, so);
    if (spark.length > 1) out.spark = spark;
    return out;
  });
}

/** Point-by-point sum of two range series, aligned on their timestamps. */
export function sumSeries(a?: PromSeries, b?: PromSeries): number[] {
  const m = new Map<number, number>();
  for (const s of [a, b]) {
    for (const [ts, v] of s?.values ?? []) {
      const x = Number(v);
      if (Number.isFinite(x)) m.set(ts, (m.get(ts) ?? 0) + x);
    }
  }
  return [...m.entries()].sort((x, y) => x[0] - y[0]).map(([, v]) => v);
}

/** The semantic utilisation thresholds (owner, 2026-11-12). */
export const UTIL_WARN = 75;
export const UTIL_CRIT = 90;

/** Tone for a utilisation figure: critical ≥ 90 %, warning ≥ 75 %, else none. */
export function utilTone(pct?: number): "" | "warn" | "bad" {
  if (pct === undefined || !Number.isFinite(pct)) return "";
  return pct >= UTIL_CRIT ? "bad" : pct >= UTIL_WARN ? "warn" : "";
}

/**
 * Where a utilisation figure sits on the scale: three calm steps of the
 * sequential ramp for normal load (u1 < 25 %, u2 < 50 %, u3 < 75 %), then the
 * semantic bands. "" when there is no figure. CSS maps each band to a token.
 */
export type UtilBand = "" | "u1" | "u2" | "u3" | "warn" | "crit";
export function utilBand(pct?: number): UtilBand {
  if (pct === undefined || !Number.isFinite(pct)) return "";
  if (pct >= UTIL_CRIT) return "crit";
  if (pct >= UTIL_WARN) return "warn";
  return pct >= 50 ? "u3" : pct >= 25 ? "u2" : "u1";
}

export function fmtPctOrDash(pct?: number): string {
  if (pct === undefined || !Number.isFinite(pct)) return "—";
  return pct < 1 && pct > 0 ? "<1%" : `${Math.round(pct)}%`;
}

// ── capacity ─────────────────────────────────────────────────────────────────

export type CapacityRow = {
  key: string;
  deviceId: string;
  deviceName: string;
  site: string;
  ifIndex: string;
  ifName: string;
  speedBps?: number;
  avgIn?: number;
  peakIn?: number;
  avgOut?: number;
  peakOut?: number;
  /** The busier direction's peak / average. */
  peak?: number;
  avg?: number;
};

export type CapacityInput = {
  avgIn: readonly PromInstantSeries[];
  peakIn: readonly PromInstantSeries[];
  avgOut: readonly PromInstantSeries[];
  peakOut: readonly PromInstantSeries[];
  speed: readonly PromInstantSeries[];
};

const maxDefined = (a?: number, b?: number): number | undefined =>
  a === undefined ? b : b === undefined ? a : Math.max(a, b);

/**
 * Per-link utilisation over the window (average and peak of the 5-minute
 * rate, in percent of the reported speed), busiest peak first. Only interfaces
 * with a known speed have a utilisation series at all.
 */
export function capacityRows(q: CapacityInput, names: ReadonlyMap<string, string>, sites: ReadonlyMap<string, string>): CapacityRow[] {
  const rows = new Map<string, CapacityRow>();
  const put = (series: readonly PromInstantSeries[], field: "avgIn" | "peakIn" | "avgOut" | "peakOut" | "speedBps") => {
    for (const s of series) {
      const m = s.metric ?? {};
      if (!m.device || !m.index) continue;
      const v = instantValue(s);
      if (v === undefined) continue;
      const key = `${m.device}|${m.index}`;
      const row = rows.get(key) ?? {
        key, deviceId: m.device, deviceName: names.get(m.device) ?? m.device, site: sites.get(m.device) ?? "",
        ifIndex: m.index, ifName: (m.ifName ?? "").trim(),
      };
      row.ifName = row.ifName || (m.ifName ?? "").trim();
      row[field] = v;
      rows.set(key, row);
    }
  };
  put(q.avgIn, "avgIn");
  put(q.peakIn, "peakIn");
  put(q.avgOut, "avgOut");
  put(q.peakOut, "peakOut");
  const withUtil = new Set(rows.keys());
  put(q.speed, "speedBps");
  return [...rows.values()]
    .filter((r) => withUtil.has(r.key))
    .map((r) => ({ ...r, peak: maxDefined(r.peakIn, r.peakOut), avg: maxDefined(r.avgIn, r.avgOut) }))
    .sort((a, b) => (b.peak ?? -1) - (a.peak ?? -1) || a.key.localeCompare(b.key));
}

export const NO_SITE = "No site set";

/** Groups capacity rows by site or by device, groups in their busiest-first order. */
export function groupCapacity(rows: readonly CapacityRow[], by: "site" | "device"): { group: string; rows: CapacityRow[] }[] {
  const m = new Map<string, CapacityRow[]>();
  for (const r of rows) {
    const g = by === "site" ? r.site || NO_SITE : r.deviceName;
    const list = m.get(g) ?? [];
    list.push(r);
    m.set(g, list);
  }
  return [...m.entries()].map(([group, rs]) => ({ group, rows: rs }));
}

// ── problems on the link ─────────────────────────────────────────────────────

/** Correlation timestamps: "YYYY-MM-DD HH:MM:SS[.fff]" in UTC, or ISO. */
export function parseCorrTs(v?: string): number | null {
  if (!v) return null;
  const s = v.includes("T") ? v : v.replace(" ", "T");
  const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);
  return Number.isFinite(t) ? t : null;
}

export type ProblemMark = { id: string; hypothesis: string; from: number; to: number; state: string };

export type LinkIdentity = { exporter: string; deviceId?: string; deviceName?: string };

/**
 * The problems whose window overlaps [from, to] and whose affected devices
 * name this link's device (by inventory id, name, or the exporter address).
 * Matching is on what the correlation object itself lists — nothing inferred.
 */
export function problemsForLink(objs: readonly CorrObject[], from: number, to: number, link: LinkIdentity): ProblemMark[] {
  const want = new Set([link.exporter, link.deviceId, link.deviceName].filter(Boolean).map((s) => String(s).toLowerCase()));
  const out: ProblemMark[] = [];
  for (const o of objs) {
    const ws = parseCorrTs(o.window_start);
    if (ws === null) continue;
    const we = parseCorrTs(o.window_end) ?? ws;
    if (ws > to || we < from) continue;
    let devices: unknown[] = [];
    try {
      const aff = JSON.parse(o.affected || "{}") as { devices?: unknown[] };
      devices = Array.isArray(aff.devices) ? aff.devices : [];
    } catch {
      devices = [];
    }
    if (!devices.some((d) => want.has(String(d).toLowerCase()))) continue;
    out.push({ id: o.correlation_id, hypothesis: o.top_hypothesis, from: ws, to: we, state: o.state });
  }
  return out.sort((a, b) => a.from - b.from);
}

// ── who-is-talking filters ───────────────────────────────────────────────────

export type IfDir = "either" | "in" | "out";

export type TalkFilters = {
  device?: string; // exporter address
  if?: string; // ifIndex on that device
  ifDir?: IfDir;
  addr?: string; // address or network, either end
  port?: string;
  proto?: string; // protocol number
  type?: string; // netflow | ipfix | sflow
  direction?: "" | "bi";
  app?: string; // narrows the Applications / Services lists
};

/** The flow-API filters for the chip bar (app is a list filter, never sent). */
export function toFlowFilters(f: TalkFilters, includePlatform: boolean): FlowFilters {
  const out: FlowFilters = {};
  if (f.device) out.device = f.device;
  if (f.device && f.if) {
    if (f.ifDir === "in") out.in_if = f.if;
    else if (f.ifDir === "out") out.out_if = f.if;
    else out.if = f.if;
  }
  if (f.addr) out.addr = f.addr;
  if (f.port) out.port = f.port;
  if (f.proto) out.proto = f.proto;
  if (includePlatform) out.traffic = "all";
  return out;
}

/** Filter-bar keys that narrow the flow queries (for the window-only caveat). */
export function serverFilterKeys(f: TalkFilters): string[] {
  return (["device", "if", "addr", "port", "proto"] as const).filter((k) => !!f[k]);
}

const IPV4_OR_6 = /^[0-9A-Fa-f.:]{2,45}$/;

/** An address or a network; null when valid, else what is wrong. */
export function checkAddress(v: string): string | null {
  const s = v.trim();
  if (!s) return "Enter an address or a network.";
  const [ip, len, extra] = s.split("/");
  if (extra !== undefined || !IPV4_OR_6.test(ip)) return "Use an address like 10.1.2.3 or a network like 10.1.0.0/16.";
  if (len !== undefined) {
    const max = ip.includes(":") ? 128 : 32;
    if (!/^\d{1,3}$/.test(len) || Number(len) > max) return `The network length must be 0 to ${max}.`;
  }
  if (!ip.includes(":")) {
    const parts = ip.split(".");
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) {
      return "Use an address like 10.1.2.3 or a network like 10.1.0.0/16.";
    }
  }
  return null;
}

export function checkPort(v: string): string | null {
  return /^\d{1,5}$/.test(v.trim()) && Number(v) <= 65535 ? null : "A port is a number from 0 to 65535.";
}

const PROTO_BY_NAME: Record<string, string> = Object.fromEntries(
  Object.entries(IANA_PROTO_NAMES).map(([n, name]) => [name.toLowerCase(), n]),
);

/** "tcp" / "TCP" / "6" → "6"; null when not a protocol. */
export function protoNumber(v: string): string | null {
  const s = v.trim().toLowerCase();
  if (/^\d{1,3}$/.test(s) && Number(s) <= 255) return String(Number(s));
  return PROTO_BY_NAME[s] ?? null;
}

export function protoName(n: string): string {
  const name = IANA_PROTO_NAMES[n];
  return name ? `${name} (${n})` : `Protocol ${n}`;
}

export const FLOW_SOURCES: { value: string; label: string }[] = [
  { value: "", label: "All sources" },
  { value: "netflow", label: "NetFlow" },
  { value: "ipfix", label: "IPFIX" },
  { value: "sflow", label: "sFlow" },
];

export type Chip = { key: keyof TalkFilters; label: string };

/** The chips on screen for the active filters, each removable on its own. */
export function filterChips(f: TalkFilters, names: { device?: string; iface?: string } = {}): Chip[] {
  const chips: Chip[] = [];
  if (f.device) chips.push({ key: "device", label: `Device: ${names.device || f.device}` });
  if (f.device && f.if) {
    const dir = f.ifDir === "in" ? " (entering)" : f.ifDir === "out" ? " (leaving)" : "";
    chips.push({ key: "if", label: `Interface: ${names.iface || `interface ${f.if}`}${dir}` });
  }
  if (f.addr) chips.push({ key: "addr", label: `Address: ${f.addr}` });
  if (f.port) chips.push({ key: "port", label: `Port: ${f.port}` });
  if (f.proto) chips.push({ key: "proto", label: `Protocol: ${protoName(f.proto)}` });
  if (f.type) chips.push({ key: "type", label: `Source: ${FLOW_SOURCES.find((s) => s.value === f.type)?.label ?? f.type}` });
  if (f.direction === "bi") chips.push({ key: "direction", label: "Both directions as one" });
  if (f.app) chips.push({ key: "app", label: `Application: ${f.app}` });
  return chips;
}

/** Removes one chip; removing the device also removes its interface. */
export function withoutChip(f: TalkFilters, key: keyof TalkFilters): TalkFilters {
  const next: TalkFilters = { ...f, [key]: undefined };
  if (key === "device") {
    next.if = undefined;
    next.ifDir = undefined;
  }
  if (key === "if") next.ifDir = undefined;
  return next;
}

/** Interface choices for a device, from the interface top-N rows (names from IF-MIB). */
export function interfaceOptions(inRows: readonly TopNRow[], outRows: readonly TopNRow[], exporter: string): { value: string; label: string }[] {
  const links = mergeLinks(inRows, outRows).filter((l) => l.exporter === exporter);
  return links
    .map((l) => ({ value: l.ifIndex, label: l.ifName ? `${l.ifName} (${l.ifIndex})` : `Interface ${l.ifIndex}` }))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
}

/**
 * Device choices by NAME: inventory devices plus any exporter that sends flows
 * without being in inventory (shown by its address). Value = exporter address.
 */
export function deviceOptions(devices: readonly Device[], exporters: readonly string[], names: ReadonlyMap<string, string>): { value: string; label: string }[] {
  const seen = new Map<string, string>();
  for (const d of devices) {
    if (!d.address) continue;
    seen.set(d.address, names.get(d.id) ?? (d.name || d.address));
  }
  for (const e of exporters) if (e && !seen.has(e)) seen.set(e, e);
  return [...seen.entries()]
    .map(([value, label]) => ({ value, label: label === value ? value : `${label} (${value})` }))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
}
