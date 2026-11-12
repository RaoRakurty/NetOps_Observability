// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowsLink — the Explore → Flows route and its deep link, in one place so
// the page that READS the link and every page that WRITES one (the RCA case's
// traffic-flow lane) agree on its shape:
//
//   #/explore/flows[/talking|/capacity]?device=<exporter>&if=<ifIndex>&from=<iso>&to=<iso>
//
// device is the flow exporter's address and if its interface index — exactly
// the flow filter's own vocabulary, validated the same way, so a malformed
// value is dropped here rather than refused by the API later.

// ── route ────────────────────────────────────────────────────────────────────

export type FlowsTab = "now" | "talking" | "capacity";
const TAB_SEG: Record<FlowsTab, string> = { now: "", talking: "talking", capacity: "capacity" };

/** The tab carried in the route's third segment: #/explore/flows[/talking|/capacity]. */
export function tabFromHash(hash: string): FlowsTab {
  const seg = hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] ?? "";
  return seg === "talking" ? "talking" : seg === "capacity" ? "capacity" : "now";
}

/** The "?…" part of a hash, or "". */
export function hashQuery(hash: string): string {
  const i = hash.indexOf("?");
  return i >= 0 ? hash.slice(i) : "";
}

export function tabHash(tab: FlowsTab, query = ""): string {
  const seg = TAB_SEG[tab];
  return `#/explore/flows${seg ? `/${seg}` : ""}${query}`;
}

/** device = exporter address, ifIndex = its interface, from/to = ms epoch. */
export type DeepLink = { device?: string; ifIndex?: string; from?: number; to?: number };

const IPISH = /^[0-9A-Fa-f.:]{1,45}$/;
const IFINDEX = /^\d{1,10}$/;

function parseTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const t = /^\d{9,13}$/.test(v) ? Number(v) * (v.length <= 10 ? 1000 : 1) : Date.parse(v);
  return Number.isFinite(t) && t > 0 ? t : undefined;
}

/**
 * Reads ?device=&if=&from=&to= off the hash. Anything malformed is dropped,
 * never passed on: the device must look like an address (the flow filter's
 * own rule), the interface must be an index.
 */
export function parseDeepLink(hash: string): DeepLink {
  const q = new URLSearchParams(hashQuery(hash).slice(1));
  const out: DeepLink = {};
  const device = (q.get("device") ?? "").trim();
  if (IPISH.test(device)) out.device = device;
  const ifIndex = (q.get("if") ?? "").trim();
  if (out.device && IFINDEX.test(ifIndex)) out.ifIndex = ifIndex;
  const from = parseTime(q.get("from"));
  const to = parseTime(q.get("to"));
  if (from !== undefined) out.from = from;
  if (to !== undefined && (from === undefined || to >= from)) out.to = to;
  return out;
}

/** #/explore/flows?device=&if=&from=&to= — the link the Flows page reads back. */
export function flowsHref(p: DeepLink, tab: FlowsTab = "now"): string {
  const q = new URLSearchParams();
  if (p.device && IPISH.test(p.device)) {
    q.set("device", p.device);
    if (p.ifIndex && IFINDEX.test(p.ifIndex)) q.set("if", p.ifIndex);
  }
  if (p.from && Number.isFinite(p.from)) q.set("from", new Date(p.from).toISOString());
  if (p.to && Number.isFinite(p.to)) q.set("to", new Date(p.to).toISOString());
  const s = q.toString();
  return tabHash(tab, s ? `?${s}` : "");
}

