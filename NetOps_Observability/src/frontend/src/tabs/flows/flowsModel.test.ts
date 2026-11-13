// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { CorrObject, Device, FlowCapacityRow, FlowLinkRow, FlowLinkSeriesResp } from "../../services/api";
import type { TopNRow } from "../flowNames";
import {
  attachDevices, attachUtil, capacityFromApi, changeLabel, checkAddress, checkPort, deviceOptions, directionNote, filterChips,
  fmtPctOrDash, forecastText, forecastTone, groupCapacity, interfaceOptions, linkLabel, linkRowKey, linksFromApi, mergeLinks,
  moverChange, NO_SITE, parseCorrTs, problemsForLink, protoName, protoNumber, samplingNote, serverFilterKeys, seriesRates,
  sumSeries, toFlowFilters, flowsWindow, utilBand, utilTone, windowQuery, withPrevious, withoutChip,
  MAX_WINDOW_S, MIN_WINDOW_S, PROBLEM_LEAD_S,
} from "./flowsModel";

const inRow = (exporter: string, k: string, bytes: number, name = "", basis = name ? "resolved" : "absent"): TopNRow => ({
  k, exporter, bytes_total: bytes, packets_total: 1, flows: 1, in_if_name: name, in_if_name_basis: basis,
});
const outRow = (exporter: string, k: string, bytes: number, name = "", basis = name ? "resolved" : "absent"): TopNRow => ({
  k, exporter, bytes_total: bytes, packets_total: 1, flows: 1, out_if_name: name, out_if_name_basis: basis,
});
const dev = (id: string, name: string, address: string): Device => ({ id, name, address, source: "snmp", last_seen: "" });

describe("mergeLinks — a link is one interface on one device", () => {
  it("adds entering and leaving traffic per (exporter, ifIndex), busiest first", () => {
    const links = mergeLinks(
      [inRow("10.0.0.1", "3", 500, "Gi0/3"), inRow("10.0.0.2", "3", 900)],
      [outRow("10.0.0.1", "3", 200), outRow("10.0.0.1", "4", 50, "Gi0/4")],
    );
    expect(links.map((l) => [l.key, l.inBytes, l.outBytes, l.totalBytes, l.ifName])).toEqual([
      ["10.0.0.2|3", 900, 0, 900, ""],
      ["10.0.0.1|3", 500, 200, 700, "Gi0/3"],
      ["10.0.0.1|4", 0, 50, 50, "Gi0/4"],
    ]);
  });

  it("never treats the IPFIX 'no interface' values or a row without an exporter as a link", () => {
    const links = mergeLinks(
      [inRow("10.0.0.1", "4294967295", 9e9), inRow("10.0.0.1", "0", 1), inRow("", "5", 10), inRow("10.0.0.1", "9", 5, "", "sentinel")],
      [],
    );
    expect(links).toEqual([]);
  });

  it("does not take a name the API did not resolve", () => {
    expect(mergeLinks([inRow("10.0.0.1", "3", 1, "ghost", "absent")], [])[0].ifName).toBe("");
  });

  it("parses ClickHouse's quoted 64-bit counts", () => {
    const r = { ...inRow("10.0.0.1", "3", 0), bytes_total: "12345" as unknown as number };
    expect(mergeLinks([r], [])[0].inBytes).toBe(12345);
  });
});

describe("withPrevious / changeLabel — change against the previous equal window", () => {
  const cur = mergeLinks([inRow("a", "1", 300), inRow("b", "1", 100), inRow("c", "1", 50)], []);
  it("previous = double window − current; unknown when the link is missing from the double window", () => {
    const dbl = mergeLinks([inRow("a", "1", 500), inRow("b", "1", 100)], []);
    const rows = withPrevious(cur, dbl);
    expect(rows.map((r) => [r.key, r.prevBytes, r.change])).toEqual([
      ["a|1", 200, 0.5],
      ["b|1", 0, null],
      ["c|1", null, null],
    ]);
    expect(rows.map(changeLabel)).toEqual(["+50%", "New", "—"]);
  });
  it("reads drops, flat and unknown plainly", () => {
    expect(changeLabel({ prevBytes: 400, change: -0.25, totalBytes: 300 })).toBe("−25%");
    expect(changeLabel({ prevBytes: 400, change: 0.004, totalBytes: 401 })).toBe("Same");
    expect(changeLabel({ prevBytes: null, change: null, totalBytes: 1 })).toBe("—");
    expect(changeLabel({ prevBytes: 0, change: null, totalBytes: 0 })).toBe("—");
  });
});

describe("devices and utilisation", () => {
  const devices = [dev("edge-1-ab", "edge-1", "10.0.0.1")];
  const names = new Map([["edge-1-ab", "edge-1"]]);
  const links = attachDevices(mergeLinks([inRow("10.0.0.1", "3", 100, "Gi0/3"), inRow("10.9.9.9", "1", 10)], []), devices, names);

  it("joins the exporter address to inventory and labels by name first", () => {
    expect(links[0]).toMatchObject({ deviceId: "edge-1-ab", deviceName: "edge-1" });
    expect(linkLabel(links[0])).toBe("edge-1 · Gi0/3");
    expect(links[1].deviceId).toBeUndefined();
    expect(linkLabel(links[1])).toBe("10.9.9.9 · interface 1");
  });

  it("utilisation = busier direction now / reported speed; absent without a speed", () => {
    const series = (dir: number[], idx = "3") => ({ metric: { device: "edge-1-ab", index: idx }, values: dir.map((v, i) => [1000 + i * 60, String(v)] as [number, string]) });
    const rows = attachUtil(
      links,
      [series([10e6, 20e6])],
      [series([5e6, 80e6])],
      [{ metric: { device: "edge-1-ab", index: "3" }, value: [0, "100000000"] }],
    );
    expect(rows[0]).toMatchObject({ inBps: 20e6, outBps: 80e6, speedBps: 100e6, utilPct: 80, spark: [15e6, 100e6] });
    expect(rows[1].utilPct).toBeUndefined(); // not in inventory → no counters to read

    const noSpeed = attachUtil(links, [series([1, 2])], [], []);
    expect(noSpeed[0].utilPct).toBeUndefined();
    expect(noSpeed[0].speedBps).toBeUndefined();
    expect(noSpeed[0].inBps).toBe(2);
  });

  it("falls back to the interface name when the series has no index label", () => {
    const s = { metric: { device: "edge-1-ab", ifName: "Gi0/3" }, values: [[1, "5"], [2, "7"]] as [number, string][] };
    expect(attachUtil(links, [s], [], [])[0].inBps).toBe(7);
  });

  it("aligns sparkline points on their timestamps", () => {
    expect(sumSeries({ metric: {}, values: [[1, "1"], [2, "2"]] }, { metric: {}, values: [[2, "10"], [3, "x"]] })).toEqual([1, 12]);
    expect(sumSeries()).toEqual([]);
  });

  it("tones and formats utilisation", () => {
    expect([utilTone(95), utilTone(90), utilTone(75), utilTone(74.9), utilTone(undefined)]).toEqual(["bad", "bad", "warn", "", ""]);
    expect([0, 24.9, 25, 49.9, 50, 74.9, 75, 89.9, 90, 140].map(utilBand)).toEqual(["u1", "u1", "u2", "u2", "u3", "u3", "warn", "warn", "crit", "crit"]);
    expect(utilBand(undefined)).toBe("");
    expect(utilBand(NaN)).toBe("");
    expect([fmtPctOrDash(undefined), fmtPctOrDash(0.4), fmtPctOrDash(0), fmtPctOrDash(73.6)]).toEqual(["—", "<1%", "0%", "74%"]);
  });
});

const capRow = (over: Partial<FlowCapacityRow>): FlowCapacityRow => ({
  device_id: "d1", device_name: "edge-1", site: "Dallas", ifindex: "1", if_name: "Gi1", speed_bps: 1e9, speed_basis: "reported",
  p95_in_bps: 1e8, p95_out_bps: 2e8, p95_bps: 2e8, peak_bps: 3e8, p95_in_pct: 10, p95_out_pct: 20, p95_pct: 20, peak_pct: 30,
  headroom_bps: 8e8, headroom_pct: 80,
  forecast: { status: "rising", days_to_90: 23.4, slope_pct_per_day: 1, fitted_pct: 66, r2: 0.9, history_days: 28, min_days: 14 },
  ...over,
});

describe("capacity (P2) — rows from /api/flows/capacity", () => {
  const rows = capacityFromApi([
    capRow({}),
    capRow({ device_id: "d2", device_name: "edge-2", site: "", ifindex: "7", if_name: "" }),
    capRow({ device_id: "d3", device_name: "edge-3", ifindex: "", if_name: "ge0/1", speed_bps: null, speed_basis: "unknown", p95_pct: null }),
    capRow({ device_id: "d4", device_name: "edge-4", ifindex: "2", speed_basis: "implausible", p95_pct: null }),
  ]);

  it("keys by device and ifIndex, or by name when the source carries no index", () => {
    expect(rows.map((r) => r.key)).toEqual(["d1|1", "d2|7", "d3|name:ge0/1", "d4|2"]);
  });

  it("groups links with a usable speed by site or device, and keeps the rest apart", () => {
    const bySite = groupCapacity(rows, "site");
    expect(bySite.groups.map((g) => [g.group, g.rows.length])).toEqual([["Dallas", 1], [NO_SITE, 1]]);
    expect(bySite.noSpeed.map((r) => r.device_id)).toEqual(["d3", "d4"]);
    expect(groupCapacity(rows, "device").groups.map((g) => g.group)).toEqual(["edge-1", "edge-2"]);
  });

  it("says when a link reaches 90 % in plain words", () => {
    const f = capRow({}).forecast;
    expect(forecastText(f)).toBe("In about 23 days");
    expect(forecastText({ ...f, days_to_90: 0.4 })).toBe("Within a day");
    expect(forecastText({ ...f, days_to_90: 1 })).toBe("In about 1 day");
    expect(forecastText({ ...f, status: "at_or_over_90" })).toBe("Already above 90 %");
    expect(forecastText({ ...f, status: "flat_or_falling" })).toBe("Not rising");
    expect(forecastText({ ...f, status: "unsteady" })).toBe("No steady trend");
    expect(forecastText({ ...f, status: "not_enough_history", history_days: 6 })).toBe("Collecting history — 6 of 14 days");
    expect(forecastText({ ...f, status: "speed_unknown" })).toBe("Speed not reported");
    expect([forecastTone(f), forecastTone({ ...f, days_to_90: 60 }), forecastTone({ ...f, days_to_90: 120 }), forecastTone({ ...f, status: "at_or_over_90" })])
      .toEqual(["bad", "warn", "", "bad"]);
  });
});

const apiLink = (over: Partial<FlowLinkRow>): FlowLinkRow => ({
  exporter: "10.0.0.1", ifindex: 3, if_name: "Gi0/3", if_name_basis: "resolved", in_bytes: 300, out_bytes: 100,
  prev_in_bytes: 100, prev_out_bytes: 100, in_packets: 1, out_packets: 1, flows: 2, in_basis: "measured", out_basis: "measured",
  sampling: "reported", ...over,
});

describe("links (P2) — rows from /api/flows/links", () => {
  it("maps the API row; change is against the previous window from the same scan", () => {
    const [r] = linksFromApi([apiLink({ device_id: "d1", device_name: "edge-1", site: "Dallas" })]);
    expect(r).toMatchObject({ key: "10.0.0.1|3", ifName: "Gi0/3", inBytes: 300, outBytes: 100, totalBytes: 400, prevBytes: 200, deviceId: "d1", site: "Dallas" });
    expect(changeLabel(r)).toBe("+100%");
  });

  it("a direction the router does not export is missing, not zero, and change still uses what it does export", () => {
    const [r] = linksFromApi([apiLink({ out_bytes: null, prev_out_bytes: null, out_basis: "not_exported" })]);
    expect(r.outMissing).toBe(true);
    expect(r.outBytes).toBe(0);
    expect(r.prevBytes).toBe(100);
    expect(directionNote(r, "out")).toBe("Not exported by this router");
  });

  it("an unknown previous window gives no change figure", () => {
    const [r] = linksFromApi([apiLink({ prev_in_bytes: null })]);
    expect(r.prevBytes).toBeNull();
    expect(changeLabel(r)).toBe("—");
    expect(linksFromApi([apiLink({ in_bytes: null, out_bytes: null })])[0].prevBytes).toBeNull();
  });

  it("drops sentinels, names only resolved interfaces, keys two tenants apart", () => {
    const rows = linksFromApi([
      apiLink({ ifindex: 0 }), apiLink({ ifindex: 4294967295 }),
      apiLink({ if_name: "x", if_name_basis: "absent", tenant_id: "t1" }), apiLink({ tenant_id: "t2" }),
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0].ifName).toBe("");
    expect(rows.map(linkRowKey)).toEqual(["10.0.0.1|3|t1", "10.0.0.1|3|t2"]);
  });

  it("says by how much a partly exported direction reads low", () => {
    const [r] = linksFromApi([apiLink({ in_basis: "partly_exported", in_unnamed_pct: 15.4 })]);
    expect(directionNote(r, "in")).toBe("Reads low: 15 % of this router's flow bytes name no input interface");
    expect(directionNote(linksFromApi([apiLink({ in_basis: "partly_exported", in_unnamed_pct: 0.2 })])[0], "in")).toMatch(/<1 %/);
    expect(directionNote(r, "out")).toBeNull();
  });

  it("names the sampling situation only when it is not reported", () => {
    expect(samplingNote("reported")).toBeNull();
    expect(samplingNote("no_flows")).toBeNull();
    expect(samplingNote("not_reported")).toMatch(/does not report its sampling rate/);
    expect(samplingNote("mixed")).toMatch(/Some of these records/);
  });
});

describe("series (P2) — /api/flows/links/series as bits per second", () => {
  const resp = (over: Partial<FlowLinkSeriesResp>): FlowLinkSeriesResp => ({
    window: { from: "", to: "", seconds: 180, explicit: false, prev_from: "", retention_days: 7, starts_before_retention: false, prev_before_retention: false },
    served: { from: "", to: "" }, step_seconds: 60, exporter: "10.0.0.1", ifindex: 3, t: [0, 60, 120],
    in_bytes: [750, 0, 1500], out_bytes: [75, 75, 75], in_packets: [1, 0, 1], out_packets: [1, 1, 1],
    last_bucket_complete: true, in_basis: "measured", out_basis: "measured",
    basis: { flows: 1, flows_rate_reported: 1, sampling: "reported", bucket_time: "received" }, ...over,
  });
  it("converts bytes per bucket to bits per second, in epoch ms", () => {
    const r = seriesRates(resp({}));
    expect(r.in).toEqual([[0, 100], [60_000, 0], [120_000, 200]]);
    expect(r.out[0]).toEqual([0, 10]);
  });
  it("leaves out a bucket that is still filling, and a direction that is not exported", () => {
    const r = seriesRates(resp({ last_bucket_complete: false, out_bytes: null }));
    expect(r.in).toHaveLength(2);
    expect(r.out).toEqual([]);
    expect(r.outMissing).toBe(true);
    expect(seriesRates(null)).toEqual({ in: [], out: [], inMissing: false, outMissing: false });
  });
});

describe("movers (P2) — what changed", () => {
  it("words each status", () => {
    expect(moverChange({ status: "up", change: 3 })).toBe("+300%");
    expect(moverChange({ status: "down", change: -0.5 })).toBe("−50%");
    expect(moverChange({ status: "new", change: null })).toBe("New");
    expect(moverChange({ status: "gone", change: -1 })).toBe("Gone");
    expect(moverChange({ status: "same", change: 0.01 })).toBe("Same");
    expect(moverChange({ status: "no_previous", change: null })).toBe("—");
  });
});

describe("problemsForLink — problems that name this link's device in the window", () => {
  const obj = (id: string, ws: string, we: string, devices: unknown): CorrObject => ({
    correlation_id: id, version: 1, state: "open", window_start: ws, window_end: we, top_hypothesis: "link_down",
    top_confidence: 0.9, verdict_tier: "suspected", evidence_missing: "[]", affected: JSON.stringify({ devices }),
    signal_count: 1, node_count: 1, engine_version: "x", catalog_version: "x", created_at: ws,
  });
  const from = Date.parse("2026-11-12T03:00:00Z");
  const to = Date.parse("2026-11-12T04:00:00Z");
  it("matches on the devices the object lists — id, name or exporter address — and on window overlap", () => {
    const got = problemsForLink([
      obj("p1", "2026-11-12 03:10:00", "2026-11-12 03:20:00", ["edge-1"]),
      obj("p2", "2026-11-12 02:00:00", "2026-11-12 03:00:30", ["10.0.0.1"]),
      obj("p3", "2026-11-12 03:10:00", "2026-11-12 03:20:00", ["other"]),
      obj("p4", "2026-11-12 05:00:00", "2026-11-12 05:10:00", ["edge-1"]),
      obj("p5", "2026-11-12 03:30:00", "", ["EDGE-1-AB"]),
      { ...obj("p6", "2026-11-12 03:30:00", "", []), affected: "not json" },
    ], from, to, { exporter: "10.0.0.1", deviceId: "edge-1-ab", deviceName: "edge-1" });
    expect(got.map((p) => p.id)).toEqual(["p2", "p1", "p5"]);
    expect(got[1].from).toBe(Date.parse("2026-11-12T03:10:00Z"));
  });
  it("reads correlation timestamps as UTC", () => {
    expect(parseCorrTs("2026-11-12 03:00:00")).toBe(Date.parse("2026-11-12T03:00:00Z"));
    expect(parseCorrTs("2026-11-12T03:00:00+01:00")).toBe(Date.parse("2026-11-12T02:00:00Z"));
    expect(parseCorrTs("")).toBeNull();
    expect(parseCorrTs("garbage")).toBeNull();
  });
});

describe("flowsWindow — 'the last N seconds', or an exact window around a deep-linked problem", () => {
  const now = Date.parse("2026-11-12T05:00:00Z");
  it("uses the shell range, clamped", () => {
    expect(flowsWindow(3600, {}, now)).toEqual({ since: 3600, query: { since: 3600 } });
    expect(windowQuery({ since: 900 })).toEqual({ since: 900 });
    expect(flowsWindow(10, {}, now).since).toBe(MIN_WINDOW_S);
    expect(flowsWindow(1e9, {}, now).since).toBe(MAX_WINDOW_S);
  });
  it("reaches back to just before a deep-linked problem and marks its window", () => {
    const from = Date.parse("2026-11-12T03:00:00Z");
    const to = Date.parse("2026-11-12T03:30:00Z");
    // The exact window: the 30-minute problem plus a quarter of it — at least 5 minutes — either side.
    const lead = Math.max(PROBLEM_LEAD_S * 1000, (to - from) / 4);
    expect(flowsWindow(3600, { from, to }, now)).toEqual({
      since: 7200 + PROBLEM_LEAD_S, problem: { from, to }, query: { from: from - lead, to: to + lead },
    });
    // A short problem still gets at least five minutes, ending no later than now.
    const w = flowsWindow(3600, { from: now - 30_000, to: now - 10_000 }, now);
    expect(w.query?.to).toBe(now);
    expect((w.query?.to ?? 0) - (w.query?.from ?? 0)).toBeGreaterThanOrEqual(MIN_WINDOW_S * 1000);
    // An open-ended problem runs to now; a future "to" is cut at now.
    expect(flowsWindow(3600, { from }, now).problem).toEqual({ from, to: now });
    expect(flowsWindow(3600, { from, to: now + 1e6 }, now).problem?.to).toBe(now);
    // A "from" in the future is ignored.
    expect(flowsWindow(3600, { from: now + 1000 }, now)).toEqual({ since: 3600, query: { since: 3600 } });
  });
});

describe("who-is-talking filters", () => {
  it("maps chips to the flow API: interface direction, either-end address, port, protocol", () => {
    expect(toFlowFilters({ device: "10.0.0.1", if: "3", ifDir: "either", addr: "10.1.0.0/16", port: "443", proto: "6", app: "S3" }, false))
      .toEqual({ device: "10.0.0.1", if: "3", addr: "10.1.0.0/16", port: "443", proto: "6" });
    expect(toFlowFilters({ device: "10.0.0.1", if: "3", ifDir: "in" }, true)).toEqual({ device: "10.0.0.1", in_if: "3", traffic: "all" });
    expect(toFlowFilters({ device: "10.0.0.1", if: "3", ifDir: "out" }, false)).toEqual({ device: "10.0.0.1", out_if: "3" });
    // An interface without its device is meaningless and never sent.
    expect(toFlowFilters({ if: "3" }, false)).toEqual({});
    expect(serverFilterKeys({ device: "x", app: "y", type: "sflow" })).toEqual(["device"]);
  });

  it("validates what an operator types", () => {
    expect(checkAddress("10.1.2.3")).toBeNull();
    expect(checkAddress("10.1.0.0/16")).toBeNull();
    expect(checkAddress("fd00::/8")).toBeNull();
    expect(checkAddress("10.1.2.300")).not.toBeNull();
    expect(checkAddress("10.1.0.0/33")).not.toBeNull();
    expect(checkAddress("fd00::/129")).not.toBeNull();
    expect(checkAddress("10.0.0.0/8/9")).not.toBeNull();
    expect(checkAddress("host.example")).not.toBeNull();
    expect(checkAddress("")).not.toBeNull();
    expect(checkPort("443")).toBeNull();
    expect(checkPort("65536")).not.toBeNull();
    expect(checkPort("http")).not.toBeNull();
    expect([protoNumber("tcp"), protoNumber("UDP"), protoNumber("6"), protoNumber("256"), protoNumber("nope")]).toEqual(["6", "17", "6", null, null]);
    expect(protoName("17")).toBe("UDP (17)");
    expect(protoName("254")).toBe("Protocol 254");
  });

  it("shows chips by name and removes them one at a time", () => {
    const f = { device: "10.0.0.1", if: "3", ifDir: "in" as const, port: "443", proto: "6", type: "sflow", direction: "bi" as const, app: "S3" };
    expect(filterChips(f, { device: "edge-1 (10.0.0.1)", iface: "Gi0/3 (3)" }).map((c) => c.label)).toEqual([
      "Device: edge-1 (10.0.0.1)", "Interface: Gi0/3 (3) (entering)", "Port: 443", "Protocol: TCP (6)",
      "Source: sFlow", "Both directions as one", "Application: S3",
    ]);
    expect(withoutChip(f, "device")).toMatchObject({ device: undefined, if: undefined, ifDir: undefined, port: "443" });
    expect(withoutChip(f, "if")).toMatchObject({ device: "10.0.0.1", if: undefined, ifDir: undefined });
  });

  it("offers devices by name (exporters outside inventory by address) and interfaces by IF-MIB name", () => {
    const names = new Map([["d1", "edge-1"]]);
    expect(deviceOptions([dev("d1", "edge-1", "10.0.0.1"), dev("d2", "no-addr", "")], ["10.0.0.1", "192.0.2.9"], names)).toEqual([
      { value: "192.0.2.9", label: "192.0.2.9" },
      { value: "10.0.0.1", label: "edge-1 (10.0.0.1)" },
    ]);
    expect(interfaceOptions([inRow("10.0.0.1", "10", 1, "Gi0/10"), inRow("10.0.0.1", "2", 1, "Gi0/2"), inRow("10.0.0.2", "1", 1, "x")], [outRow("10.0.0.1", "7", 1)], "10.0.0.1")).toEqual([
      { value: "2", label: "Gi0/2 (2)" },
      { value: "10", label: "Gi0/10 (10)" },
      { value: "7", label: "Interface 7" },
    ]);
  });
});
