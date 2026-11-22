// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// measuredFold.test.ts — which measured path belongs to which Paths row, and
// what a path's state is. The Measured paths tab was retired on 2026-11-22
// because it showed a path apart from the circuit or tunnel it measured; these
// are the rules that put each path back on its row.

import { describe, it, expect } from "vitest";
import type { Device, PathHealthItem, ProbePath } from "../../services/api";
import {
  buildMeasuredIndex, destText, hopsText, hostOf, roleText, tunnelRowPaths, unclaimedPaths,
  verdictOf, verdictText, wanRowPaths,
} from "./measuredFold";

const hop = (ttl: number, ip: string, loss = 0) => ({ ttl, ip, rtt_ms: ip ? ttl * 2 : undefined, loss_pct: ip ? loss : undefined });

function path(over: Partial<ProbePath> = {}): ProbePath {
  return {
    dst: "192.168.222.105", method: "icmp", vantage_id: "v1", site: "Branch 40", reached: true, changed: false,
    ts: "2026-11-22T10:00:00Z", hops: [hop(1, "10.0.0.1"), hop(2, "10.0.0.2"), hop(3, "192.168.222.105")], ...over,
  };
}

function health(dst: string, state: PathHealthItem["health_state"]): PathHealthItem {
  return {
    path_id: dst, agent: "traceroute", dst, health_state: state, score: 0, confidence: "high",
    severities: {}, baseline_source: "path", reason: "", likely_fault_domain: "isp_carrier", evidence: [],
    current: { latency_p95_5m: 10, jitter_p95_5m: 1, loss_pct_5m: 0 },
    baseline: { source: "path", source_label: "its own week", window: "7d", sample_count: 10, latency_p50: 5, latency_p99: 20, jitter_p50: 1, jitter_p99: 3 },
  };
}

const dev = (name: string, address: string): Device => ({ id: `${name}-id`, name, address, source: "snmp", last_seen: "" });

describe("hostOf", () => {
  it("strips a port, brackets and case, and leaves a bare IPv6 address whole", () => {
    expect(hostOf(" 10.0.0.1:443 ")).toBe("10.0.0.1");
    expect(hostOf("[2001:DB8::1]:443")).toBe("2001:db8::1");
    expect(hostOf("2001:db8::1")).toBe("2001:db8::1");
    expect(hostOf("Edge.Example")).toBe("edge.example");
    expect(hostOf(undefined)).toBe("");
  });
});

describe("the verdict, worst first", () => {
  it("unreached beats loss beats a changed route beats degraded health", () => {
    expect(verdictOf(path({ reached: false, hops: [hop(1, "10.0.0.1"), hop(2, "")] }))).toBe("unreached");
    expect(verdictOf(path({ hops: [hop(1, "10.0.0.1"), hop(2, "10.0.0.2", 20), hop(3, "192.168.222.105", 25)], changed: true }))).toBe("loss");
    expect(verdictOf(path({ changed: true }))).toBe("changed");
    expect(verdictOf(path(), health("192.168.222.105", "degraded"))).toBe("degraded");
    expect(verdictOf(path(), health("192.168.222.105", "healthy"))).toBe("ok");
  });

  it("does not call one router's rate limiting loss on the path", () => {
    // Loss at hop 2 that hop 3 does not show is that router declining to answer.
    expect(verdictOf(path({ hops: [hop(1, "10.0.0.1"), hop(2, "10.0.0.2", 60), hop(3, "192.168.222.105", 0)] }))).toBe("ok");
  });

  it("names the hop loss starts from, by its TTL", () => {
    const idx = buildMeasuredIndex([path({ hops: [hop(1, "10.0.0.1"), hop(2, "10.0.0.2", 20), hop(3, "192.168.222.105", 25)] })], [], []);
    expect(verdictText(idx.all[0])).toEqual({ text: "Loss from hop 2", tone: "warn" });
    expect(hopsText(idx.all[0])).toBe("3 hops");
  });

  it("reads severe health as bad and a clean trace as Reached", () => {
    const sev = buildMeasuredIndex([path()], [health("192.168.222.105", "severe")], []);
    expect(verdictText(sev.all[0])).toEqual({ text: "Severe", tone: "bad" });
    const ok = buildMeasuredIndex([path()], [], []);
    expect(verdictText(ok.all[0])).toEqual({ text: "Reached", tone: "good" });
  });
});

describe("the index", () => {
  it("names a destination by the one visible device at that address", () => {
    const idx = buildMeasuredIndex([path()], [], [dev("cedge-40", "192.168.222.105")]);
    expect(idx.all[0].device).toBe("cedge-40");
    expect(destText(idx.all[0])).toBe("cedge-40 (192.168.222.105)");
    expect(idx.byDevice.get("cedge-40")?.length).toBe(1);
  });

  it("names nobody when two visible devices share the address", () => {
    const idx = buildMeasuredIndex([path()], [], [dev("cedge-40", "192.168.222.105"), dev("other", "192.168.222.105")]);
    expect(idx.all[0].device).toBeUndefined();
    expect(idx.byDevice.size).toBe(0);
    expect(destText(idx.all[0])).toBe("192.168.222.105");
  });

  it("keeps the paths when health and inventory could not be read", () => {
    const idx = buildMeasuredIndex([path()], null, undefined);
    expect(idx.all).toHaveLength(1);
    expect(idx.byDst.get("192.168.222.105")).toHaveLength(1);
  });

  it("tolerates a non-array body and skips a path with no destination", () => {
    expect(buildMeasuredIndex({} as unknown as ProbePath[], [], []).all).toEqual([]);
    expect(buildMeasuredIndex([path({ dst: "" })], [], []).all).toEqual([]);
  });

  it("keeps two methods to one destination as two paths, and drops an exact repeat", () => {
    const idx = buildMeasuredIndex([path(), path({ method: "tcp" }), path()], [], []);
    expect(idx.all).toHaveLength(2);
  });

  it("orders worst first", () => {
    const idx = buildMeasuredIndex([path({ dst: "10.1.1.1" }), path({ dst: "10.2.2.2", reached: false })], [], []);
    expect(idx.all.map((m) => m.verdict)).toEqual(["unreached", "ok"]);
  });
});

describe("a WAN circuit row's paths", () => {
  const idx = buildMeasuredIndex(
    [path({ dst: "203.0.113.1" }), path({ dst: "192.168.222.105", reached: false, hops: [hop(1, "10.0.0.1")] })],
    [],
    [dev("wan-edge-1", "192.168.222.105")],
  );

  it("claims the path to its measurement target and the path to its router, worst first", () => {
    const got = wanRowPaths(idx, { device: "wan-edge-1", target: "203.0.113.1", has_target: true });
    expect(got.map((a) => [a.role, a.m.dst])).toEqual([["router", "192.168.222.105"], ["target", "203.0.113.1"]]);
    expect(roleText(got[0])).toBe("To the router");
    expect(roleText(got[1])).toBe("To the measurement target");
  });

  it("matches the router by name without regard to case", () => {
    expect(wanRowPaths(idx, { device: "WAN-EDGE-1" }).map((a) => a.role)).toEqual(["router"]);
  });

  it("claims nothing for a row with no target and no traced router", () => {
    expect(wanRowPaths(idx, { device: "spine-1", target: "203.0.113.1", has_target: false })).toEqual([]);
    expect(wanRowPaths(null, { device: "wan-edge-1", target: "203.0.113.1" })).toEqual([]);
  });

  it("claims a path once even when it is both the target and the router", () => {
    const one = buildMeasuredIndex([path()], [], [dev("wan-edge-1", "192.168.222.105")]);
    expect(wanRowPaths(one, { device: "wan-edge-1", target: "192.168.222.105" }).map((a) => a.role)).toEqual(["target"]);
  });
});

describe("a tunnel row's paths", () => {
  const idx = buildMeasuredIndex(
    [path({ dst: "192.168.222.105" }), path({ dst: "192.168.222.200", changed: true })],
    [],
    [dev("cedge-40", "192.168.222.105"), dev("vedge-100", "192.168.222.200")],
  );

  it("claims the path to the device at either end", () => {
    const got = tunnelRowPaths(idx, { a: { device: "cedge-40" }, b: { device: "vedge-100" } });
    expect(got.map((a) => a.role)).toEqual(["end-b", "end-a"]);
    expect(roleText(got[0], { a: "cedge-40", b: "vedge-100" })).toBe("To End B (vedge-100)");
  });

  it("falls back to the row's local and remote device on an IPsec/GRE row", () => {
    expect(tunnelRowPaths(idx, { local_device: "cedge-40", remote_device: "none" }).map((a) => a.role)).toEqual(["end-a"]);
  });
});

describe("paths no row claims", () => {
  it("are listed apart, worst first, and say where they go", () => {
    const idx = buildMeasuredIndex([path({ dst: "8.8.8.8" }), path({ dst: "1.1.1.1", reached: false })], [], []);
    const claimed = new Set(wanRowPaths(idx, { device: "x", target: "8.8.8.8" }).map((a) => a.m.key));
    const rest = unclaimedPaths(idx, claimed);
    expect(rest.map((m) => m.dst)).toEqual(["1.1.1.1"]);
    expect(roleText({ m: rest[0], role: "other" })).toBe("To 1.1.1.1");
    expect(unclaimedPaths(null, new Set())).toEqual([]);
  });
});
