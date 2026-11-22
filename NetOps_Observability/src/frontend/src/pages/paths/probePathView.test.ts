// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { ProbePath } from "../../services/api";
import { firstLossIndex, probePathToView } from "./probePathView";

const path = (hops: ProbePath["hops"], over: Partial<ProbePath> = {}): ProbePath => ({
  dst: "10.9.9.9", hops, reached: true, changed: false, ts: "2026-11-21T10:00:00Z", vantage_id: "v1", ...over,
});
const hop = (ttl: number, ip: string, rtt?: number, loss?: number) => ({ ttl, ip, rtt_ms: rtt, loss_pct: loss });

describe("firstLossIndex", () => {
  it("no loss anywhere → none", () => {
    expect(firstLossIndex(path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.9.9.9", 5, 0)]))).toBe(-1);
  });

  it("loss that persists to the end starts at its first hop", () => {
    const p = path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.0.0.2", 2, 20), hop(3, "10.9.9.9", 5, 25)]);
    expect(firstLossIndex(p)).toBe(1);
  });

  it("loss at one hop that later hops do not show is rate limiting, not path loss", () => {
    const p = path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.0.0.2", 2, 60), hop(3, "10.9.9.9", 5, 0)]);
    expect(firstLossIndex(p)).toBe(-1);
  });

  it("a hop that does not answer between lossy hops does not break the run", () => {
    const p = path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.0.0.2", 2, 10), hop(3, ""), hop(4, "10.9.9.9", 5, 10)]);
    expect(firstLossIndex(p)).toBe(1);
  });

  it("an unreached path is marked where the answers stop", () => {
    const p = path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.0.0.2", 2, 0), hop(3, ""), hop(4, "")], { reached: false });
    expect(firstLossIndex(p)).toBe(2);
  });

  it("an empty path has nothing to mark", () => {
    expect(firstLossIndex(path([], { reached: false }))).toBe(-1);
  });
});

describe("probePathToView", () => {
  it("is a measured path: prober first, every hop in order", () => {
    const v = probePathToView(path([hop(1, "10.0.0.1", 1.5, 0), hop(2, "10.9.9.9", 5, 0)]));
    expect(v.path_source).toBe("measured");
    expect(v.path).toEqual(v.nodes.map((n) => n.id));
    expect(v.nodes.map((n) => n.label)).toEqual(["Prober v1", "10.0.0.1", "10.9.9.9"]);
    expect(v.nodes[1].metrics).toEqual({ trace_rtt_ms: 1.5, trace_loss_pct: 0 });
    expect(v.edges).toHaveLength(2);
    expect(v.edges.every((e) => e.evidence.length > 0)).toBe(true);
  });

  it("a hop that did not answer is unresolved, with no name or number of its own", () => {
    const v = probePathToView(path([hop(1, "10.0.0.1", 1, 0), hop(2, "", 9, 50), hop(3, "10.9.9.9", 5, 0)]));
    const silent = v.nodes[2];
    expect(silent.label).toBe("No reply");
    expect(silent.kind).toBe("unresolved");
    expect(silent.metrics).toEqual({});
    expect(silent.health).toBe("unknown");
  });

  it("marks the first-loss hop and the link into it", () => {
    const v = probePathToView(path([hop(1, "10.0.0.1", 1, 0), hop(2, "10.0.0.2", 2, 20), hop(3, "10.9.9.9", 5, 25)]));
    const loss = v.nodes[2];
    expect(loss.health).toBe("warning");
    expect(loss.issues?.[0].summary).toBe("Loss starts here");
    const into = v.edges.find((e) => e.target === loss.id);
    expect(into?.status).toBe("degraded");
    expect(v.edges.filter((e) => e.status === "degraded")).toHaveLength(1);
  });

  it("an unreached target is drawn after the last hop, unresolved", () => {
    const v = probePathToView(path([hop(1, "10.0.0.1", 1, 0), hop(2, "")], { reached: false }));
    const last = v.nodes[v.nodes.length - 1];
    expect(last.id).toBe("target");
    expect(last.label).toBe("10.9.9.9");
    expect(last.resolved).toBe(false);
  });

  it("node ids are unique even when a router answers twice", () => {
    const v = probePathToView(path([hop(1, "10.0.0.1"), hop(2, "10.0.0.1"), hop(3, "10.9.9.9")]));
    expect(new Set(v.nodes.map((n) => n.id)).size).toBe(v.nodes.length);
  });
});
