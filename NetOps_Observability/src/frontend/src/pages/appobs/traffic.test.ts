// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// traffic.test.ts — per-service app-edge traffic from the cloud LB plane.
//
// Acceptance: the gateway-5xx count is real and complete (every ELB-side 5xx is
// a signal); only GROUNDED observations count; a quiet window is an honest zero
// rather than a blank; and we never manufacture the throughput/rate denominator
// that the log pipeline does not store.

import { describe, it, expect } from "vitest";
import { isLbErrorSignal, lbTraffic, EMPTY_TRAFFIC } from "./traffic";
import type { EvidenceRow } from "./types";

const NOW = Date.UTC(2026, 6, 15, 12, 0, 0);
const agoMin = (m: number) => new Date(NOW - m * 60_000).toISOString();

const ev = (over: Partial<EvidenceRow> = {}): EvidenceRow => ({
  time: agoMin(5), category: "grounded", signalType: "cloud_lb_log",
  app: "billing", resource: "alb-prod (app/alb/0a1)", source: "aws",
  confidence: "confirmed", reason: "ELB-side 5xx", grounded: true,
  rcaGroup: "cid-1", evidenceRef: "sig-1", ...over,
});

describe("isLbErrorSignal", () => {
  it("recognises every producer that emits an app-edge 5xx", () => {
    for (const k of ["cloud_lb_log", "lb_5xx", "alb_5xx", "synthetic_http_5xx"]) {
      expect(isLbErrorSignal(k)).toBe(true);
    }
  });
  it("does not treat unrelated cloud signals as traffic errors", () => {
    for (const k of ["cloud_health", "cloud_resource_health", "cloud_change", "cloud_flow_log", ""]) {
      expect(isLbErrorSignal(k)).toBe(false);
    }
  });
});

describe("lbTraffic", () => {
  it("counts the gateway 5xx a service actually suffered in the window", () => {
    const t = lbTraffic([ev(), ev({ evidenceRef: "sig-2", time: agoMin(20) })], 60, NOW);
    expect(t.errors).toBe(2);
    expect(t.newest).toBe(agoMin(5));
    expect(t.resources).toEqual(["alb-prod (app/alb/0a1)"]);
  });

  it("honours the selected range — a torn-down lab reads zero, not stale", () => {
    // the owner's exact situation: the cloud hosts stopped ~2h ago, so a 1h
    // window legitimately holds nothing while 24h still shows the real events.
    const rows = [ev({ time: agoMin(125) })];
    expect(lbTraffic(rows, 60, NOW)).toEqual(EMPTY_TRAFFIC);
    expect(lbTraffic(rows, 1440, NOW).errors).toBe(1);
  });

  it("ignores a declared gap — the engine naming what it lacks is not an observation", () => {
    const t = lbTraffic([ev({ category: "missing", grounded: false })], 60, NOW);
    expect(t.errors).toBe(0);
  });

  it("ignores non-traffic signals attached to the same service", () => {
    const t = lbTraffic([ev({ signalType: "cloud_resource_health" }), ev({ evidenceRef: "s2" })], 60, NOW);
    expect(t.errors).toBe(1);
  });

  it("dedupes the reporting load balancers", () => {
    const t = lbTraffic([
      ev({ evidenceRef: "s1", resource: "alb-a" }),
      ev({ evidenceRef: "s2", resource: "alb-a" }),
      ev({ evidenceRef: "s3", resource: "alb-b" }),
    ], 60, NOW);
    expect(t.errors).toBe(3);
    expect(t.resources).toEqual(["alb-a", "alb-b"]);
  });
});
