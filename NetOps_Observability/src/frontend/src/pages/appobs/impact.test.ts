// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// impact.ts — the degraded-services strip logic: duration from the FIRST
// degraded signal, worst-first ordering (down → criticality → longest), blast
// radius counted from the signals, and honest "unknown" when nothing measured it.

import { describe, it, expect } from "vitest";
import type { BusinessServiceRow } from "../../services/api";
import type { App, CloudResource, HealthSignal } from "./types";
import { buildDegradedRows, fmtDuration } from "./impact";

const NOW = Date.parse("2026-07-17T12:00:00Z");
const iso = (minAgo: number) => new Date(NOW - minAgo * 60000).toISOString();

const app = (over: Partial<App>): App => ({
  id: "a", name: "payments", health: "unknown", owner: "—", env: "—",
  confidence: "confirmed", source: "cloud_tag", provider: "aws", providers: ["aws"],
  account: "—", region: "—", resources: 0, trafficBps: -1, errorPct: -1, p95ms: -1,
  unknownPct: -1, lastSeen: iso(0), primarySymptom: "—", rootDomain: "unknown",
  underlayImpacted: false,
  ...over,
});
const sig = (over: Partial<HealthSignal>): HealthSignal => ({
  time: iso(30), app: "payments", resource: "web01", signal: "alb_5xx",
  state: "degraded", metric: "", current: "", baseline: "", severity: "warning",
  source: "cloudwatch_alarm",
  ...over,
});
const res = (over: Partial<CloudResource>): CloudResource => ({
  id: "r", name: "web01", type: "VM", provider: "aws", account: "1", region: "us-east-1",
  app: "payments", owner: "—", env: "—", source: "cloud_tag", confidence: "confirmed",
  health: "unknown", powerState: "running", trafficBps: -1, lastSeen: iso(0),
  missingTags: [],
  ...over,
});
const cat = (over: Partial<BusinessServiceRow>): BusinessServiceRow => ({
  business_service_id: "b1", tenant_id: "t", name: "payments", description: "",
  criticality: "critical", owner: "payments-sre", created_by: "u",
  created_at: "", updated_at: "",
  ...over,
});

describe("fmtDuration", () => {
  it("renders coarse human durations", () => {
    expect(fmtDuration(0)).toBe("");
    expect(fmtDuration(30_000)).toBe("<1m");
    expect(fmtDuration(5 * 60000)).toBe("5m");
    expect(fmtDuration(135 * 60000)).toBe("2h 15m");
    expect(fmtDuration(50 * 3600_000)).toBe("2d 2h");
  });
});

describe("buildDegradedRows", () => {
  it("computes duration from the FIRST degraded signal and blast radius from distinct resources", () => {
    const rows = buildDegradedRows(
      [app({})],
      [sig({ time: iso(120), resource: "web01" }), sig({ time: iso(10), resource: "web02" })],
      [res({ id: "r1", name: "web01" }), res({ id: "r2", name: "web02" }), res({ id: "r3", name: "db01" })],
      [cat({})],
      NOW,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].durationMs).toBe(120 * 60000);
    expect(rows[0].affected).toBe(2);
    expect(rows[0].total).toBe(3);
    expect(rows[0].criticality).toBe("critical");
    expect(rows[0].owner).toBe("payments-sre");
  });

  it("orders worst first: down before degraded, then catalog criticality, then longest", () => {
    const rows = buildDegradedRows(
      [],
      [
        sig({ app: "checkout", state: "degraded", time: iso(300) }),
        sig({ app: "payments", state: "down", time: iso(5) }),
        sig({ app: "reports", state: "degraded", time: iso(600) }),
      ],
      [],
      [cat({ name: "checkout", criticality: "critical" }), cat({ business_service_id: "b2", name: "reports", criticality: "low" })],
      NOW,
    );
    expect(rows.map((r) => r.name)).toEqual(["payments", "checkout", "reports"]);
  });

  it("live app health with no signal row → degraded with honest unknown duration/extent", () => {
    const rows = buildDegradedRows([app({ name: "crm", health: "degraded", resources: 4 })], [], [], [], NOW);
    expect(rows).toHaveLength(1);
    expect(rows[0].sinceIso).toBe("");
    expect(rows[0].durationMs).toBe(0);
    expect(rows[0].affected).toBe(0);
    expect(rows[0].total).toBe(4); // falls back to the app's resource count
    expect(rows[0].criticality).toBe(""); // not in the catalog — never assumed
  });

  it("healthy inputs produce no rows", () => {
    expect(buildDegradedRows([app({ health: "healthy" })], [sig({ state: "healthy" })], [], [], NOW)).toHaveLength(0);
  });
});
