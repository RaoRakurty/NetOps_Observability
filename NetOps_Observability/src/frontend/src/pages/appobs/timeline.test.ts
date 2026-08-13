// timeline.test.ts — the event-timeline episode model (2026-07 UX defect #1).
// Acceptance: a repeated identical event collapses into ONE episode with a count
// and a first→last span; genuinely-distinct signals never merge; empty provider
// values normalize to "" so the UI can omit them honestly (no "— — (baseline —)").

import { describe, it, expect } from "vitest";
import { buildTimeline, cleanVal, isStateEvent, stateLabel, stateReason } from "./timeline";
import type { ChangeEvent, HealthSignal } from "./types";

const hs = (time: string, over: Partial<HealthSignal> = {}): HealthSignal => ({
  time, app: "correlix-demoapp", resource: "vm-1", signal: "cloud_resource_health",
  state: "down", metric: "", current: "", baseline: "—", severity: "critical", source: "aws", ...over,
});

describe("cleanVal", () => {
  it("normalizes provider empties to an empty string", () => {
    for (const v of ["", "—", "-", "null", "N/A", "none", "  ", undefined, null]) {
      expect(cleanVal(v as string)).toBe("");
    }
  });
  it("passes real values through, trimmed", () => {
    expect(cleanVal("  5xx ")).toBe("5xx");
    expect(cleanVal("down")).toBe("down");
  });
});

// The owner's finding: a CRITICAL Azure cloud_resource_health "down" row rendered
// empty metric / baseline / current. Those three describe a METRIC ANOMALY; a
// provider state event has none of them by design and its substance is the state
// + the provider's reasonType. The two kinds must be told apart and both must
// render something real.
describe("state events vs metric anomalies", () => {
  it("classifies a provider health-state event (no metric) as a state event", () => {
    expect(isStateEvent(hs("t", { metric: "" }))).toBe(true);
    // the backend sends "—" for a state event's absent metric
    expect(isStateEvent(hs("t", { metric: "—" }))).toBe(true);
  });
  it("classifies a metric anomaly as NOT a state event", () => {
    expect(isStateEvent(hs("t", { metric: "CPUUtilization" }))).toBe(false);
  });
  it("names the declared state in operator words", () => {
    expect(stateLabel("down")).toBe("Down");
    expect(stateLabel("degraded")).toBe("Degraded");
    expect(stateLabel("healthy")).toBe("Healthy");
    expect(stateLabel("unknown")).toBe("Unknown"); // never promoted
  });
  it("surfaces the provider's reasonType, and stays empty when it declared none", () => {
    expect(stateReason({ reason: "Customer Initiated" })).toBe("Customer Initiated");
    expect(stateReason({ reason: "" })).toBe("");
    expect(stateReason({ reason: undefined })).toBe("");
    expect(stateReason({ reason: "—" })).toBe(""); // provider empty, not a reason
  });
});

describe("buildTimeline", () => {
  it("carries state + reason on a state-event episode (never an empty triplet)", () => {
    const eps = buildTimeline([hs("2026-07-15T10:00:00.000Z", {
      metric: "", current: "", baseline: "", state: "down", reason: "Customer Initiated", source: "azure",
    })], []);
    expect(eps[0].stateEvent).toBe(true);
    expect(eps[0].state).toBe("down");
    expect(eps[0].reason).toBe("Customer Initiated");
  });

  it("leaves a metric anomaly's readings intact and does not mark it a state event", () => {
    const eps = buildTimeline([hs("2026-07-15T10:00:00.000Z", {
      metric: "CPUUtilization", current: "94%", baseline: "31%", state: "degraded",
    })], []);
    expect(eps[0].stateEvent).toBe(false);
    expect(eps[0].metric).toBe("CPUUtilization");
    expect(eps[0].current).toBe("94%");
    expect(eps[0].baseline).toBe("31%");
  });

  it("does NOT collapse a state run whose declared cause changed", () => {
    // same resource, same state — but the provider re-attributed the cause.
    // Collapsing would hide a real change of story.
    const t = (m: number) => new Date(Date.UTC(2026, 6, 15, 10, m, 0)).toISOString();
    const eps = buildTimeline([
      hs(t(0), { metric: "", reason: "Platform Initiated" }),
      hs(t(2), { metric: "", reason: "Customer Initiated" }),
    ], []);
    expect(eps).toHaveLength(2);
  });

  it("still collapses an identical state run that repeats the same cause", () => {
    const t = (m: number) => new Date(Date.UTC(2026, 6, 15, 10, m, 0)).toISOString();
    const eps = buildTimeline([
      hs(t(0), { metric: "", reason: "Customer Initiated" }),
      hs(t(2), { metric: "", reason: "Customer Initiated" }),
    ], []);
    expect(eps).toHaveLength(1);
    expect(eps[0].count).toBe(2);
  });
});

describe("buildTimeline", () => {
  it("collapses a consecutive run of identical events into one episode with a count + span", () => {
    // 22 identical 'down' reports, oldest→newest 2 minutes apart (the real defect).
    const health: HealthSignal[] = [];
    for (let i = 0; i < 22; i++) {
      const t = new Date(Date.UTC(2026, 6, 15, 10, i * 2, 0)).toISOString();
      health.push(hs(t));
    }
    const eps = buildTimeline(health, []);
    expect(eps).toHaveLength(1);
    expect(eps[0].count).toBe(22);
    expect(eps[0].firstSeen).toBe(health[0].time);            // earliest
    expect(eps[0].lastSeen).toBe(health[health.length - 1].time); // latest
    // resource identity + kind are surfaced (defect #1b)
    expect(eps[0].resource).toBe("vm-1");
    expect(eps[0].kind).toBe("down");
    // baseline "—" normalized away — no fabricated reading (defect #1c)
    expect(eps[0].current).toBe("");
    expect(eps[0].baseline).toBe("");
  });

  it("does NOT merge genuinely distinct signals on the same resource (different metric)", () => {
    const t1 = new Date(Date.UTC(2026, 6, 15, 10, 0, 0)).toISOString();
    const t2 = new Date(Date.UTC(2026, 6, 15, 10, 2, 0)).toISOString();
    const eps = buildTimeline([hs(t1, { metric: "cpu" }), hs(t2, { metric: "mem" })], []);
    expect(eps).toHaveLength(2);
  });

  it("only collapses CONSECUTIVE runs (A,B,A stays three episodes)", () => {
    const t = (m: number) => new Date(Date.UTC(2026, 6, 15, 10, m, 0)).toISOString();
    const eps = buildTimeline([
      hs(t(0), { resource: "vm-a" }),
      hs(t(2), { resource: "vm-b" }),
      hs(t(4), { resource: "vm-a" }),
    ], []);
    expect(eps).toHaveLength(3);
  });

  it("orders newest-first and merges health + change feeds", () => {
    const change: ChangeEvent = {
      time: new Date(Date.UTC(2026, 6, 15, 11, 0, 0)).toISOString(),
      app: "correlix-demoapp", resource: "sg-1", changeType: "security_policy_change",
      actor: "role/deployer", source: "cloudtrail", confidence: "confirmed", relatedSymptoms: [],
    };
    const health = hs(new Date(Date.UTC(2026, 6, 15, 10, 0, 0)).toISOString());
    const eps = buildTimeline([health], [change]);
    expect(eps).toHaveLength(2);
    expect(eps[0].kind).toBe("change");      // newest first
    expect(eps[0].detail).toBe("security policy change"); // humanized, no underscores
    expect(eps[0].actor).toBe("role/deployer");
  });
});
