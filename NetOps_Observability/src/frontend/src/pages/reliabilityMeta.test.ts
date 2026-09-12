// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import {
  fmtDur, delayLabel, recommendedAction, offenderDisplay,
  deriveCoverage, recoveryReadiness, pctlOrSample,
} from "./reliabilityMeta";

describe("reliabilityMeta", () => {
  it("formats durations", () => {
    expect(fmtDur(84000)).toBe("1m 24s");
    expect(fmtDur(undefined)).toBe("—");
    expect(fmtDur(0)).toBe("0 ms");
  });
  it("maps delay drivers to NOC labels", () => {
    expect(delayLabel("evidence_bundle")).toBe("Evidence Missing");
    expect(delayLabel("provider_repair")).toBe("Provider Repair Pending");
    expect(delayLabel("root_isolation")).toBe("Root Domain Unknown");
  });
  it("gives a recommended action per owner domain", () => {
    expect(recommendedAction("ISP")).toMatch(/Escalate carrier/);
    expect(recommendedAction("Cloud")).toMatch(/route table/);
    expect(recommendedAction("Unknown")).toMatch(/missing evidence/);
  });
  it("object-aware recommended actions", () => {
    expect(recommendedAction("Cloud", "app_path:api->x")).toMatch(/route tables/);
    expect(recommendedAction("LAN", "device:wan-r2")).toMatch(/WAN interface errors, BGP\/BFD/);
    expect(recommendedAction("LAN", "device:spine1")).toMatch(/uplink errors.*ECMP/);
    expect(recommendedAction("LAN", "root_entity:10.0.0.1:10.0.0.2")).toMatch(/path endpoints/);
    expect(recommendedAction("LAN", "device:leaf1")).toMatch(/optic health, link flaps/);
  });

  it("never renders 0 ms for a no-sample percentile", () => {
    expect(pctlOrSample(0)).toBeNull();      // → caller shows "No valid sample"
    expect(pctlOrSample(undefined)).toBeNull();
    expect(pctlOrSample(84000)).toBe("1m 24s");
  });

  it("evidence coverage reflects which phases are measured", () => {
    const c = deriveCoverage({ ttc: true, tti: true, recovery: false, ticketing: false });
    expect(c.correlation).toBe("connected");
    expect(c.isolation).toBe("connected");
    expect(c.recovery).toBe("missing");
    expect(c.ticketing).toBe("missing");
  });

  it("readiness: high repeat + missing evidence → At Risk; clean → Healthy", () => {
    const atRisk = recoveryReadiness({
      repeatRate: 0.94, topDelay: "evidence_bundle",
      coverage: { correlation: "connected", isolation: "connected", recovery: "missing", ticketing: "missing" },
      mttiP90Ms: 30 * 60 * 1000 + 1, offenderCount: 10,
    });
    expect(atRisk.state).toBe("At Risk");
    expect(atRisk.score).toBeLessThan(55);

    const healthy = recoveryReadiness({
      repeatRate: 0.05, topDelay: "resolved",
      coverage: { correlation: "connected", isolation: "connected", recovery: "connected", ticketing: "connected" },
      mttiP90Ms: 5 * 60 * 1000, offenderCount: 0,
    });
    expect(healthy.state).toBe("Healthy");
    expect(healthy.score).toBeGreaterThanOrEqual(75);
  });

  it("enriches offender display names but keeps the raw id", () => {
    const a = offenderDisplay("app_path:api->clickhouse");
    expect(a.display).toBe("Correlix API → Flow Store");
    expect(a.secondary).toBe("api->clickhouse");

    const b = offenderDisplay("device:spine1");
    expect(b.display).toBe("DC Spine-1");

    // an ip:ip pair is honestly a "Path segment", not a fabricated circuit name
    const c = offenderDisplay("root_entity:192.0.2.120:192.168.100.5");
    expect(c.display).toBe("Path segment");
    expect(c.secondary).toBe("192.0.2.120:192.168.100.5");
  });
});
