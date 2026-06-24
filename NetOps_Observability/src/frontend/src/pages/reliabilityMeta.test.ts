import { describe, it, expect } from "vitest";
import { fmtDur, delayLabel, recommendedAction, offenderDisplay } from "./reliabilityMeta";

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
  it("enriches offender display names but keeps the raw id", () => {
    const a = offenderDisplay("app_path:api->clickhouse");
    expect(a.display).toBe("Correlix API → Flow Store");
    expect(a.secondary).toBe("api->clickhouse");

    const b = offenderDisplay("device:spine1");
    expect(b.display).toBe("DC Spine-1");

    // an ip:ip pair is honestly a "Path segment", not a fabricated circuit name
    const c = offenderDisplay("root_entity:10.70.245.120:192.168.100.5");
    expect(c.display).toBe("Path segment");
    expect(c.secondary).toBe("10.70.245.120:192.168.100.5");
  });
});
