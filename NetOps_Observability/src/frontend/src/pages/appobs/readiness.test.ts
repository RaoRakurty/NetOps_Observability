// readiness.test.ts — the honest data-readiness core (#81 P3F+1). Proves the
// trust rules: only inventory is real today, missing sources are "off" not
// healthy, missing values are "not measured" not 0, and no label ever says "mock".

import { describe, it, expect } from "vitest";
import {
  deriveDataMode, DATA_MODE_LABEL, deriveReadiness, summarize, deriveScope,
  getMeasurementState, isMeasured, deriveHealthFromAvailableSignals, freshnessLabel,
  SOURCE_TYPES,
} from "./readiness";

describe("data mode", () => {
  it("is live only with a real connector", () => {
    expect(deriveDataMode({ inventoryCount: 5, connector: "live" })).toBe("live");
  });
  it("is demo when fixtures are present (no live connector)", () => {
    expect(deriveDataMode({ inventoryCount: 5, connector: "fixture" })).toBe("demo");
  });
  it("is empty when nothing is connected", () => {
    expect(deriveDataMode({ inventoryCount: 0, connector: "none" })).toBe("empty");
  });
  it("never uses the word 'mock' in any label", () => {
    for (const label of Object.values(DATA_MODE_LABEL)) {
      expect(label.toLowerCase()).not.toContain("mock");
    }
  });
});

describe("deriveReadiness — only inventory is real", () => {
  it("inventory flowing when present, the rest off", () => {
    const r = deriveReadiness({ inventoryCount: 12, inventoryError: false });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("flowing");
    expect(r.filter((x) => x.sourceType !== "inventory").every((x) => x.status === "off")).toBe(true);
    expect(r).toHaveLength(SOURCE_TYPES.length);
  });
  it("inventory no_data when empty (honest, not healthy)", () => {
    const r = deriveReadiness({ inventoryCount: 0, inventoryError: false });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("no_data");
  });
  it("inventory off on load error", () => {
    const r = deriveReadiness({ inventoryCount: 0, inventoryError: true });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("off");
  });
});

describe("summarize", () => {
  it("counts flowing/off and carries account count", () => {
    const r = deriveReadiness({ inventoryCount: 3, inventoryError: false, lastSyncIso: "2026-06-25T00:00:00Z" });
    const s = summarize(r, 2);
    expect(s.connectedAccounts).toBe(2);
    expect(s.flowing).toBe(1); // only inventory
    expect(s.off).toBe(SOURCE_TYPES.length - 1);
    expect(s.lastSyncIso).toBe("2026-06-25T00:00:00Z");
  });
});

describe("deriveScope", () => {
  it("shows a single value verbatim and many as a count", () => {
    const s = deriveScope(
      [
        { provider: "aws", account: "111", region: "us-east-1", env: "prod" },
        { provider: "aws", account: "222", region: "us-west-2", env: "prod" },
      ],
      "Retail-US",
    );
    expect(s.tenant).toBe("Retail-US");
    expect(s.provider).toBe("AWS"); // single provider, upper-cased
    expect(s.account).toBe("2 accounts"); // many
    expect(s.region).toBe("2 regions");
    expect(s.env).toBe("prod"); // single
  });
  it("handles an empty inventory honestly", () => {
    const s = deriveScope([], "t1");
    expect(s.provider).toBe("—");
    expect(s.account).toBe("—");
  });
});

describe("measurement state", () => {
  it("flowing/stale are measured; off/no_data/undefined are not", () => {
    expect(isMeasured("flowing")).toBe(true);
    expect(isMeasured("stale")).toBe(true);
    expect(isMeasured("off")).toBe(false);
    expect(isMeasured(undefined)).toBe(false);
  });
  it("maps status to a display state", () => {
    expect(getMeasurementState("flowing")).toBe("ok");
    expect(getMeasurementState("stale")).toBe("stale");
    expect(getMeasurementState("permission_denied")).toBe("permission_denied");
    expect(getMeasurementState("off")).toBe("not_measured");
    expect(getMeasurementState("no_data")).toBe("not_measured");
  });
});

describe("deriveHealthFromAvailableSignals — never fake healthy", () => {
  it("returns raw health when the health source is measured", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "flowing", anyMeasured: true })).toBe("healthy");
  });
  it("cloud health off + other signals ⇒ partial data, not healthy", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "off", anyMeasured: true })).toBe("partial");
  });
  it("cloud health off + nothing measured ⇒ not measured", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "off", anyMeasured: false })).toBe("not_measured");
  });
  it("a real problem on another signal is preserved even with no health source", () => {
    expect(deriveHealthFromAvailableSignals("down", { health: "off", anyMeasured: false })).toBe("down");
    expect(deriveHealthFromAvailableSignals("degraded", { health: "off", anyMeasured: true })).toBe("degraded");
  });
});

describe("freshnessLabel", () => {
  const now = new Date("2026-06-25T12:00:00Z").getTime();
  it("renders seconds / minutes / dash", () => {
    expect(freshnessLabel(undefined, now)).toBe("—");
    expect(freshnessLabel("2026-06-25T11:59:18Z", now)).toBe("42s ago");
    expect(freshnessLabel("2026-06-25T11:57:00Z", now)).toBe("3m ago");
    expect(freshnessLabel("2026-06-25T11:59:59Z", now)).toBe("just now");
  });
});
