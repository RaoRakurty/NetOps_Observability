// sortRanks.test.ts — semantic ordering for the Cloud Service View tables
// (2026-07 UX defect #2). Ascending sort must surface the most urgent / strongest
// row first, not alphabetical noise.

import { describe, it, expect } from "vitest";
import { healthRank, confidenceRank, verdictRank, timeRank } from "./sortRanks";

describe("healthRank", () => {
  it("orders worst-first: down < degraded < unknown < healthy", () => {
    expect(healthRank("down")).toBeLessThan(healthRank("degraded"));
    expect(healthRank("degraded")).toBeLessThan(healthRank("unknown"));
    expect(healthRank("unknown")).toBeLessThan(healthRank("healthy"));
  });
});

describe("confidenceRank", () => {
  it("orders strongest-first: confirmed < strong < suspected < weak < unknown", () => {
    const order = ["confirmed", "strong", "suspected", "weak", "unknown"] as const;
    for (let i = 1; i < order.length; i++) {
      expect(confidenceRank(order[i - 1])).toBeLessThan(confidenceRank(order[i]));
    }
  });
});

describe("verdictRank", () => {
  it("orders confirmed before undetermined; unknown tiers sort last", () => {
    expect(verdictRank("confirmed")).toBeLessThan(verdictRank("suspected"));
    expect(verdictRank("suspected")).toBeLessThan(verdictRank("undetermined"));
    expect(verdictRank("garbage")).toBeGreaterThan(verdictRank("undetermined"));
  });
});

describe("timeRank", () => {
  it("returns epoch ms so times sort chronologically", () => {
    const a = timeRank("2026-07-15T10:00:00Z");
    const b = timeRank("2026-07-15T10:02:00Z");
    expect(a).toBeLessThan(b);
  });
  it("treats a missing/invalid time as oldest", () => {
    expect(timeRank(undefined)).toBe(0);
    expect(timeRank("not-a-date")).toBe(0);
  });
});
