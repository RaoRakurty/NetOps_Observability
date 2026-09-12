// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { fidelityBadgeClass, fidelityLabel, fidelityRank, fidelityTitle, weakestFidelity } from "./fidelity";

// The tier table itself is pinned by pages/telemetry/coverageModel.test.ts (which
// imports it through that page's re-export). These tests cover the SHARED
// contract the RCA evidence rows added: the weakest-tier fold.

describe("weakestFidelity — a row is only as trustworthy as its least-proven rule", () => {
  it("returns the weakest tier in the group, not the strongest", () => {
    expect(weakestFidelity(["live_validated", "code"])).toBe("code");
    expect(weakestFidelity(["live_validated", "lab_validated"])).toBe("lab_validated");
    expect(weakestFidelity(["doc_claimed", "live_validated", "lab_validated"])).toBe("doc_claimed");
  });

  it("returns \"\" when nothing declared a fidelity — an absent grade is not a bad grade", () => {
    expect(weakestFidelity([])).toBe("");
    expect(weakestFidelity(["", "   "])).toBe("");
  });

  it("ignores blanks but keeps the graded values around them", () => {
    expect(weakestFidelity(["", "lab_validated", "  "])).toBe("lab_validated");
  });

  it("grades an unrecognised token BELOW code and passes it through verbatim", () => {
    expect(weakestFidelity(["live_validated", "wishful"])).toBe("wishful");
    expect(fidelityRank("wishful")).toBeLessThan(fidelityRank("code"));
    expect(fidelityLabel("wishful")).toBe("wishful");
    expect(fidelityBadgeClass("wishful")).toBe("badge tier-t5");
    expect(fidelityTitle("wishful")).toMatch(/treat as unproven/i);
  });
});
