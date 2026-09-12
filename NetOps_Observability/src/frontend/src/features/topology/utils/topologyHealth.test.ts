// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { fmtUtil } from "./topologyHealth";

describe("fmtUtil — operator-readable link utilization", () => {
  it("collapses a long raw VM ratio to a tiny-but-readable value", () => {
    expect(fmtUtil(0.00003984453955175126)).toBe("<0.1%"); // was the 20-digit bug
  });
  it("rounds sensibly across the range", () => {
    expect(fmtUtil(0)).toBe("0%");
    expect(fmtUtil(8.04)).toBe("8.0%"); // under 10% → one decimal
    expect(fmtUtil(12.37)).toBe("12%"); // at/above 10% → whole percent
    expect(fmtUtil(86.6)).toBe("87%");
    expect(fmtUtil(100)).toBe("100%");
  });
  it("is honest about no/garbage data — never a fake number", () => {
    expect(fmtUtil(null)).toBe("—");
    expect(fmtUtil(undefined)).toBe("—");
    expect(fmtUtil(NaN)).toBe("—");
    expect(fmtUtil(Infinity)).toBe("—");
  });
});
