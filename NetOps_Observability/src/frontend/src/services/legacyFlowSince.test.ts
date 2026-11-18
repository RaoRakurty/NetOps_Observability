import { describe, expect, it } from "vitest";
import { legacyFlowSince } from "./api";

// Tracker 405: the older flow routes refuse a window outside 5 min – 30 days,
// so every caller's range is clamped to those bounds before it is sent.
describe("legacyFlowSince", () => {
  it("passes an in-range window through, rounded to whole seconds", () => {
    expect(legacyFlowSince(3600)).toBe(3600);
    expect(legacyFlowSince(900.4)).toBe(900);
  });
  it("clamps short and long section ranges to the route's bounds", () => {
    expect(legacyFlowSince(60)).toBe(300);
    expect(legacyFlowSince(0)).toBe(300);
    expect(legacyFlowSince(90 * 86_400)).toBe(30 * 86_400);
  });
  it("falls back to one hour for a value that is not a number", () => {
    expect(legacyFlowSince(Number.NaN)).toBe(3600);
  });
});
