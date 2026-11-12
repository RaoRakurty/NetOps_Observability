// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaPhrases.test.ts — the four fixed confidence phrases (owner D4, 2026-11-11)
// and the context-story test (D1). Mirrors backend/internal/noclabel/
// confidence_test.go so the RCA view, the PDF and Iris say the same thing.

import { describe, it, expect } from "vitest";
import {
  confidencePhrase, levelFor, phraseFor, isContextStory,
  RCA_SECTION_NAMES, HOW_TO_READ,
} from "./rcaPhrases";

describe("confidence phrases (owner D4)", () => {
  it.each([
    ["confirmed", "confirmed", "a WAN routing session flapping", "Confirmed cause"],
    ["suspected", "likely", "x", "Likely cause"],
    ["suspected", "suspected", "BGP peer down", "Possibly because of BGP peer down"],
    ["suspected", "suspected", "Routing adjacency change.", "Possibly because of routing adjacency change"],
    ["suspected", "suspected", "", "Cause not determined"],
    ["undetermined", "", "anything", "Cause not determined"],
    ["", "", "", "Cause not determined"],
    ["CONFIRMED", "", "", "Confirmed cause"],
    ["bogus", "bogus", "x", "Cause not determined"],
  ])("tier=%s label=%s cause=%s → %s", (tier, label, cause, want) => {
    expect(confidencePhrase(tier, label, cause)).toBe(want);
  });

  it("orders the levels strongest first and never prints a number", () => {
    expect(levelFor("confirmed", "")).toBe("confirmed");
    expect(levelFor("suspected", "likely")).toBe("likely");
    expect(levelFor("suspected", "")).toBe("suspected");
    expect(levelFor("undetermined", "")).toBe("undetermined");
    for (const l of ["confirmed", "likely", "suspected", "undetermined"] as const) {
      expect(phraseFor(l, "a fault")).not.toMatch(/%|engine confidence/i);
    }
  });
});

describe("context stories (owner D1)", () => {
  it("honours the engine flag and the pre-flag fallback ids", () => {
    expect(isContextStory("sig.ent.security.exposure-story")).toBe(true);
    expect(isContextStory("sig.ent.security.hardening-drift-story")).toBe(true);
    expect(isContextStory("sig.future.story", true)).toBe(true);
  });
  it("a dated detection story and causal templates are never background", () => {
    expect(isContextStory("sig.ent.security.threat-signal-story")).toBe(false);
    expect(isContextStory("sig.ent.wan-edge.bgp-peer-flap")).toBe(false);
    expect(isContextStory(undefined)).toBe(false);
  });
});

describe("the document contract", () => {
  it("has the ten sections in reading order", () => {
    expect(RCA_SECTION_NAMES).toEqual([
      "What broke", "Who is affected", "When", "Cause and how sure we are", "How we know",
      "Where the break is", "Background on this device (not a cause)", "Other explanations considered",
      "Who owns the fix", "What to do now · Watch for recurrence",
    ]);
  });
  it("the reading guide is six points and names the phrases and sections", () => {
    expect(HOW_TO_READ).toHaveLength(6);
    expect(HOW_TO_READ.join(" ")).toMatch(/Confirmed cause/);
    expect(HOW_TO_READ.join(" ")).toMatch(/Possibly because of X/);
    expect(HOW_TO_READ.join(" ")).toMatch(/red is a measured break and dotted is inferred/);
  });
});
