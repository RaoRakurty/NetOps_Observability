// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { topProblemId, groundedToText, isCapabilityMiss, groundedChipLabel } from "./Opsis";
import type { AiAnswer } from "../services/api";

// A minimal current-state answer factory for the helper tests.
function currentState(over: Partial<AiAnswer> = {}): AiAnswer {
  return {
    mode: "current_state_summary",
    intent: "current_state",
    modules: ["command_center"],
    text: "25 active correlation(s): 1 confirmed, 7 suspected, 17 undetermined.",
    current_state: {
      summary: "",
      active_incidents: ["614896e5 — dia-egress (confirmed, 80%)"],
      confirmed: 1,
      suspected: 7,
      undetermined: 17,
      impacted_entities: ["leaf1", "wan-r2"],
      recommended_focus: ["614896e5 — dia-egress (confirmed, 80%)"],
      confidence_notes: [],
      missing_data: [],
    },
    citations: [
      { id: "problem:614896e5-1111-2222-3333-444455556666", kind: "finding", label: "dia-egress", href: "#/monitoring/correlations?id=614896e5-1111-2222-3333-444455556666" },
    ],
    disclaimers: [],
    provider: "none",
    ...over,
  };
}

describe("topProblemId", () => {
  it("resolves the recommended-focus problem's full id from its short id", () => {
    expect(topProblemId(currentState())).toBe("614896e5-1111-2222-3333-444455556666");
  });

  it("falls back to the first cited problem when focus doesn't match", () => {
    const ans = currentState({
      current_state: { ...currentState().current_state!, recommended_focus: [], active_incidents: [] },
    });
    expect(topProblemId(ans)).toBe("614896e5-1111-2222-3333-444455556666");
  });

  it("returns empty string when nothing is active", () => {
    const ans = currentState({ current_state: undefined, citations: [] });
    expect(topProblemId(ans)).toBe("");
  });

  it("ignores non-problem citations", () => {
    const ans = currentState({
      current_state: undefined,
      citations: [{ id: "nav:#/x", kind: "navigation", label: "x", href: "#/x" }],
    });
    expect(topProblemId(ans)).toBe("");
  });
});

describe("groundedToText", () => {
  // groundedToText is the chat-BUBBLE fallback = the model narrative only. The
  // counts / focus / evidence-only badges are rendered by the GroundedAnswer CARD
  // from the structured fields, never flattened into the text (no duplication).
  it("returns the narrative text", () => {
    const t = groundedToText(currentState());
    expect(t).toContain("25 active correlation");
  });

  it("gives an honest quiet-fleet line when there's no narrative", () => {
    const ans = currentState({ text: "", current_state: undefined, provider: "anthropic" });
    expect(groundedToText(ans)).toContain("fleet is quiet");
  });
});

// ── tracker 330: the two pure decisions behind the routing and the claim ─────
describe("isCapabilityMiss — the ONLY engine outcome eligible for the plain proxy", () => {
  it("is true for the capability clarification (the engine could not place it)", () => {
    expect(isCapabilityMiss(currentState({ mode: "unavailable", intent: "capability" }))).toBe(true);
  });

  it("is false for any real answer, however thin", () => {
    expect(isCapabilityMiss(currentState())).toBe(false);
    expect(isCapabilityMiss(currentState({ text: "", citations: [] }))).toBe(false);
  });

  it("is false for an access refusal or a not-built answer mode", () => {
    // "unavailable" also carries "no module is available for your access" and
    // "that answer mode isn't built yet". Neither may be re-answered by a
    // general model: one is an authorization decision, the other is honesty.
    expect(isCapabilityMiss(currentState({ mode: "unavailable", intent: "current_state" }))).toBe(false);
    expect(isCapabilityMiss(currentState({ mode: "unavailable", intent: "shift_handoff" }))).toBe(false);
  });
});

describe("groundedChipLabel — 'cited' is claimed only when there are citations", () => {
  it("claims cited when the answer carries citations", () => {
    expect(groundedChipLabel(currentState())).toMatch(/cited/);
  });

  it("drops the cited claim when the answer carries none", () => {
    const label = groundedChipLabel(currentState({ citations: [] }));
    expect(label).toMatch(/Grounded/);
    expect(label).not.toMatch(/cited/);
  });
});
