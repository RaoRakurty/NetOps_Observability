// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, afterEach, vi } from "vitest";
import {
  applyRecommended,
  answerFootnote,
  bannerState,
  shouldLandOnConnect,
  testResultText,
  readDismissed,
  writeDismissed,
  CONNECT_DISMISSED_KEY,
  CONNECT_ROUTE,
  PROVIDER_ORDER,
} from "./connectModel";

const rec = {
  gemini: { default: "gemini-flash-latest", fast: "gemini-flash-lite-latest", strong: "gemini-flash-latest" },
  anthropic: { default: "claude-sonnet-4-6", fast: "claude-haiku-4-5", strong: "claude-opus-4-8" },
};

describe("connectModel", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    try { localStorage.clear(); } catch { /* none */ }
  });

  it("gemini is first (D6)", () => {
    expect(PROVIDER_ORDER[0]).toBe("gemini");
  });

  it("a provider choice fills all three recommended models (C2)", () => {
    expect(applyRecommended("anthropic", rec)).toEqual({ provider: "anthropic", model: "claude-sonnet-4-6", model_fast: "claude-haiku-4-5", model_strong: "claude-opus-4-8" });
    // Unknown recommendation: keep what was typed.
    expect(applyRecommended("openai", rec, { model: "gpt-x", model_fast: "", model_strong: "" })).toEqual({ provider: "openai", model: "gpt-x", model_fast: "", model_strong: "" });
    expect(applyRecommended("gemini", undefined).model).toBe("");
  });

  it("test verdicts are plain words per closed error class", () => {
    expect(testResultText({ ok: true, latency_ms: 840, model: "gemini-flash-lite-latest" })).toBe("Connected to gemini-flash-lite-latest in 0.8 s.");
    for (const [cls, re] of [["auth", /rejected this key/], ["model_not_found", /cannot use that model/], ["rate_limited", /quota/],
      ["timeout", /did not answer in time/], ["network", /could not reach/], ["server_error", /temporary/],
      ["empty_response", /answered with nothing/], ["bad_request", /refused/], ["???", /did not succeed/]] as const) {
      expect(testResultText({ ok: false, error_class: cls })).toMatch(re);
    }
  });

  it("the banner: key missing first, then spent workspaces; a workspace sees only its own budget (C5/D4)", () => {
    expect(bannerState({ key_present: false }, null)?.kind).toBe("connect");
    expect(bannerState({ key_present: true, budget: { workspaces_exhausted: 1 } }, null)?.text).toBe("One workspace has spent today's AI budget.");
    expect(bannerState({ key_present: true, budget: { workspaces_exhausted: 3 } }, null)?.text).toBe("3 workspaces have spent today's AI budget.");
    expect(bannerState({ key_present: true, budget: { workspaces_exhausted: 0 } }, null)).toBeNull();
    expect(bannerState(null, { budget: { exhausted: true } })?.kind).toBe("budget");
    expect(bannerState(null, { budget: { exhausted: false } })).toBeNull();
    expect(bannerState(null, null)).toBeNull(); // operators: both 403 → nothing
  });

  it("the footnote (C6)", () => {
    expect(answerFootnote({ provider: "anthropic", model: "claude-haiku-4-5" })).toBe("Answered with Claude claude-haiku-4-5 · based on your Correlix data");
    expect(answerFootnote({ provider: "openai" })).toBe("Answered with GPT · based on your Correlix data");
    expect(answerFootnote({ provider: "none", provider_note: "Evidence-only mode: AI provider unavailable." })).toBe("Answered from your Correlix data (no AI model)");
    expect(answerFootnote({ provider: "engine" })).toBe("Answered from your Correlix data (no AI model)");
    expect(answerFootnote({})).toBe("Answered from your Correlix data (no AI model)");
    expect(answerFootnote({ provider: "none", provider_note: "AI model paused after repeated failures; showing the evidence answer." }))
      .toBe("AI model paused after repeated failures; showing the evidence answer.");
    expect(answerFootnote({ mode: "unavailable" })).toBe("");
  });

  it("first-login landing only for a platform admin with no key, once (D5)", () => {
    const base = { freshLogin: true, canSeeFeatures: true, keySource: "none", dismissed: false, currentHash: "#/overview/home" };
    expect(shouldLandOnConnect(base)).toBe(true);
    expect(shouldLandOnConnect({ ...base, freshLogin: false })).toBe(false);
    expect(shouldLandOnConnect({ ...base, canSeeFeatures: false })).toBe(false);
    expect(shouldLandOnConnect({ ...base, keySource: "stored" })).toBe(false);
    expect(shouldLandOnConnect({ ...base, keySource: "env" })).toBe(false);
    expect(shouldLandOnConnect({ ...base, dismissed: true })).toBe(false);
    expect(shouldLandOnConnect({ ...base, currentHash: CONNECT_ROUTE })).toBe(false);
  });

  it("dismissal persists, and a throwing storage reads as not dismissed", () => {
    expect(readDismissed()).toBe(false);
    writeDismissed();
    expect(localStorage.getItem(CONNECT_DISMISSED_KEY)).toBe("1");
    expect(readDismissed()).toBe(true);
    const blocked = () => { throw new Error("blocked"); };
    vi.stubGlobal("localStorage", { getItem: blocked, setItem: blocked, clear: () => {} });
    try {
      expect(readDismissed()).toBe(false);
      expect(() => writeDismissed()).not.toThrow();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
