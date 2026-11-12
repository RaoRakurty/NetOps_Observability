// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// connectModelTiers.test.tsx — the connection test shows each tier model's
// verdict and latency, and saving a model that failed its test warns (never
// blocks) — owner 2026-11-12, after the lab's default model timed out while
// its quick-answer model answered.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { resolvedTierModels, saveWarnings, tierTestLines } from "./connectModel";
import { ConnectionTestLine } from "../tabs/Iris";
import type { ProviderTestResult } from "../services/api";

afterEach(cleanup);

const rec = { gemini: { default: "gemini-2.5-flash", fast: "gemini-flash-lite-latest", strong: "gemini-2.5-flash" } };
const lab: ProviderTestResult = {
  ok: true, provider: "gemini", model: "gemini-flash-lite-latest", latency_ms: 670,
  tiers: [
    { tier: "default", model: "gemini-flash-latest", ok: false, latency_ms: 10000, error_class: "timeout" },
    { tier: "fast", model: "gemini-flash-lite-latest", ok: true, latency_ms: 670 },
    { tier: "strong", model: "gemini-2.5-flash", ok: true, latency_ms: 590 },
  ],
};

describe("tier connection test", () => {
  it("one line per tier with its model and latency", () => {
    const lines = tierTestLines(lab);
    expect(lines.map((l) => l.ok)).toEqual([false, true, true]);
    expect(lines[1].text).toBe("Model for quick answers: gemini-flash-lite-latest, 0.7 s.");
    expect(lines[2].text).toBe("Model for deep investigations: gemini-2.5-flash, 0.6 s.");
    expect(lines[0].text).toMatch(/^Default model: gemini-flash-latest failed\. The provider did not answer in time/);
    expect(tierTestLines(null)).toEqual([]);
  });

  it("a blank tier field is its recommended model", () => {
    expect(resolvedTierModels({ provider: "gemini", model: "gemini-flash-latest", model_fast: "", model_strong: " " }, rec))
      .toEqual({ default: "gemini-flash-latest", fast: "gemini-flash-lite-latest", strong: "gemini-2.5-flash" });
  });

  it("warns before saving a model that failed its test, only while it is still the model being saved", () => {
    const draft = { provider: "gemini", model: "gemini-flash-latest", model_fast: "", model_strong: "" };
    expect(saveWarnings(lab, draft, rec)).toEqual(["Default model gemini-flash-latest failed its last test."]);
    // The operator picked another default: nothing to warn about.
    expect(saveWarnings(lab, { ...draft, model: "gemini-2.5-flash" }, rec)).toEqual([]);
    // A test of another provider says nothing about this one.
    expect(saveWarnings(lab, { ...draft, provider: "openai" }, rec)).toEqual([]);
    expect(saveWarnings(null, draft, rec)).toEqual([]);
  });

  it("the settings page shows every tier's latency", () => {
    const { getByTestId } = render(<ConnectionTestLine result={lab} />);
    const box = getByTestId("connection-test");
    expect(box.textContent).toContain("A model did not answer.");
    const items = getByTestId("connection-test-tiers").querySelectorAll("li");
    expect(items).toHaveLength(3);
    expect(items[1].textContent).toContain("0.7 s");
    expect(items[0].className).toBe("bad");
    // An older server (no tiers) keeps the single verdict.
    cleanup();
    const old = render(<ConnectionTestLine result={{ ok: true, provider: "gemini", model: "m", latency_ms: 840 }} />);
    expect(old.getByTestId("connection-test").textContent).toContain("Connected to m in 0.8 s.");
  });
});
