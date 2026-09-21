// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Opsis.routing.test.tsx — the routing invariant behind Iris's central claim
// (tracker 330). Before this test, a configured provider key sent freely typed
// questions to the PLAIN chat proxy, skipping classification, skills, the policy
// engine, TAC, the quality layer and citations — while the panel still told the
// operator the answers were grounded, tenant-scoped and cited.
//
// The contract asserted here:
//   1. free text reaches /api/ai/ask (api.aiAsk) EVEN WHEN a provider key is
//      configured — the grounded engine is the default route, not the fallback;
//   2. the "grounded · cited" claim is rendered per-answer and only beside an
//      answer that actually carries citations;
//   3. the one surviving ungrounded path (the general-model retry for a question
//      the engine could not place) is labelled from the SERVER's own
//      `is_grounded:false` flag, never silently.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor, act } from "@testing-library/react";
import Opsis from "./Opsis";
import { ShellContext, TIME_RANGES, type ShellState } from "../context/shell";
import type { AiAnswer } from "../services/api";

const aiAsk = vi.fn();
const copilotChat = vi.fn();
const copilotConfig = vi.fn();
const aiTenantConfig = vi.fn();
const aiTenants = vi.fn();
const aiCommands = vi.fn();
const features = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    aiAsk: (...a: unknown[]) => aiAsk(...a),
    copilotChat: (...a: unknown[]) => copilotChat(...a),
    copilotConfig: (...a: unknown[]) => copilotConfig(...a),
    aiTenantConfig: (...a: unknown[]) => aiTenantConfig(...a),
    aiTenants: (...a: unknown[]) => aiTenants(...a),
    aiCommands: (...a: unknown[]) => aiCommands(...a),
    features: (...a: unknown[]) => features(...a),
    aiFeedback: () => Promise.resolve(),
  },
}));

const shell: ShellState = {
  range: TIME_RANGES[1], setRange: () => {},
  query: "", setQuery: () => {},
  copilotOpen: true, setCopilotOpen: () => {},
  helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
  navigate: () => {},
};

/** A grounded, cited answer as /api/ai/ask returns it. */
function citedAnswer(over: Partial<AiAnswer> = {}): AiAnswer {
  return {
    mode: "current_state_summary",
    intent: "current_state",
    modules: ["command_center"],
    text: "Three suspected incidents; start with the DIA egress seam.",
    citations: [{ id: "problem:abc", kind: "finding", label: "dia-egress", href: "#/monitoring/correlations?id=abc" }],
    disclaimers: [],
    provider: "anthropic",
    ...over,
  } as AiAnswer;
}

/** The engine's honest "I could not place that question" answer. */
function capabilityAnswer(): AiAnswer {
  return {
    mode: "unavailable",
    intent: "capability",
    modules: [],
    text: "I didn't quite catch that.",
    citations: [],
    disclaimers: [],
  } as AiAnswer;
}

/** A platform owner WITH a provider key configured — the production state. */
function keyedOwner() {
  copilotConfig.mockResolvedValue({ provider: "anthropic", model: "claude-sonnet-4-6", feature_enabled: true, key_present: true });
  aiTenantConfig.mockRejectedValue(new Error("403"));
  aiTenants.mockResolvedValue({ tenants: [] });
}

/** Render and let every mount fetch settle, so no state update escapes act(). */
async function renderOpsis() {
  const utils = render(
    <ShellContext.Provider value={shell}><Opsis /></ShellContext.Provider>,
  );
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  return utils;
}

async function ask(text: string) {
  const ta = await screen.findByPlaceholderText(/Ask Iris AI/);
  fireEvent.change(ta, { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByTitle("Send (⏎)")); });
}

beforeEach(() => {
  [aiAsk, copilotChat, copilotConfig, aiTenantConfig, aiTenants, aiCommands, features].forEach((m) => m.mockReset());
  features.mockResolvedValue({ copilot: true });
  aiCommands.mockResolvedValue({ commands: [] });
  aiTenants.mockResolvedValue({ tenants: [] });
  aiTenantConfig.mockRejectedValue(new Error("403"));
  copilotConfig.mockRejectedValue(new Error("403"));
});
afterEach(() => cleanup());

describe("Opsis — free text routes to the GROUNDED engine", () => {
  it("posts a typed question to /api/ai/ask even when a provider key is configured", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(citedAnswer());
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("why is wan-r2 flapping?");

    await waitFor(() => expect(aiAsk).toHaveBeenCalled());
    expect(aiAsk.mock.calls[0][0]).toBe("why is wan-r2 flapping?");
    // The whole point: the plain proxy is NOT the route for free text.
    expect(copilotChat).not.toHaveBeenCalled();
  });

  it("still routes to /api/ai/ask when no key is configured (unchanged behaviour)", async () => {
    aiAsk.mockResolvedValue(citedAnswer());
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("what is going on right now?");
    await waitFor(() => expect(aiAsk).toHaveBeenCalled());
    expect(copilotChat).not.toHaveBeenCalled();
  });

  it("never sends a browser-assembled prompt — the question travels verbatim", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(citedAnswer());
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("explain the bgp drop");
    await waitFor(() => expect(aiAsk).toHaveBeenCalled());
    expect(JSON.stringify(aiAsk.mock.calls[0])).not.toMatch(/Answer using ONLY|context below/i);
  });
});

describe("Opsis — the grounded claim is per-answer, and an ungrounded answer is labelled", () => {
  it("renders the grounded+cited chip beside an answer that carries citations", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(citedAnswer());
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("what is going on right now?");

    const chip = await screen.findByTestId("iris-grounded-chip");
    expect(chip.textContent).toMatch(/cited/i);
    expect(screen.queryByTestId("iris-ungrounded-chip")).toBeNull();
  });

  it("does not claim 'cited' for a grounded answer with no citations", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(citedAnswer({ citations: [] }));
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("what is going on right now?");

    const chip = await screen.findByTestId("iris-grounded-chip");
    expect(chip.textContent).toMatch(/grounded/i);
    expect(chip.textContent).not.toMatch(/cited/i);
  });

  it("labels the general-model answer from the server's own is_grounded flag", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(capabilityAnswer());
    copilotChat.mockResolvedValue({ provider: "anthropic", text: "Shorter version: two sites are down.", is_grounded: false });
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("shorter please");

    expect(await screen.findByTestId("iris-ungrounded-chip")).toBeTruthy();
    expect(await screen.findByText(/Shorter version: two sites are down\./)).toBeTruthy();
    expect(screen.queryByTestId("iris-grounded-chip")).toBeNull();
  });

  it("keeps the engine's own answer when no provider key can carry the retry", async () => {
    aiAsk.mockResolvedValue(capabilityAnswer());
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("shorter please");

    await waitFor(() => expect(aiAsk).toHaveBeenCalled());
    expect(copilotChat).not.toHaveBeenCalled();
    expect(screen.queryByTestId("iris-ungrounded-chip")).toBeNull();
  });

  it("treats a provider-down engine fallback as grounded, not as a general answer", async () => {
    keyedOwner();
    aiAsk.mockResolvedValue(capabilityAnswer());
    copilotChat.mockResolvedValue({
      provider: "engine", text: "Evidence only.", is_grounded: true,
      fallback: "provider_unavailable", grounded: citedAnswer({ text: "Evidence only." }),
    });
    await renderOpsis();
    await screen.findByText(/How can I help/);
    await ask("shorter please");

    expect(await screen.findByTestId("iris-grounded-chip")).toBeTruthy();
    expect(screen.queryByTestId("iris-ungrounded-chip")).toBeNull();
    expect(await screen.findByText(/AI narration is temporarily unavailable/)).toBeTruthy();
  });

  it("no longer makes a blanket 'answers are grounded, tenant-scoped and cited' claim", async () => {
    keyedOwner();
    await renderOpsis();
    await screen.findByText(/How can I help/);
    fireEvent.click(screen.getByTitle("Help & documentation"));
    expect(screen.queryByText(/Answers are grounded, tenant-scoped and cited/)).toBeNull();
  });
});
