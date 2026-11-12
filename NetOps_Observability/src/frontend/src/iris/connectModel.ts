// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// connectModel — the pure rules behind "Connect a model" (tracker 337 plan
// C2–C6, owner decisions D4–D6, 2026-11-09). No React, no fetches: the setup
// step, the admin banner, the per-answer footnote and the first-login landing
// all read these, and the unit tests pin them.

import type { AIBudgetStatus, RecommendedModels, TierTestResult } from "../services/api";

// D6: gemini is pre-selected; the order is the order the tiles show.
export const PROVIDER_ORDER = ["gemini", "anthropic", "openai"] as const;

export const PROVIDER_LABEL: Record<string, string> = {
  gemini: "Gemini",
  anthropic: "Claude",
  openai: "GPT",
};

export function providerLabel(p?: string): string {
  return (p && PROVIDER_LABEL[p]) || "AI model";
}

// D6: shown whenever Gemini is the chosen provider in a setup step.
export const GEMINI_FREE_TIER_WARNING =
  "Free-tier Gemini keys: Google may use what is sent to improve its products. Use a paid (billed) key for production network data.";

// The fields a provider choice fills in (C2). A provider with no
// recommendation keeps whatever the operator typed.
export type ModelFields = { provider: string; model: string; model_fast: string; model_strong: string };

export function applyRecommended(
  provider: string,
  recommended: Record<string, RecommendedModels> | undefined,
  current?: Partial<ModelFields>,
): ModelFields {
  const r = recommended?.[provider];
  if (!r) {
    return { provider, model: current?.model ?? "", model_fast: current?.model_fast ?? "", model_strong: current?.model_strong ?? "" };
  }
  return { provider, model: r.default, model_fast: r.fast, model_strong: r.strong };
}

// Plain-language result of a connection test, by the server's closed error
// class (ai.ClassifyProviderError). Never the provider's own message.
export function testResultText(r: { ok: boolean; error_class?: string; http_status?: number; latency_ms?: number; model?: string }): string {
  if (r.ok) {
    const secs = typeof r.latency_ms === "number" ? ` in ${(r.latency_ms / 1000).toFixed(1)} s` : "";
    return `Connected${r.model ? ` to ${r.model}` : ""}${secs}.`;
  }
  switch (r.error_class) {
    case "auth":
      return "The provider rejected this key. Check that it is correct and active.";
    case "model_not_found":
      return "This key cannot use that model. Pick a recommended model or check the name.";
    case "rate_limited":
      return "The provider says this key is over its quota or rate limit.";
    case "timeout":
      return "The provider did not answer in time. The model may be busy, or this server may not reach the internet. Test the recommended model to tell which.";
    case "network":
      return "This server could not reach the provider. Check its internet access or proxy.";
    case "server_error":
      if (r.http_status === 503 || r.http_status === 529) {
        return "The provider says this model is overloaded right now. Try again in a few minutes, or pick the recommended model.";
      }
      return "The provider had a temporary problem. Try again in a minute.";
    case "empty_response":
      return "The provider answered with nothing. Try the recommended model.";
    case "bad_request":
      return "The provider refused the request. Try the recommended model.";
    default:
      return "The test did not succeed. Try again, or pick the recommended model.";
  }
}

// The operator's words for each tier (the settings form's own labels).
export const TIER_LABEL: Record<string, string> = {
  default: "Default model",
  fast: "Model for quick answers",
  strong: "Model for deep investigations",
};

export type TierLine = { tier: string; ok: boolean; text: string };

// One line per tier model of a connection test (2026-11-12: the lab's default
// model timed out while its quick-answer model answered in 0.7 s, and the
// single verdict could not show it).
//
// When another model of the same test answered, the server plainly reaches
// the provider, so a model that timed out or "could not be reached" is slow or
// overloaded — never the internet path (2026-11-12: the page said "check this
// server's internet access" while gemini-2.5-flash answered in 0.8 s).
export function tierTestLines(r: { tiers?: TierTestResult[] } | null | undefined): TierLine[] {
  const tiers = r?.tiers ?? [];
  const reached = tiers.some((t) => t.ok);
  return tiers.map((t) => {
    const label = TIER_LABEL[t.tier] ?? t.tier;
    const why = reached && (t.error_class === "timeout" || t.error_class === "network")
      ? "It did not answer in time, but another model answered, so this server reaches the provider. This model is slow or overloaded right now. Try again later, or pick the recommended model."
      : testResultText({ ok: false, error_class: t.error_class, http_status: t.http_status });
    const text = t.ok
      ? `${label}: ${t.model}, ${(t.latency_ms / 1000).toFixed(1)} s.`
      : `${label}: ${t.model} failed. ${why}`;
    return { tier: t.tier, ok: t.ok, text };
  });
}

// The models a save will use, per tier: a blank tier is its provider's
// recommended model (the server's rule, ai.TierModels.ForProvider).
export function resolvedTierModels(
  draft: ModelFields,
  recommended: Record<string, RecommendedModels> | undefined,
): Record<"default" | "fast" | "strong", string> {
  const r = recommended?.[draft.provider];
  return {
    default: draft.model.trim() || r?.default || "",
    fast: draft.model_fast.trim() || r?.fast || "",
    strong: draft.model_strong.trim() || r?.strong || "",
  };
}

// Warnings before a save (warn, never block): each tier whose model FAILED the
// latest test of the same provider and is still the model this save will use.
export function saveWarnings(
  test: { provider?: string; tiers?: TierTestResult[] } | null | undefined,
  draft: ModelFields,
  recommended: Record<string, RecommendedModels> | undefined,
): string[] {
  if (!test?.tiers?.length || (test.provider && test.provider !== draft.provider)) return [];
  const will = resolvedTierModels(draft, recommended);
  return test.tiers
    .filter((t) => !t.ok && will[t.tier] === t.model)
    .map((t) => `${TIER_LABEL[t.tier] ?? t.tier} ${t.model} failed its last test.`);
}

// The admin banner (C5, D4). Platform view first (key missing, then spent
// workspaces); a workspace admin sees only their own budget. Never shown to
// operators — the config calls behind it are 403 for them, so both inputs stay
// null.
export type BannerState = { kind: "connect" | "budget"; text: string } | null;

export function bannerState(
  platform: { key_present?: boolean; feature_enabled?: boolean; budget?: AIBudgetStatus } | null | undefined,
  workspace: { budget?: AIBudgetStatus } | null | undefined,
): BannerState {
  if (platform) {
    if (!platform.key_present) {
      return { kind: "connect", text: "Connect a model to unlock full language understanding." };
    }
    const n = platform.budget?.workspaces_exhausted ?? 0;
    if (n > 0) {
      return { kind: "budget", text: n === 1 ? "One workspace has spent today's AI budget." : `${n} workspaces have spent today's AI budget.` };
    }
    return null;
  }
  if (workspace?.budget?.exhausted) {
    return { kind: "budget", text: "Today's AI budget for this workspace is spent. Answers use your Correlix data only until tomorrow." };
  }
  return null;
}

// The per-answer footnote (C6). A model answer names the provider and model;
// a deterministic answer says it came from the customer's own data; a fallback
// with a specific reason (timed out, paused, budget spent) says that reason.
const GENERIC_FALLBACK = /^Evidence-only mode: AI provider/i;

export function answerFootnote(a: { provider?: string; model?: string; provider_note?: string; mode?: string }): string {
  if (a.mode === "unavailable") return "";
  const p = (a.provider ?? "").toLowerCase();
  if (p && p !== "none" && p !== "engine") {
    return `Answered with ${providerLabel(p)}${a.model ? ` ${a.model}` : ""} · based on your Correlix data`;
  }
  const note = (a.provider_note ?? "").trim();
  if (note && !GENERIC_FALLBACK.test(note)) return note;
  return "Answered from your Correlix data (no AI model)";
}

// D5: on a FRESH login, a platform administrator whose installation has no
// model key lands on the Features page, where the Connect-a-model step is.
// Once dismissed, never again on this browser.
export const CONNECT_DISMISSED_KEY = "correlix.connectModel.dismissed";
export const CONNECT_ROUTE = "#/platform/features";

export function shouldLandOnConnect(x: {
  freshLogin: boolean;
  canSeeFeatures: boolean;
  keySource?: string;
  dismissed: boolean;
  currentHash: string;
}): boolean {
  return x.freshLogin && x.canSeeFeatures && x.keySource === "none" && !x.dismissed && x.currentHash !== CONNECT_ROUTE;
}

// Browser storage can throw (private mode, blocked site data): every access is
// guarded and a failure reads as "not dismissed" / is ignored.
export function readDismissed(): boolean {
  try {
    return localStorage.getItem(CONNECT_DISMISSED_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeDismissed(): void {
  try {
    localStorage.setItem(CONNECT_DISMISSED_KEY, "1");
  } catch {
    /* storage unavailable: the step simply shows again next login */
  }
}
