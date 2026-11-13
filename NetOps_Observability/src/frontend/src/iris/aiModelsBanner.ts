// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// aiModelsBanner.ts — what the Iris panel says about model-backed answers on
// this installation (owner 2026-11-12/13: model-backed Iris is the `iris_model`
// licence add-on, Enterprise includes it, and a platform administrator turns it
// on under Features). Pure, so every state is tested.
//
// Iris never dead-ends: with models unavailable it still answers from the
// platform's own data. The banner says that first, then what would change it.

import type { AIModelsState } from "../services/api";

export type ModelsBanner = { tone: "info" | "warn"; text: string } | null;

/**
 * The persistent banner for the panel. `isPlatformAdmin` decides whether the
 * next step is "turn it on" (they can) or "ask your administrator".
 */
export function modelsBanner(m: AIModelsState | undefined, isPlatformAdmin: boolean): ModelsBanner {
  if (!m || m.state === "on") return null;
  const lead = "Iris is answering from your network data.";
  if (m.state === "unlicensed") {
    return {
      tone: "info",
      text: `${lead} Written AI answers and AI investigations need the Iris AI add-on on your license. Enterprise includes it.`,
    };
  }
  return {
    tone: "info",
    text: isPlatformAdmin
      ? `${lead} AI models are off. Turn on "Iris AI models" under Administration → Features.`
      : `${lead} AI models are off. Your platform administrator can turn them on.`,
  };
}

/** The per-answer note when the server answered evidence-only for this reason. */
export function modelsOffNote(reason: string | undefined): string {
  switch (reason) {
    case "not_licensed":
      return "Answered from your network data. AI models need the Iris AI add-on.";
    case "switched_off":
      return "Answered from your network data. AI models are turned off on this installation.";
    case "tenant_off":
      return "Answered from your network data. AI models are turned off for this workspace.";
    default:
      return "Answered from your network data.";
  }
}

/** Why AI investigations cannot run, for the workspace-access settings. */
export function investigationsHint(m: AIModelsState | undefined): string | null {
  if (!m) return null;
  if (m.state === "unlicensed") return "AI investigations need the Iris AI add-on on your license.";
  if (!m.models_on) return 'Turn on "Iris AI models" under Administration → Features first.';
  if (!m.investigations_on) return 'Turn on "AI investigations" under Administration → Features, then tick the workspaces below.';
  return null;
}
