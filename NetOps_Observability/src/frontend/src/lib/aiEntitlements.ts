// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// aiEntitlements — the caller's atomic AI entitlements (tracker 337 N-A7), as
// GET /api/features reports them in `ai_entitlements`.
//
// HIDING IS COSMETIC. Every AI route gates on its entitlement server-side and
// refuses without it; this module only spares the operator a button that
// would answer "not available". Never use it as a reason to skip a server
// check, and never treat a visible control as proof of access.

import { useEffect, useState } from "react";
import { api, type FeatureFlags } from "../services/api";

/** The closed vocabulary, mirrored from internal/aientitlement. */
export type AIEntitlement =
  | "ai.chat"
  | "ai.investigate"
  | "ai.nlquery"
  | "ai.context.author"
  | "ai.runbook.author"
  | "ai.mcp";

/**
 * Whether the caller holds `e`, from a /api/features answer.
 *
 * A server that predates N-A7 sends no `ai_entitlements` at all; the controls
 * then keep their old visibility (the server still refuses what it must). A
 * failed or missing answer (`null`) hides — the page cannot tell.
 */
export function hasAIEntitlement(flags: FeatureFlags | null | undefined, e: AIEntitlement): boolean {
  if (!flags) return false;
  const list = flags.ai_entitlements;
  if (!Array.isArray(list)) return true;
  return list.includes(e);
}

/**
 * The caller's entitlements for a component. `ready` is false until the
 * answer lands; `has` answers false until then, so nothing flashes into view
 * and is then withdrawn.
 */
export function useAIEntitlements(): { ready: boolean; has: (e: AIEntitlement) => boolean } {
  const [flags, setFlags] = useState<FeatureFlags | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    let live = true;
    // Promise.resolve().then: a call that throws synchronously still lands in
    // the catch below (hidden), never as a render-time crash.
    Promise.resolve()
      .then(() => api.features())
      .then((f) => { if (live) setFlags(f); })
      .catch(() => { if (live) setFlags(null); })
      .finally(() => { if (live) setReady(true); });
    return () => { live = false; };
  }, []);
  return { ready, has: (e) => hasAIEntitlement(flags, e) };
}
