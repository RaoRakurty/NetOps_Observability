// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectModelBanner — the admin-only notice (tracker 337 plan C5, owner D4).
//
// Two cases, both administrator business:
//   · no model key on this installation → "Connect a model…" with the action;
//   · today's AI budget is spent (platform: how many workspaces; workspace
//     admin: their own).
// Operators never see it: the inputs come from /api/copilot/config (platform
// admin) and /api/ai/tenant-config (workspace admin), both 403 for everyone
// else, so both stay null and this renders nothing.

import type { AIBudgetStatus } from "../services/api";
import { bannerState } from "../iris/connectModel";

export function ConnectModelBanner({
  platform,
  workspace,
  onConnect,
}: {
  platform: { key_present?: boolean; feature_enabled?: boolean; budget?: AIBudgetStatus } | null | undefined;
  workspace?: { budget?: AIBudgetStatus } | null;
  onConnect?: () => void;
}) {
  const st = bannerState(platform, workspace);
  if (!st) return null;
  return (
    <div className={`connect-banner ${st.kind}`} role="status" data-testid="connect-model-banner">
      <span className="connect-banner-text">{st.text}</span>
      {st.kind === "connect" && onConnect && (
        <button type="button" className="dash-btn accent" onClick={onConnect}>
          Connect a model
        </button>
      )}
    </div>
  );
}
