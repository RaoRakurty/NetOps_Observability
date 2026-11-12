// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PlatformAlertsNotice — the platform-admin-only notice that Correlix's own
// alerts reach nobody (owner decision 2026-11-11: platform alerts are set up
// in the GUI, and an unconfigured route must be loud).
//
// Everyone else never sees it: the input is /api/platform/alerting/host-route,
// which is requirePlatformAdmin, so for a tenant admin or an operator the call
// is refused and this renders nothing.

import { useEffect, useState } from "react";
import { api, type PlatformAlertRoute } from "../services/api";
import { routeBanner } from "../pages/platform/platformAlertsModel";

export const PLATFORM_ALERTS_ROUTE = "#/platform/platform-alerts";

export function PlatformAlertsNotice() {
  const [route, setRoute] = useState<PlatformAlertRoute | null>(null);
  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const r = await api.platformAlertRoute();
        if (live) setRoute(r);
      } catch {
        // Not the platform administrator (403), or the api is unreachable:
        // nothing to say here — the page itself reports its own load errors.
      }
    })();
    return () => {
      live = false;
    };
  }, []);
  const text = route ? routeBanner(route) : null;
  if (!text) return null;
  return (
    <div className="cc-panel" role="alert" data-testid="platform-alerts-notice" style={{ padding: "10px 12px", marginBottom: 12, fontSize: 14, borderColor: "var(--bad)" }}>
      {text} <a href={PLATFORM_ALERTS_ROUTE}>Set up platform alerts</a>
    </div>
  );
}
