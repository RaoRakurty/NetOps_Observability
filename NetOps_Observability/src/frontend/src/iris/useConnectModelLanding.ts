// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useConnectModelLanding — D5 (tracker 337, owner 2026-11-09): on a FRESH
// login, a platform administrator whose installation has no model key lands on
// Platform → Features, where the "Connect a model" step is. Runs once per load.
// The gate is the nav itself (only a platform admin's nav resolves the
// Features page) AND the server: /api/copilot/config is requirePlatformAdmin,
// so anyone else gets a 403 and nothing happens.

import { useEffect, useRef } from "react";
import { api } from "../services/api";
import { landingResolves, type NavSection } from "../nav";
import { CONNECT_ROUTE, readDismissed, shouldLandOnConnect } from "./connectModel";

export function readFreshLoginFlag(key: string): boolean {
  try {
    return sessionStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

export function useConnectModelLanding(freshLogin: boolean, ready: boolean, nav: NavSection[]): void {
  const done = useRef(false);
  useEffect(() => {
    if (done.current || !ready) return;
    done.current = true;
    const canSeeFeatures = landingResolves(CONNECT_ROUTE, nav);
    if (!freshLogin || !canSeeFeatures || readDismissed()) return;
    let live = true;
    api.copilotConfig()
      .then((c) => {
        if (live && shouldLandOnConnect({ freshLogin, canSeeFeatures, keySource: c.key_source, dismissed: readDismissed(), currentHash: location.hash })) {
          location.hash = CONNECT_ROUTE;
        }
      })
      .catch(() => { /* 403 for everyone but the platform admin: nothing to do */ });
    return () => { live = false; };
  }, [freshLogin, ready, nav]);
}
