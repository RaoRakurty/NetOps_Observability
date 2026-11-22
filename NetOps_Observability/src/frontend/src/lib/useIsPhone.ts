// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useIsPhone — true at phone width. Table rows are laid out by the table's own
// grid tracks, so a phone needs different columns rather than different CSS
// (the Logs page's rule, shared by Active Alerts and Incidents).

import { useSyncExternalStore } from "react";

export const PHONE_QUERY = "(max-width: 640px)";

export function useIsPhone(): boolean {
  return useSyncExternalStore(
    (notify) => {
      if (typeof window.matchMedia !== "function") return () => undefined;
      const mq = window.matchMedia(PHONE_QUERY);
      mq.addEventListener("change", notify);
      return () => mq.removeEventListener("change", notify);
    },
    () => typeof window.matchMedia === "function" && window.matchMedia(PHONE_QUERY).matches,
  );
}
