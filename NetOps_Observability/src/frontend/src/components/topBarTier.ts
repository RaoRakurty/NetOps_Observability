// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useSyncExternalStore } from "react";

// How much room the global top bar has, as one of three layouts (TopBar.tsx).
// This module is the ONE place the header's breakpoints live: TopBar renders
// a different control order per tier and stamps it on the header as
// data-tier, and styles.css keys every narrow-header rule off that attribute
// ("Narrow header"), so the markup and the styling can never disagree about
// which layout is showing.
//
//   full   (> 1000 px)  the desktop header, unchanged: wordmark · search ·
//                       scope · time range · help · health · ✦ Iris · account.
//   medium (≤ 1000 px)  wordmark · search · [More] · ✦ Iris · account. Scope,
//                       time range, help and health move into the More panel.
//   phone  (≤ 720 px)   Correlix mark · [More] · ✦ Iris · account. Search moves
//                       into the More panel too; the wordmark (≈ 320 px on its
//                       own) gives way to the mark.
//
// Why these numbers: in the default shell (44 px rail) the full cluster needs
// roughly 1000 px before its tail runs off-screen; wordmark + search (at its
// 120 px minimum) + More + ✦ Iris needs roughly 660 px, so the phone layout
// takes over at 720 px with margin to spare.
export type TopBarTier = "full" | "medium" | "phone";

export const TOPBAR_MEDIUM_QUERY = "(max-width: 1000px)";
export const TOPBAR_PHONE_QUERY = "(max-width: 720px)";

// The narrow header's ONE overflow control: its panel's id (aria-controls)
// and the button's accessible name.
export const TOPBAR_MORE_PANEL_ID = "topbar-more-panel";
export const TOPBAR_MORE_LABEL = "More";

/** The tier for a pair of media-query results. Phone implies medium. */
export function tierFrom(medium: boolean, phone: boolean): TopBarTier {
  if (phone) return "phone";
  if (medium) return "medium";
  return "full";
}

function mediaList(query: string): MediaQueryList | null {
  try {
    return typeof window !== "undefined" && typeof window.matchMedia === "function" ? window.matchMedia(query) : null;
  } catch {
    return null;
  }
}

/** The current tier. Without media-query support it is "full" — the desktop
 *  header, which is what every environment rendered before tiers existed. */
export function readTopBarTier(): TopBarTier {
  const medium = mediaList(TOPBAR_MEDIUM_QUERY);
  const phone = mediaList(TOPBAR_PHONE_QUERY);
  return tierFrom(!!medium?.matches, !!phone?.matches);
}

function subscribe(onChange: () => void): () => void {
  const lists = [mediaList(TOPBAR_MEDIUM_QUERY), mediaList(TOPBAR_PHONE_QUERY)].filter(
    (l): l is MediaQueryList => l !== null,
  );
  for (const l of lists) {
    if (typeof l.addEventListener === "function") l.addEventListener("change", onChange);
    else l.addListener(onChange); // Safari < 14
  }
  return () => {
    for (const l of lists) {
      if (typeof l.removeEventListener === "function") l.removeEventListener("change", onChange);
      else l.removeListener(onChange);
    }
  };
}

/** The live tier: re-renders when the window crosses a breakpoint. */
export function useTopBarTier(): TopBarTier {
  return useSyncExternalStore(subscribe, readTopBarTier, () => "full");
}
