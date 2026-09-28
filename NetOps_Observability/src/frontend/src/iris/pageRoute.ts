// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { canonicalHash, landingResolves, resolveRoute } from "../nav";

// pageRoute.ts — page-aware help (plan N-G3). The Iris box sends the page the
// operator is looking at, so "what am I looking at?" is answered from that
// page's documentation and a product question ranks that page's docs first.
//
// Only a REAL nav leaf is sent, in its canonical "section/leaf" form. The SPA
// router never says "not found" (an unknown section falls back to the first
// one), so the hash is checked against the nav tree here rather than trusted:
// a hash that only resolves by fallback, a section with no leaf named, and the
// in-page sub-item or ?query suffix are all dropped. The server validates the
// route again against its own table and ignores anything else; the route only
// ranks documentation and never scopes data.

/** The canonical "section/leaf" route of the page behind the Iris box, or
 *  undefined when the location names no real page. */
export function currentPageRoute(hash: string = typeof window === "undefined" ? "" : window.location.hash): string | undefined {
  if (!hash || hash.length > 200) return undefined;
  const canon = canonicalHash(hash) ?? hash;
  const segs = canon.replace(/^#\/?/, "").split("?")[0].split("/");
  if (segs.length < 2 || !segs[0] || !segs[1]) return undefined;
  if (!landingResolves(canon)) return undefined;
  const r = resolveRoute(canon);
  if (!r.leaf || r.section.id !== segs[0] || r.leaf.id !== segs[1]) return undefined;
  return `${r.section.id}/${r.leaf.id}`;
}

/** The ui-context the Iris box sends with a question: the current page, if
 *  there is one, merged under any context the caller already carries. */
export function withPageContext(context?: Record<string, string>, hash?: string): Record<string, string> | undefined {
  const route = currentPageRoute(hash);
  if (!route) return context;
  return { route, ...(context ?? {}) };
}
