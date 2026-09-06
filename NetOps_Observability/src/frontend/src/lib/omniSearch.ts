// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// omniSearch — the ONE search-first entry point behind the topbar box and the
// ⌘K palette (Wave 6 #20). Merges the typed, tenant-scoped unified search
// (/api/search: devices · resources · services · accounts · cases, each with
// its permanent href) with the legacy global resolver's alert/saved kinds
// (/api/search/global), and groups results by kind for rendering.
//
// Pure helpers (mergeHits / groupHits) are unit-tested; omniSearch() is the
// thin fetch wrapper both surfaces share, so they can never disagree.

import { api, GlobalResult, SearchHit } from "../services/api";

export type OmniKind = SearchHit["kind"] | "alert" | "saved";

export type OmniHit = {
  kind: OmniKind;
  id: string;
  label: string;
  sublabel?: string;
  /** hash route without the leading "#/" — the permanent deep link. */
  href: string;
};

// Canonical group order: infrastructure first, then the cloud nouns, then the
// event-ish kinds. Mirrors the backend's tie-break order.
export const OMNI_KIND_ORDER: readonly OmniKind[] = [
  "device", "resource", "app", "account", "case", "alert", "saved",
];

export const OMNI_KIND_LABEL: Record<OmniKind, string> = {
  device: "Devices",
  resource: "Resources",
  app: "Services",
  account: "Accounts",
  case: "Cases",
  alert: "Alerts",
  saved: "Saved",
};

// Singular tag shown on a result row.
export const OMNI_KIND_TAG: Record<OmniKind, string> = {
  device: "Device",
  resource: "Resource",
  app: "Service",
  account: "Account",
  case: "Case",
  alert: "Alert",
  saved: "Saved",
};

export const OMNI_KIND_ICON: Record<OmniKind, string> = {
  device: "datasets",
  resource: "infrastructure",
  app: "monitoring",
  account: "settings",
  case: "incident",
  alert: "alerts",
  saved: "dashboards",
};

/** Map the legacy global resolver's rows into OmniHits, keeping ONLY the kinds
 *  the unified search does not cover (alerts, saved objects) — devices come
 *  from the unified search and the logs handoff is rendered by the surface. */
export function fromLegacy(results: GlobalResult[]): OmniHit[] {
  const out: OmniHit[] = [];
  for (const g of results) {
    if (g.kind !== "alert" && g.kind !== "saved") continue;
    out.push({ kind: g.kind, id: g.id, label: g.title, sublabel: g.sub || undefined, href: g.route });
  }
  return out;
}

/** Merge unified (already ranked by the backend) + legacy rows. Unified order
 *  is preserved verbatim — the backend's ranking is the ranking. */
export function mergeHits(unified: SearchHit[], legacy: GlobalResult[]): OmniHit[] {
  return [...unified, ...fromLegacy(legacy)];
}

export type OmniGroup = { kind: OmniKind; label: string; hits: OmniHit[] };

/** Group hits by kind in canonical group order, preserving each kind's
 *  internal (backend-ranked) order. Unknown kinds are dropped, not guessed. */
export function groupHits(hits: OmniHit[]): OmniGroup[] {
  const by = new Map<OmniKind, OmniHit[]>();
  for (const h of hits) {
    if (!OMNI_KIND_ORDER.includes(h.kind)) continue;
    const list = by.get(h.kind);
    if (list) list.push(h);
    else by.set(h.kind, [h]);
  }
  const out: OmniGroup[] = [];
  for (const kind of OMNI_KIND_ORDER) {
    const list = by.get(kind);
    if (list && list.length) out.push({ kind, label: OMNI_KIND_LABEL[kind], hits: list });
  }
  return out;
}

/** One live query against both search backends. Each side degrades
 *  independently — a failed sub-fetch yields its kinds empty, never an error
 *  for the whole box. */
export async function omniSearch(q: string): Promise<OmniHit[]> {
  const [unified, legacy] = await Promise.allSettled([api.unifiedSearch(q), api.globalSearch(q)]);
  return mergeHits(
    unified.status === "fulfilled" ? unified.value.results : [],
    legacy.status === "fulfilled" ? legacy.value.results : [],
  );
}
