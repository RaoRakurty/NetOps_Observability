// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// scope.ts — how the global scope bar's provider/account/region/env filters
// actually apply to each Service View surface (Wave 2 #5). Pure + unit-tested
// (scope.test.ts).
//
// Semantics (shared with the backend's multi-value /api/cloud/resources
// filters): values OR within a dimension, dimensions AND together, an empty
// dimension filters nothing. Filters NARROW within the caller's tenant view —
// they can never widen it (§3a: tenancy is enforced server-side; this module
// only ever subtracts from what the tenant-scoped APIs returned).
//
// Where the truth lives decides where the filter runs:
//   · resources — SERVER-side (loadResources passes provider/account/region to
//     the Wave-1 SQL filters; env alone narrows client-side because env is a
//     resolved tag, not a store column).
//   · apps / signals / evidence / investigations — client-side over the
//     already-loaded, LIMIT-bounded sets these tabs fetched anyway (≤1000 rows
//     by construction); the signal store has no provider/account columns to
//     filter on server-side without a JSON-extract scan.
//
// Honesty rule (mirrors range.ts withinRange): a row that CANNOT be placed on
// a dimension (a signal whose resource isn't in the inventory, no provider
// stamp) STAYS VISIBLE rather than being hidden by a filter it never met — an
// incident must never disappear because attribution is incomplete. The one
// exception is a RESOLVED absence: an investigation whose evidence carries no
// cloud provider is *known* non-cloud (origin.ts), so a provider filter
// excludes it.

import type { CloudScopeState } from "./scopeUrl";
import { isScopeActive } from "./scopeUrl";
import type { App, CloudResource } from "./types";
import type { CloudRcaObject } from "./api";

// ── option derivation (what the scope bar offers) ─────────────────────────────
export interface ScopeOptions {
  providers: string[];
  accounts: string[];
  regions: string[];
  envs: string[];
}

// Distinct values present in the tenant's inventory, sorted. A dimension only
// offers what actually exists — a cloud with nothing connected is not a dead
// filter choice (same rule the Applications FilterBar follows).
export function scopeOptions(rows: {
  provider?: string; account?: string; region?: string; env?: string;
}[]): ScopeOptions {
  const dim = (get: (r: (typeof rows)[number]) => string | undefined) =>
    [...new Set(rows.map(get).filter((v): v is string => !!v && v !== "—"))].sort();
  return {
    providers: dim((r) => r.provider),
    accounts: dim((r) => r.account),
    regions: dim((r) => r.region),
    envs: dim((r) => r.env),
  };
}

// ── predicates ────────────────────────────────────────────────────────────────
const inSet = (v: string | undefined, set: string[], fold = false): boolean => {
  if (set.length === 0) return true;
  if (!v || v === "—") return false;
  return fold ? set.some((s) => s.toLowerCase() === v.toLowerCase()) : set.includes(v);
};

/** A cloud resource against the scope. Every dimension is a resolved field on
 *  the resource itself, so this is exact (used for the env leftover narrowing
 *  and the Untagged/coverage-by-scope client sets). */
export function resourceInScope(r: CloudResource, s: CloudScopeState): boolean {
  return inSet(r.provider, s.providers, true) &&
    inSet(r.account, s.accounts) &&
    inSet(r.region, s.regions) &&
    inSet(r.env, s.envs);
}

// A merged multi-value cell ("111 · sub-9") from the Apps merge — any part hit
// keeps the app: the service IS present in the scoped account.
const mergedHas = (cell: string, set: string[]): boolean => {
  if (set.length === 0) return true;
  return cell.split("·").map((p) => p.trim()).some((p) => p !== "" && p !== "—" && set.includes(p));
};

/** A (possibly multi-cloud) service row against the scope. */
export function appInScope(a: App, s: CloudScopeState): boolean {
  const provOK = s.providers.length === 0 ||
    a.providers.some((p) => inSet(p, s.providers, true));
  return provOK && mergedHas(a.account, s.accounts) &&
    mergedHas(a.region, s.regions) && inSet(a.env, s.envs);
}

// ── signal rows (alerts / changes / findings / timeline) ──────────────────────
// A signal names its provider directly (source / cloud_ref); account/region/env
// resolve through the inventory by the resource NAME the backend already
// stamped on the row. Unresolvable rows stay visible (see header).

export interface ScopeIndex {
  /** resource name AND resource id → the inventory resource. */
  byHandle: Map<string, CloudResource>;
}

export function buildScopeIndex(resources: CloudResource[]): ScopeIndex {
  const byHandle = new Map<string, CloudResource>();
  for (const r of resources) {
    if (r.name) byHandle.set(r.name, r);
    if (r.id) byHandle.set(r.id, r);
    if (r.resourceId) byHandle.set(r.resourceId, r);
  }
  return { byHandle };
}

/** The scope-relevant identity of one signal-ish row, adapter-built below. */
export interface SignalScopeKey {
  provider?: string; // "aws" | "azure" | "gcp" | anything else = unresolved
  account?: string;
  region?: string;
  resource?: string; // resolved name (or raw handle) for the inventory join
}

const isCloud = (p: string | undefined): boolean =>
  p === "aws" || p === "azure" || p === "gcp";

export function signalInScope(k: SignalScopeKey, s: CloudScopeState, idx?: ScopeIndex): boolean {
  const hit = k.resource && idx ? idx.byHandle.get(k.resource) : undefined;
  // provider: the row's own stamp first, the inventory join as fallback.
  const prov = (k.provider ?? "").trim().toLowerCase();
  const provider = isCloud(prov) ? prov : hit?.provider;
  if (s.providers.length > 0) {
    // resolvable → must match; unresolvable → visible (can't be placed).
    if (provider && isCloud(provider) && !inSet(provider, s.providers, true)) return false;
  }
  const check = (want: string[], own: string | undefined, inv: string | undefined): boolean => {
    if (want.length === 0) return true;
    const v = own && own !== "—" ? own : inv;
    if (!v || v === "—") return true; // unresolvable → visible
    return inSet(v, want);
  };
  if (!check(s.accounts, k.account, hit?.account)) return false;
  if (!check(s.regions, k.region, hit?.region)) return false;
  if (!check(s.envs, undefined, hit?.env)) return false;
  return true;
}

// adapters for the concrete row shapes (kept structural so tests need no full rows)
export const healthScopeKey = (h: { source: string; resource: string }): SignalScopeKey =>
  ({ provider: h.source, resource: h.resource });
export const changeScopeKey = (c: {
  resource: string; cloudRef?: { provider: string; account: string; region: string };
}): SignalScopeKey => ({
  provider: c.cloudRef?.provider, account: c.cloudRef?.account,
  region: c.cloudRef?.region, resource: c.resource,
});
export const evidenceScopeKey = (e: {
  source: unknown; resource: string;
  cloudRef?: { provider: string; account: string; region: string };
}): SignalScopeKey => ({
  provider: e.cloudRef?.provider ?? String(e.source ?? ""),
  account: e.cloudRef?.account, region: e.cloudRef?.region, resource: e.resource,
});

/** An investigation against the scope. Providers are DERIVED from the object's
 *  own attached evidence (origin.ts): a non-empty set is a positive claim (must
 *  intersect the filter), an empty set is a RESOLVED "no cloud signal attached"
 *  (a network/on-prem object) — a provider-scoped view excludes it. Account/
 *  region/env resolve through the primary affected resource when the inventory
 *  knows it; otherwise the object stays visible. */
export function objectInScope(o: CloudRcaObject, s: CloudScopeState, idx?: ScopeIndex): boolean {
  if (s.providers.length > 0 &&
    !o.origin.providers.some((p) => inSet(p, s.providers, true))) return false;
  return signalInScope({ resource: o.origin.primaryResource }, {
    ...s, providers: [], // provider already decided above from the origin
  }, idx);
}

/** An untagged-resource row against the scope. Its provider/account/region are
 *  resolved inventory facts → strict; env is exactly what an untagged resource
 *  is missing, so an env filter cannot place these rows — they stay visible. */
export function unknownInScope(u: {
  provider?: string; account?: string; region?: string;
}, s: CloudScopeState): boolean {
  return inSet(u.provider, s.providers, true) &&
    inSet(u.account, s.accounts) &&
    inSet(u.region, s.regions);
}

/** True when an ACTIVE scope produced the empty set — the "no matches in this
 *  scope" state (distinct from "nothing ingested", which shows the connect CTA). */
export function scopedToNothing(s: CloudScopeState, total: number, shown: number): boolean {
  return isScopeActive(s) && total > 0 && shown === 0;
}
