// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// signalPage — pure helpers for the Wave 3 #10 scale-out of the cloud signal
// tables: the `sq` (signal search) hash param, and named saved views.
//
// SEARCH is server-side (?q= on /api/cloud/health|changes|evidence — bounded,
// escaped, tenant-scoped in cloud_signals.go): the search narrows the SERVER
// read, so it can find rows the LIMIT-bounded first page never loaded. The
// term lives in the URL (`sq`) exactly like the scope bar's params, so a
// pasted link reproduces the same narrowed table.
//
// SAVED VIEWS are named URL states (the hash query carrying scope + range +
// search + drawer), stored client-side in localStorage. They are keyed by the
// caller's active tenant scope so switching tenants never offers another
// tenant's view names — a cosmetic guard, not a security boundary: the DATA a
// view shows is always re-fetched through the tenant-scoped API, so applying
// a foreign view could only ever rename an empty result.

export function sqFromHash(hash: string): string {
  const q = hash.split("?")[1] ?? "";
  return new URLSearchParams(q).get("sq") ?? "";
}

/** The hash with `sq=<term>` set (other params preserved; empty term removes it). */
export function hashWithSq(hash: string, term: string): string {
  const [path, q = ""] = hash.split("?");
  const params = new URLSearchParams(q);
  if (term) params.set("sq", term);
  else params.delete("sq");
  const rest = params.toString();
  return rest ? `${path}?${rest}` : path;
}

export type SavedView = { name: string; query: string; savedAt: string };

const VIEWS_KEY = "netops_appobs_views";

type ViewStore = Record<string, SavedView[]>;

function readStore(storage: Pick<Storage, "getItem">): ViewStore {
  try {
    const raw = storage.getItem(VIEWS_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? (parsed as ViewStore) : {};
  } catch {
    return {};
  }
}

function scopeKey(tenantScope: string): string {
  return tenantScope || "default";
}

export function listViews(storage: Pick<Storage, "getItem">, tenantScope: string): SavedView[] {
  const views = readStore(storage)[scopeKey(tenantScope)];
  return Array.isArray(views) ? views : [];
}

/** Upsert by name (a re-save under the same name replaces the old query). */
export function saveView(
  storage: Pick<Storage, "getItem" | "setItem">, tenantScope: string,
  name: string, query: string, now: () => string = () => new Date().toISOString(),
): SavedView[] {
  const trimmed = name.trim().slice(0, 60);
  if (!trimmed) return listViews(storage, tenantScope);
  const store = readStore(storage);
  const key = scopeKey(tenantScope);
  const rest = (store[key] ?? []).filter((v) => v.name !== trimmed);
  store[key] = [...rest, { name: trimmed, query, savedAt: now() }]
    .sort((a, b) => a.name.localeCompare(b.name));
  storage.setItem(VIEWS_KEY, JSON.stringify(store));
  return store[key];
}

export function deleteView(
  storage: Pick<Storage, "getItem" | "setItem">, tenantScope: string, name: string,
): SavedView[] {
  const store = readStore(storage);
  const key = scopeKey(tenantScope);
  store[key] = (store[key] ?? []).filter((v) => v.name !== name);
  storage.setItem(VIEWS_KEY, JSON.stringify(store));
  return store[key];
}
