// appNames — client-side app-name enrichment over POST /api/appid/resolve/batch
// (#81 P3G). List views (top talkers, scan fan-out, tunnels) collect their
// visible IPs and get names in ONE debounced call; results live in a
// module-level TTL cache so switching tabs or refreshing a panel does not
// re-ask. Unresolved IPs are cached as null (negative cache — no re-asking, no
// "unknown" spam) and render exactly as before.

import { useEffect, useMemo, useSyncExternalStore } from "react";
import { api, AppIdBatchVerdict } from "./api";

export type ResolvedApp = AppIdBatchVerdict;

const TTL_MS = 5 * 60_000; // resolved + negative entries
const ERROR_TTL_MS = 60_000; // brief back-off when the batch call fails
const DEBOUNCE_MS = 250;
const MAX_KEYS = 200; // server cap per request

type CacheEntry = { value: ResolvedApp | null; expires: number };

// module-level state (shared across every consumer)
const cache = new Map<string, CacheEntry>();
let pending = new Set<string>();
let inFlight = new Set<string>();
let timer: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<() => void>();
let version = 0; // bumped when a batch lands — the store snapshot for the hook

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

// looksLikeIp — cheap shape gate mirroring the server's charset rule (IPv4/IPv6
// textual chars, bounded length, at least one separator). Non-IPs (device
// names, ports, countries) are skipped client-side so mixed lists never 400.
export function looksLikeIp(k: string): boolean {
  if (!k || k.length > 45) return false;
  if (!/^[0-9a-fA-F.:]+$/.test(k)) return false;
  return k.includes(".") || k.includes(":");
}

/** Cached verdict for one key: ResolvedApp, null (asked — unresolved), or
 * undefined (never asked / expired). */
export function cachedAppName(key: string): ResolvedApp | null | undefined {
  const e = cache.get(key);
  if (!e || e.expires <= Date.now()) return undefined;
  return e.value;
}

/** Queue keys for resolution (debounced, deduped, cache- and flight-aware). */
export function requestAppNames(keys: string[]): void {
  const now = Date.now();
  for (const k of keys) {
    if (!looksLikeIp(k)) continue;
    const e = cache.get(k);
    if (e && e.expires > now) continue;
    if (inFlight.has(k)) continue;
    pending.add(k);
  }
  if (pending.size > 0 && timer === null) timer = setTimeout(flush, DEBOUNCE_MS);
}

async function flush(): Promise<void> {
  timer = null;
  const all = [...pending];
  const keys = all.slice(0, MAX_KEYS);
  pending = new Set(all.slice(MAX_KEYS));
  if (pending.size > 0) timer = setTimeout(flush, DEBOUNCE_MS);
  if (keys.length === 0) return;
  keys.forEach((k) => inFlight.add(k));
  try {
    const res = await api.appIdResolveBatch(keys);
    const expires = Date.now() + TTL_MS;
    for (const k of keys) cache.set(k, { value: res[k] ?? null, expires });
  } catch {
    // Silent to the user by design: enrichment is additive — rows render as
    // plain IPs. Brief negative cache so a failing backend isn't hammered.
    const expires = Date.now() + ERROR_TTL_MS;
    for (const k of keys) if (!cache.has(k)) cache.set(k, { value: null, expires });
  } finally {
    keys.forEach((k) => inFlight.delete(k));
  }
  version++;
  listeners.forEach((fn) => fn());
}

/** React hook: resolved app names for the given keys. Returns {key: ResolvedApp}
 * containing ONLY resolved keys; re-renders when a batch lands. */
export function useAppNames(keys: string[]): Record<string, ResolvedApp> {
  const v = useSyncExternalStore(subscribe, () => version);
  const sig = keys.join("|");
  useEffect(() => {
    requestAppNames(keys);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig, v]);
  return useMemo(() => {
    const out: Record<string, ResolvedApp> = {};
    const now = Date.now();
    for (const k of keys) {
      const e = cache.get(k);
      if (e && e.value && e.expires > now) out[k] = e.value;
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig, v]);
}

/** Test hook: wipe module state (cache, queue, listeners). */
export function _resetAppNamesForTest(): void {
  cache.clear();
  pending = new Set();
  inFlight = new Set();
  if (timer !== null) clearTimeout(timer);
  timer = null;
  listeners.clear();
  version = 0;
}
