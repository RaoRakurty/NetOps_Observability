// scopeUrl — the Service View's global scope + time-range as URL state
// (Wave 2 #5). The interactive scope bar's selections live in the hash query
// (`#/operations/services?provider=aws,azure&region=us-east-1&range=7d`), so a
// refresh or a pasted link reopens the exact same view. Coexists with the
// investigation drawer's `inv` param (investigationUrl.ts) — both codecs
// preserve every param they do not own.
//
// URL schema (every param optional; absent = unfiltered / default):
//   provider = comma-separated cloud set        e.g. provider=aws,azure
//   account  = comma-separated account/sub/proj e.g. account=111,sub-9
//   region   = comma-separated regions          e.g. region=us-east-1,eastus
//   env      = comma-separated environments     e.g. env=prod
//   range    = a CLOUD_RANGES label             e.g. range=7d   (default 24h)
// Values never contain commas (provider enums, account ids, region codes, env
// tags), so the separator is unambiguous — the same contract the backend's
// multi-value /api/cloud/resources filters use.
//
// Pure + deterministic → unit-tested (scopeUrl.test.ts).

import { CLOUD_RANGES, DEFAULT_CLOUD_RANGE } from "./range";

export interface CloudScopeState {
  providers: string[];
  accounts: string[];
  regions: string[];
  envs: string[];
  /** the selected time range for the signal surfaces (minutes). */
  rangeMinutes: number;
}

export type ScopeDim = "providers" | "accounts" | "regions" | "envs";

export const SCOPE_DIMS: readonly ScopeDim[] = ["providers", "accounts", "regions", "envs"];

// dim → its URL param (singular, reads naturally in a pasted link).
const DIM_PARAM: Record<ScopeDim, string> = {
  providers: "provider", accounts: "account", regions: "region", envs: "env",
};

export function emptyScope(): CloudScopeState {
  return { providers: [], accounts: [], regions: [], envs: [], rangeMinutes: DEFAULT_CLOUD_RANGE.minutes };
}

/** any filter dimension set (the range alone is not a "filter"). */
export function isScopeActive(s: CloudScopeState): boolean {
  return SCOPE_DIMS.some((d) => s[d].length > 0);
}

// split a comma-joined param into clean values (trimmed, deduped, no empties).
function splitValues(raw: string | null): string[] {
  if (!raw) return [];
  return [...new Set(raw.split(",").map((v) => v.trim()).filter(Boolean))];
}

/** The scope encoded in a hash like `#/operations/services?provider=aws&range=7d`.
 *  Junk degrades safely: an unknown range label falls back to the default —
 *  the label must never claim a window the reads won't honor. */
export function scopeFromHash(hash: string): CloudScopeState {
  const q = new URLSearchParams(hash.split("?")[1] ?? "");
  const rangeLabel = (q.get("range") ?? "").trim();
  const range = CLOUD_RANGES.find((r) => r.label === rangeLabel) ?? DEFAULT_CLOUD_RANGE;
  return {
    providers: splitValues(q.get(DIM_PARAM.providers)),
    accounts: splitValues(q.get(DIM_PARAM.accounts)),
    regions: splitValues(q.get(DIM_PARAM.regions)),
    envs: splitValues(q.get(DIM_PARAM.envs)),
    rangeMinutes: range.minutes,
  };
}

/** The hash with the scope written into it (defaults omitted, every param this
 *  codec does not own — e.g. the drawer's `inv` — preserved verbatim). */
export function hashWithScope(hash: string, s: CloudScopeState): string {
  const [path, q = ""] = hash.split("?");
  const params = new URLSearchParams(q);
  for (const dim of SCOPE_DIMS) {
    if (s[dim].length > 0) params.set(DIM_PARAM[dim], s[dim].join(","));
    else params.delete(DIM_PARAM[dim]);
  }
  const range = CLOUD_RANGES.find((r) => r.minutes === s.rangeMinutes);
  if (range && range.minutes !== DEFAULT_CLOUD_RANGE.minutes) params.set("range", range.label);
  else params.delete("range");
  const rest = params.toString();
  return rest ? `${path}?${rest}` : path;
}

/** A stable identity key for effect deps / cache keys. */
export function scopeKey(s: CloudScopeState): string {
  return SCOPE_DIMS.map((d) => `${d}=${[...s[d]].sort().join(",")}`).join("|") +
    `|range=${s.rangeMinutes}`;
}
