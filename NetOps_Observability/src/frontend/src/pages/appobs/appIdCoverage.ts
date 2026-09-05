// appIdCoverage.ts — pure logic behind the App-ID coverage panel and the
// operator override editor (Settings tab). Rendering lives in AppIdCoverage.tsx.
//
// THE HONESTY RULE THIS MODULE EXISTS FOR. /api/appid/status reports a count of
// **-1** when the operator override store did not answer (appid_catalog.go
// handleAppIDStatus, which also sets `tenant_overrides_unavailable`). Operator
// overrides are the HIGHEST-precedence identification layer, so "the store did
// not answer" and "this tenant declared none" are different facts and must never
// share a rendering. readCount() is the single place that decision is made.
//
// The precedence ladder labels are NOT redeclared here: they come from
// GovernanceSettings, which is where the operator edits that order. This panel
// reports the order; that card sets it.

import type { AppCatalogEntry, AppCatalogInput, AppIdStatus } from "../../services/api";
import { PRECEDENCE_LABELS } from "./GovernanceSettings";

/** The engine's UNKNOWN sentinel — a store that did not answer, never a zero. */
export const UNKNOWN_COUNT = -1;

export type CountReading =
  | { known: true; value: number; text: string }
  | { known: false; value: null; text: string };

/**
 * How one coverage count reads. A negative value (the -1 sentinel, or anything
 * else non-sensical) is UNKNOWN, never "none" — the caller pairs it with
 * unavailableReason() so the operator learns why.
 */
export function readCount(n: number): CountReading {
  if (!Number.isFinite(n) || n < 0) return { known: false, value: null, text: "unknown" };
  return { known: true, value: n, text: n.toLocaleString() };
}

/**
 * Why this tenant's override counts are unknown, or null when they are known.
 * Either signal from the server is enough: the explicit flag, or the sentinel.
 */
export function unavailableReason(s: Pick<AppIdStatus, "tenant_overrides" | "tenant_overrides_unavailable">): string | null {
  if (s.tenant_overrides_unavailable === true || !Number.isFinite(s.tenant_overrides) || s.tenant_overrides < 0) {
    return "The engine could not read the operator override store, so these counts are unknown — this is not a statement that this tenant has none.";
  }
  return null;
}

/** The class whose rows this editor writes: operator overrides outrank everything. */
export const OPERATOR_CLASS = "operator";

export type PrecedenceRow = { cls: string; label: string; rank: number; isOperator: boolean };

/**
 * The active ladder as rows, highest-precedence first. An unrecognized class
 * renders its raw name rather than being hidden — a ladder we cannot label is
 * still a ladder the engine is using.
 */
export function precedenceRows(order: readonly string[]): PrecedenceRow[] {
  return order.map((cls, i) => ({
    cls,
    label: PRECEDENCE_LABELS[cls] ?? cls,
    rank: i + 1,
    isOperator: cls === OPERATOR_CLASS,
  }));
}

/** How the precedence order was arrived at, for the panel's meta line. */
export function precedenceOrigin(isDefault: boolean): string {
  return isDefault ? "platform default order" : "tenant order";
}

/** Said when no managed vendor feed directory is configured on the deployment. */
export const NO_FEEDS_NOTE =
  "No managed vendor feed directory is configured here, so the vendor prefix and domain layers stay empty and identification falls to the layers below them.";

// ── the override editor ─────────────────────────────────────────────────────

export const MATCH_KINDS = [
  { value: "prefix", label: "IP prefix", hint: "an IPv4 address or CIDR, e.g. 52.96.0.0/12" },
  { value: "domain", label: "Domain suffix", hint: "matched against the destination name, e.g. teams.microsoft.com" },
  { value: "asn", label: "Autonomous system", hint: "the destination's AS, e.g. 8075" },
  { value: "port", label: "Destination port", hint: "0 to 65535, e.g. 3389" },
] as const;

export const MATCH_KIND_LABELS: Record<string, string> =
  Object.fromEntries(MATCH_KINDS.map((k) => [k.value, k.label]));

/**
 * Mirror of appid.catalogIsCIDRToken (catalog_store.go): IPv4 only, four octets
 * 0-255 with no leading zeros, optional /0-32 mask. Copied by shape, never by
 * recall — the server stays the authority; this only buys an instant message.
 */
export function isIPv4CidrToken(raw: string): boolean {
  const s = raw.trim();
  const slash = s.indexOf("/");
  const host = slash < 0 ? s : s.slice(0, slash);
  if (slash >= 0) {
    const mask = s.slice(slash + 1);
    if (!/^\d{1,2}$/.test(mask)) return false;
    const m = Number(mask);
    if (m < 0 || m > 32) return false;
  }
  const octets = host.split(".");
  if (octets.length !== 4) return false;
  return octets.every((o) => {
    if (!/^\d{1,3}$/.test(o)) return false;
    if (o.length > 1 && o[0] === "0") return false;
    return Number(o) <= 255;
  });
}

export type OverrideDraft = {
  match_kind: string;
  match_value: string;
  app_label: string;
  confidence: string; // free text: empty means "let the engine use its default"
};

export const EMPTY_OVERRIDE_DRAFT: OverrideDraft = {
  match_kind: "prefix", match_value: "", app_label: "", confidence: "",
};

/**
 * Client-side mirror of appid.ValidateCatalogInput plus the app_catalog
 * confidence CHECK (0..1, migration 0015_app_identity.sql). Returns "" when the
 * draft is sendable; the server revalidates everything regardless.
 */
export function validateOverride(d: OverrideDraft): string {
  if (!MATCH_KIND_LABELS[d.match_kind]) return "choose what this override matches on";
  const value = d.match_value.trim();
  if (!value) return "a match value is required";
  if (!d.app_label.trim()) return "an application name is required";
  if (d.match_kind === "prefix" && !isIPv4CidrToken(value)) {
    return "an IP prefix must be a valid IPv4 address or CIDR, e.g. 52.96.0.0/12";
  }
  if (d.match_kind === "port") {
    if (!/^\d{1,5}$/.test(value)) return "a port must be a whole number from 0 to 65535";
    if (Number(value) > 65535) return "a port must be a whole number from 0 to 65535";
  }
  const conf = d.confidence.trim();
  if (conf) {
    const n = Number(conf);
    if (!Number.isFinite(n) || n < 0 || n > 1) return "confidence must be a number between 0 and 1";
  }
  return "";
}

/**
 * The request body for POST /api/appid/catalog. The tenant is deliberately
 * absent: the server stamps it from the caller's token and ignores anything a
 * body claims (appid_overrides.go handleAppIDCatalog).
 */
export function overrideInput(d: OverrideDraft): AppCatalogInput {
  const out: AppCatalogInput = {
    match_kind: d.match_kind,
    match_value: d.match_value.trim(),
    app_label: d.app_label.trim(),
  };
  const conf = d.confidence.trim();
  if (conf) out.confidence = Number(conf);
  return out;
}

/** Newest first, so a row just created is the one the operator sees. */
export function sortOverrides(entries: readonly AppCatalogEntry[]): AppCatalogEntry[] {
  return [...entries].sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
}

/** The confirm sentence before a delete. Says what goes and what follows. */
export function deleteOverridePrompt(e: Pick<AppCatalogEntry, "app_label" | "match_value">): string {
  return `Remove the override that names ${e.match_value} as "${e.app_label}"? Traffic it matched falls back to the next source in the order.`;
}
