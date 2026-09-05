// registries.ts — pure logic behind the Registries sub-tab (the operator-authored
// service catalog + the application registry). Rendering lives in Registries.tsx.
//
// TWO REGISTRIES, DELIBERATELY SEPARATE. The verdict the audit asked for:
//   · /api/services      — the SERVICE CATALOG. A service groups flow traffic
//     through a versioned, append-only SELECTOR; that selector is what makes the
//     platform's per-service flow totals attribute anything at all.
//   · /api/applications  — the APPLICATION REGISTRY. Names the business
//     application and the team accountable for it.
// Migration 0015_app_identity.sql adds services.application_id as a nullable
// "thin parent" link — but internal/servicecat never reads or writes that column
// and Service has no such field, so THE LINK DOES NOT EXIST IN THE PRODUCT. The
// surface says so instead of implying a parent/child relationship it cannot honour.
//
// Selector semantics mirrored here come from internal/servicecat/selector_sql.go
// BuildSelectorCondition: only `ports`, `dst_prefixes` and `protocols` are
// understood. A spec with none of them yields NO condition, which is exactly the
// `attributed:false` a service shows in the flow view — so specAttributes() is
// what lets the editor say that before the operator saves.

import type { CatalogServiceSelector, RegistryStorageStatus } from "../../services/api";
import { httpFailure } from "../../lib/errors";
import { isIPv4CidrToken } from "./appIdCoverage";

/** servicecat.ValidateInput / appid.ValidateApplicationInput: name ≤ 120. */
export const REGISTRY_NAME_MAX = 120;

/** Client-side mirror of both servers' name rule. "" when the name is sendable. */
export function validateRegistryName(raw: string, what: "service" | "application"): string {
  const name = raw.trim();
  const a = what === "application" ? "an" : "a";
  if (!name) return `${a} ${what} name is required`;
  if (name.length > REGISTRY_NAME_MAX) return `the ${what} name must be ${REGISTRY_NAME_MAX} characters or fewer`;
  return "";
}

// ── selector specs ──────────────────────────────────────────────────────────

/** What the operator types; parsed into the spec the server stores. */
export type SelectorDraft = { ports: string; prefixes: string; protocols: string };
export const EMPTY_SELECTOR_DRAFT: SelectorDraft = { ports: "", prefixes: "", protocols: "" };

function splitList(raw: string): string[] {
  return raw.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
}

export type SelectorParse = { spec: Record<string, unknown>; error: string };

/**
 * Parses the three predicate fields the engine understands. Anything it cannot
 * make sense of is an error, never a silently dropped predicate — a dropped
 * predicate is how a service ends up attributing nothing while looking configured.
 */
export function parseSelectorDraft(d: SelectorDraft): SelectorParse {
  const spec: Record<string, unknown> = {};
  const ports: number[] = [];
  for (const t of splitList(d.ports)) {
    if (!/^\d{1,5}$/.test(t) || Number(t) > 65535) {
      return { spec: {}, error: `"${t}" is not a port — use whole numbers from 0 to 65535` };
    }
    ports.push(Number(t));
  }
  const protocols: number[] = [];
  for (const t of splitList(d.protocols)) {
    if (!/^\d{1,3}$/.test(t) || Number(t) > 255) {
      return { spec: {}, error: `"${t}" is not a protocol number — use whole numbers from 0 to 255` };
    }
    protocols.push(Number(t));
  }
  const prefixes: string[] = [];
  for (const t of splitList(d.prefixes)) {
    if (!isIPv4CidrToken(t)) {
      return { spec: {}, error: `"${t}" is not a valid IPv4 address or CIDR` };
    }
    prefixes.push(t);
  }
  if (ports.length) spec.ports = ports;
  if (prefixes.length) spec.dst_prefixes = prefixes;
  if (protocols.length) spec.protocols = protocols;
  return { spec, error: "" };
}

function intsIn(v: unknown, min: number, max: number): number[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is number => typeof x === "number" && Number.isInteger(x) && x >= min && x <= max);
}

function cidrsIn(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string" && isIPv4CidrToken(x));
}

/**
 * Mirror of servicecat.BuildSelectorCondition: true when this spec yields a
 * usable predicate. False is the `attributed:false` state — the service exists
 * and nothing is being attributed to it.
 */
export function specAttributes(spec: Record<string, unknown> | null | undefined): boolean {
  if (!spec) return false;
  return intsIn(spec.ports, 0, 65535).length > 0
    || cidrsIn(spec.dst_prefixes).length > 0
    || intsIn(spec.protocols, 0, 255).length > 0;
}

/** The predicate in one operator-readable line, or "" when there is none. */
export function describeSpec(spec: Record<string, unknown> | null | undefined): string {
  if (!spec) return "";
  const parts: string[] = [];
  const ports = intsIn(spec.ports, 0, 65535);
  if (ports.length) parts.push(`ports ${ports.join(", ")}`);
  const pfx = cidrsIn(spec.dst_prefixes);
  if (pfx.length) parts.push(`destinations ${pfx.join(", ")}`);
  const protos = intsIn(spec.protocols, 0, 255);
  if (protos.length) parts.push(`protocols ${protos.join(", ")}`);
  return parts.join(" · ");
}

/** Keys present in a stored spec that the engine does not act on. */
export function ignoredSpecKeys(spec: Record<string, unknown> | null | undefined): string[] {
  const understood = new Set(["ports", "dst_prefixes", "protocols"]);
  return Object.keys(spec ?? {}).filter((k) => !understood.has(k)).sort();
}

/** What the flow plane does with this service. Never claims traffic exists. */
export const NO_SELECTOR_CONSEQUENCE =
  "Nothing is attributed to this service until a selector matches on ports, destination prefixes or protocols.";

/**
 * The selector the engine actually uses: the highest version. The server returns
 * them newest-first, but picking by version keeps that an implementation detail.
 */
export function latestSelector(sels: readonly CatalogServiceSelector[]): CatalogServiceSelector | null {
  let best: CatalogServiceSelector | null = null;
  for (const s of sels) if (!best || s.version > best.version) best = s;
  return best;
}

/** The version a new POST will create (selectors are append-only). */
export function nextSelectorVersion(sels: readonly CatalogServiceSelector[]): number {
  const latest = latestSelector(sels);
  return (latest?.version ?? 0) + 1;
}

// ── bindings ────────────────────────────────────────────────────────────────

export const BINDING_KINDS = [
  { value: "probe", label: "Probe", hint: "a synthetic check that measures this service" },
  { value: "path", label: "Path", hint: "a measured network path this service depends on" },
  { value: "seam", label: "Seam", hint: "an ownership handoff this service crosses" },
] as const;

export const BINDING_KIND_LABELS: Record<string, string> =
  Object.fromEntries(BINDING_KINDS.map((k) => [k.value, k.label]));

/** Mirror of the server's binding guard: a known kind and a non-empty ref. */
export function validateBinding(kind: string, ref: string): string {
  if (!BINDING_KIND_LABELS[kind]) return "choose what kind of attachment this is";
  if (!ref.trim()) return "an attachment reference is required";
  return "";
}

// ── store availability ──────────────────────────────────────────────────────

/**
 * True when the read failed because the service catalog has no relational store
 * on this deployment (the API answers 501 with its own reason). That is a
 * deployment fact, not an empty registry, and the two must not render alike.
 */
export function isStoreUnavailable(e: unknown): boolean {
  const st = httpFailure(e)?.status;
  // 501 — the configured backend has no implementation for this registry.
  // 503 — it has one, but the store cannot be reached right now. Both are
  // deployment facts rather than "the tenant has nothing", so both render as an
  // explained unavailable state instead of an empty list (tracker 245).
  return st === 501 || st === 503;
}

// ── which backend holds these records (tracker 245) ─────────────────────────
//
// The page must never assert durability it cannot see. Everything below is
// derived from GET /api/registries/status; nothing is hardcoded per registry.

/** Operator-facing name of a backend kind. Unknown kinds print as they arrive
 *  rather than being coerced into a familiar-looking label. */
export function backendLabel(kind: string): string {
  switch (kind) {
    case "postgres": return "PostgreSQL";
    case "file": return "File";
    case "memory": return "Memory";
    default: return kind || "unknown";
  }
}

function persistenceLabel(p: string): string {
  switch (p) {
    case "persistent": return "Persistent";
    case "ephemeral": return "Ephemeral";
    default: return "";
  }
}

export type StorageBadge = { label: string; tone: string; title: string };

/**
 * How one registry's storage reads on screen. Four distinct states, none of
 * which may be rendered as any of the others:
 *
 *   healthy persistent   "PostgreSQL · Persistent"
 *   ephemeral            "Memory · Ephemeral"           (development mode)
 *   configured but down  "PostgreSQL · Persistent · Unavailable"   — NEVER
 *                        relabelled as file or memory: no failover happens.
 *   unsupported          "Unavailable · configured storage: File"
 *
 * The copy names STORAGE, never a "backend" (src/copyVoice.test.ts): an
 * operator reads what holds their records, not our configuration switch.
 */
export function storageBadge(st: RegistryStorageStatus | undefined): StorageBadge | null {
  if (!st) return null;
  const configured = backendLabel(st.configured_backend);
  if (!st.active_backend) {
    return {
      label: `Unavailable · configured storage: ${configured}`,
      tone: "var(--bad)",
      title: `${configured} storage cannot hold this registry, so nothing here is saved. `
        + "Switch this deployment to PostgreSQL to use it.",
    };
  }
  const active = backendLabel(st.active_backend);
  const persistence = persistenceLabel(st.persistence);
  const base = persistence ? `${active} · ${persistence}` : active;
  if (!st.available || !st.healthy) {
    return {
      label: `${base} · Unavailable`,
      tone: "var(--bad)",
      title: (st.reason ? `${st.reason}. ` : `${active} is unavailable. `)
        + `Records stay in ${active}; nothing is written anywhere else, and they `
        + "are readable again as soon as it recovers.",
    };
  }
  if (st.persistence === "ephemeral") {
    return {
      label: base,
      tone: "var(--warn)",
      title: "Development mode — these records are held in memory and are lost when the API restarts.",
    };
  }
  return { label: base, tone: "var(--good)", title: `Stored in ${active}; records survive an API restart.` };
}

// ── archive semantics ───────────────────────────────────────────────────────

/** DELETE archives — it is never a hard delete. The confirm says so. */
export function archivePrompt(what: "service" | "application", name: string): string {
  return what === "service"
    ? `Archive the service "${name}"? It stops being attributed and drops off the active list; its selector versions and past attribution are kept.`
    : `Archive the application "${name}"? It drops off the active list; the record is kept.`;
}

export function isArchived(row: { archived_at?: string }): boolean {
  return Boolean(row.archived_at);
}
