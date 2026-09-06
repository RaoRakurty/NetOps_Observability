// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Service catalog (Wave 3 #8) — pure logic behind the catalog CRUD surface and
// the catalog↔derived-apps join. The catalog is the operator-authored registry
// (name/criticality/owner/description over /api/cloud/business-services); the
// derived apps are inventory-inferred. Joining is by service NAME because the
// mapping layer denormalizes service_name onto resources and the derived app
// rows carry that name — never a guess beyond an exact case-insensitive match.

import type { BusinessServiceRow, ResourceMappingRow } from "../../services/api";

// criticality vocabulary (backend validCriticality) → rank + display tone.
// Rank 0 = most critical so "worst first" sorts ascending.
export const CRITICALITY_META: Record<string, { rank: number; label: string; tone: string }> = {
  critical: { rank: 0, label: "Business-critical", tone: "var(--crit)" },
  high:     { rank: 1, label: "High",              tone: "var(--warn)" },
  normal:   { rank: 2, label: "Normal",            tone: "var(--accent)" },
  low:      { rank: 3, label: "Low",               tone: "var(--fg-subtle)" },
};
export const CRITICALITY_ORDER = ["critical", "high", "normal", "low"] as const;

export function criticalityRank(c: string): number {
  return CRITICALITY_META[c]?.rank ?? 4; // unset sorts after every set value
}

// per-service mapped-resource counts from the override ledger (keyed by the
// service id when bound, else the denormalized name).
export function mappingCounts(mappings: ResourceMappingRow[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const m of mappings) {
    const key = m.business_service_id || nameKey(m.service_name);
    if (!key) continue;
    out.set(key, (out.get(key) ?? 0) + 1);
  }
  return out;
}

export function nameKey(name: string): string {
  return name.trim().toLowerCase();
}

// catalog lookup for the derived-apps join (exact name match, case-insensitive).
export function catalogByName(services: BusinessServiceRow[]): Map<string, BusinessServiceRow> {
  const out = new Map<string, BusinessServiceRow>();
  for (const s of services) out.set(nameKey(s.name), s);
  return out;
}

// client-side mirror of the backend bounds (bizSvcName/bizSvcOwner): printable,
// single line, ≤128 chars; owner/description optional. The server remains the
// authority — this only gives the operator an immediate, specific message.
function printableLine(s: string): boolean {
  for (const c of s) {
    const code = c.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

export function validateServiceForm(f: { name: string; owner: string; runbook?: string }): string {
  const name = f.name.trim();
  if (!name) return "a service name is required";
  if (name.length > 128) return "the service name must be 128 characters or fewer";
  if (!printableLine(name)) return "the service name must be a single line of printable text";
  const owner = f.owner.trim();
  if (owner.length > 128) return "the owner must be 128 characters or fewer";
  if (!printableLine(owner)) return "the owner must be a single line of printable text";
  const runbook = (f.runbook ?? "").trim();
  if (runbook && !isSafeRunbookUrl(runbook)) {
    return "the runbook link must be an absolute https:// URL (512 characters or fewer)";
  }
  return "";
}

// client-side mirror of the backend bizSvcRunbookURL bounds (Wave 4 #12):
// empty = unset; otherwise an absolute https:// URL with a host, ≤512 chars.
// Also the zero-trust gate before a stored runbook_url ever reaches an
// <a href> — never render javascript:/data:/http: as a click-through.
export function isSafeRunbookUrl(raw: string): boolean {
  const s = raw.trim();
  if (!s || s.length > 512 || !printableLine(s)) return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" && u.hostname !== "";
  } catch {
    return false;
  }
}

// safeRunbookUrl returns the renderable href ("" when unset or unsafe).
export function safeRunbookUrl(raw: string | undefined): string {
  const s = (raw ?? "").trim();
  return isSafeRunbookUrl(s) ? s : "";
}
