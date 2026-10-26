// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tenantOwner — who owns a row, in words an operator reads (tracker 365).
//
// The platform's own data is spelled two ways on the wire: no tenant / ""
// (untagged, discovered infrastructure) and "global" (the Provider tenant).
// They are ONE owner — the backend's internal/owner package says so, and this
// is its SPA mirror. Real tenant ids are never collapsed into each other.
//
// Why this exists: on 2026-10-25 an operator looking at what they took to be
// the Provider's own list deleted another tenant's controller integration. The
// list was every tenant's, unlabelled. So the "All tenants" view labels every
// row with its tenant, and a delete or change of a row that belongs to another
// tenant says whose it is before anything happens.

import type { ScopeDetail } from "../services/api";

/** The Provider (platform) tenant id. */
export const PROVIDER_TENANT = "global";
/** What the Provider is called when /api/scopes has not answered. */
export const PROVIDER_LABEL = "Provider";

/** The canonical owner of a row: trimmed, lower-cased, "" → Provider. */
export function ownerOf(tenantId?: string | null): string {
  const t = (tenantId ?? "").trim().toLowerCase();
  return t === "" ? PROVIDER_TENANT : t;
}

/** Whether two tenant ids name the same owner. */
export function sameOwner(a?: string | null, b?: string | null): boolean {
  return ownerOf(a) === ownerOf(b);
}

export type TenantNames = Record<string, string>;

/** tenant id → display name, from the caller's /api/scopes answer. */
export function tenantNames(scopes: ScopeDetail[]): TenantNames {
  const out: TenantNames = {};
  for (const s of scopes) out[ownerOf(s.tenant_id)] = s.tenant_name || s.tenant_id;
  return out;
}

/** The name to show for a row's owner. No tenant → Provider. An id the
 *  caller has no name for is shown as the id itself, never hidden. */
export function tenantLabel(tenantId: string | null | undefined, names: TenantNames): string {
  const o = ownerOf(tenantId);
  if (names[o]) return names[o];
  return o === PROVIDER_TENANT ? PROVIDER_LABEL : o;
}

/** The "All tenants" view: a cross-tenant principal with no scope selected.
 *  Only here do rows from several tenants share one list. */
export function isAllTenantsView(crossTenant: boolean, activeScope: string): boolean {
  return crossTenant && !activeScope;
}

/** The owner the operator is acting as: the selected scope, or — in the All
 *  tenants view — the Provider, which is the platform admin's own realm. */
export function actingOwner(activeScope: string): string {
  return ownerOf(activeScope);
}

/** A plain-language sentence naming the row's owner when it is NOT the owner
 *  the operator is acting as, or null when the row is their own. */
export function foreignOwnerNote(
  rowTenant: string | null | undefined,
  activeScope: string,
  names: TenantNames,
  noun: string,
): string | null {
  if (sameOwner(rowTenant, actingOwner(activeScope))) return null;
  const owner = tenantLabel(rowTenant, names);
  const acting = tenantLabel(actingOwner(activeScope), names);
  return `This ${noun} belongs to the tenant "${owner}", not ${acting}.`;
}

/** The text of a destructive-action confirm. A row owned by another tenant
 *  names that tenant first, so the dialog cannot be read as "mine". */
export function confirmText(opts: {
  verb: string; // "Delete", "Pause collection for"
  name: string;
  noun: string; // "integration"
  rowTenant?: string | null;
  activeScope: string;
  names: TenantNames;
  consequence?: string;
}): string {
  const head = `${opts.verb} "${opts.name}"?`;
  const note = foreignOwnerNote(opts.rowTenant, opts.activeScope, opts.names, opts.noun);
  const owner = tenantLabel(opts.rowTenant, opts.names);
  const parts = [head];
  if (note) parts.push(`${note} The change affects ${owner}.`);
  if (opts.consequence) parts.push(opts.consequence);
  return parts.join("\n\n");
}
