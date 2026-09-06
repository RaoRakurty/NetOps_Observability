// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// App Observability — bulk service-assignment helpers (2026-07 review, imp #5).
//
// Pure, unit-tested core for the "assign resources to a service" workflow: the
// backend shipped PUT /api/cloud/resource-mappings (bulk, operator-authoritative
// override) with the Azure optional-tags epic, but no UI ever called it — the
// untagged remediation queue dead-ended at "go tag it in the provider console".
// These helpers mirror the backend's own validation (business_service_handlers.go)
// so a request that would 400 never leaves the client.

// ── Interfaces ────────────────────────────────────────────────────────────────

/** What the operator picked in the assign drawer. Exactly one of the two. */
export interface AssignTarget {
  /** An existing named service (business_service_id, a UUID). */
  businessServiceId?: string;
  /** A free-text service name — upserted server-side as a manual mapping. */
  serviceName?: string;
}

/** The wire body for PUT /api/cloud/resource-mappings, or an error to show. */
export type AssignRequestResult =
  | { ok: true; body: { business_service_id?: string; service_name?: string; resource_ids: string[] } }
  | { ok: false; error: string };

// Backend bounds (business_service_handlers.go): 1..5000 ids, name ≤128 printable.
export const ASSIGN_MAX_RESOURCES = 5000;
const NAME_MAX = 128;

// ── Implementation ────────────────────────────────────────────────────────────

/** Mirrors backend bizSvcName: non-empty, ≤128 chars, no control characters. */
export function validServiceName(s: string): boolean {
  const t = s.trim();
  if (t.length === 0 || t.length > NAME_MAX) return false;
  for (const ch of t) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

/**
 * Build the bulk-assignment body, or the exact human reason it can't be sent.
 * Validation mirrors the server so the drawer never fires a doomed request.
 */
export function buildAssignRequest(resourceIds: string[], target: AssignTarget): AssignRequestResult {
  const ids = [...new Set(resourceIds.map((r) => r.trim()).filter(Boolean))];
  if (ids.length === 0) return { ok: false, error: "Select at least one resource." };
  if (ids.length > ASSIGN_MAX_RESOURCES) {
    return { ok: false, error: `at most ${ASSIGN_MAX_RESOURCES.toLocaleString()} resources per assignment` };
  }
  const hasID = !!target.businessServiceId;
  const name = (target.serviceName ?? "").trim();
  if (hasID && name) return { ok: false, error: "pick an existing service OR a new name — not both" };
  if (!hasID && !name) return { ok: false, error: "pick a service or enter a name" };
  if (!hasID && !validServiceName(name)) {
    return { ok: false, error: "service name must be 1–128 printable characters" };
  }
  return {
    ok: true,
    body: hasID
      ? { business_service_id: target.businessServiceId, resource_ids: ids }
      : { service_name: name, resource_ids: ids },
  };
}

/** Toggle one id in a selection (returns a new Set — state-friendly). */
export function toggleSelection(sel: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(sel);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

/**
 * Header checkbox semantics over the CURRENTLY VISIBLE (filtered) rows:
 * if every visible id is selected, unselect the visible ones (other pages'
 * selections survive); otherwise select all visible.
 */
export function toggleAllVisible(sel: ReadonlySet<string>, visibleIds: string[]): Set<string> {
  const next = new Set(sel);
  const allSelected = visibleIds.length > 0 && visibleIds.every((id) => next.has(id));
  if (allSelected) {
    for (const id of visibleIds) next.delete(id);
  } else {
    for (const id of visibleIds) next.add(id);
  }
  return next;
}

/** The honest message for a failed assignment (501 = store needs the DB backend). */
export function assignErrorMessage(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg.startsWith("501")) {
    return "Service assignment is not enabled on this deployment.";
  }
  if (msg.startsWith("404")) return "That service no longer exists — refresh and pick again.";
  return "Assignment failed — retry, or check your access.";
}
