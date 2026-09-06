// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// origin.ts — where an investigation actually comes from (2026-07 owner review #5)
// and who it is about (#1). Both are DERIVED from the object's own evidence, so
// the answer is only ever something the engine really grounded.
//
// The correlation object the API returns (CloudRcaObject) carries `apps` and a
// verdict, but no provider: the object's `affected` blob buckets devices/apps/
// cloud_resources and never labels a cloud. The provider IS carried, per signal,
// on the evidence attached to that object (attrs.provider → the row's cloud_ref
// / source). So we join the evidence ledger back onto its object by rca_group and
// report only the providers that appear in that object's real evidence.
//
// Honesty rules this module exists to enforce:
//   · a provider is claimed ONLY when a signal of that provider is attached —
//     never inferred from a name, a region or a hypothesis string;
//   · an object whose evidence carries no cloud provider is NOT "unknown cloud",
//     it is a non-cloud (network / on-prem) investigation — a distinct answer;
//   · the fallback identity is the first GROUNDED row's resource (a fact), never
//     a gap row's placeholder and never a fabricated service name.
// Pure + deterministic → unit-tested (origin.test.ts).

import type { EvidenceRow, Provider } from "./types";
import { cleanVal } from "./timeline";

// The clouds we can actually attribute to. "—" (the Provider "none" member) is
// deliberately not here: it is an absence, not a provider.
export const CLOUD_PROVIDERS: readonly Provider[] = ["aws", "azure", "gcp"] as const;

// A provider token from the wire → a Provider, or null when it is not one of the
// three clouds. The backend's providerOf() degrades an unstamped cloud signal to
// the generic "cloud", and gap rows carry "correlation engine" — both must return
// null rather than be promoted to a specific cloud we cannot evidence.
export function providerFrom(v: string | null | undefined): Provider | null {
  const s = (v ?? "").trim().toLowerCase();
  return s === "aws" || s === "azure" || s === "gcp" ? s : null;
}

// The provider behind ONE evidence row. cloud_ref.provider is the signal's own
// attrs.provider (the strongest fact); `source` is the backend's providerOf()
// projection of the same attr and is the fallback.
export function evidenceProvider(e: EvidenceRow): Provider | null {
  return providerFrom(e.cloudRef?.provider) ?? providerFrom(String(e.source ?? ""));
}

export interface ObjectOrigin {
  // Every cloud actually represented in this object's evidence, deduped + stable
  // ordered. Empty = no cloud signal is attached (a network / on-prem object).
  providers: Provider[];
  // The first GROUNDED row's resource — the object's primary affected resource,
  // used as the Service column's fallback identity when `apps` is empty. "" when
  // no grounded row named a resource (then the UI says "unattributed", honestly).
  primaryResource: string;
}

export const EMPTY_ORIGIN: ObjectOrigin = { providers: [], primaryResource: "" };

// Join the evidence ledger onto its objects by rca_group. One pass, so the
// Overview pays nothing extra: the rows are already in the same API response.
export function deriveObjectOrigins(rows: EvidenceRow[]): Map<string, ObjectOrigin> {
  const acc = new Map<string, { providers: Set<Provider>; primaryResource: string }>();
  for (const e of rows) {
    const cid = cleanVal(e.rcaGroup);
    if (!cid) continue;
    let cur = acc.get(cid);
    if (!cur) {
      cur = { providers: new Set<Provider>(), primaryResource: "" };
      acc.set(cid, cur);
    }
    const p = evidenceProvider(e);
    if (p) cur.providers.add(p);
    // Only a GROUNDED row is a fact about a resource; a "missing" gap row is the
    // engine describing what it does NOT have (resource "—") and must never
    // become the object's identity.
    if (!cur.primaryResource && e.grounded) {
      const res = cleanVal(e.resource);
      if (res) cur.primaryResource = res;
    }
  }
  const out = new Map<string, ObjectOrigin>();
  for (const [cid, v] of acc) {
    out.set(cid, {
      providers: CLOUD_PROVIDERS.filter((p) => v.providers.has(p)),
      primaryResource: v.primaryResource,
    });
  }
  return out;
}

// The Service column's answer for one object — the real service when the engine
// named one, else the primary affected resource, else an explicit unattributed.
// `label` is what the cell shows; `why` is the tooltip that explains a fallback
// (the anti-"silent dash" rule: an empty cell must always say why it is empty).
export interface ServiceIdentity {
  label: string;
  kind: "service" | "resource" | "unattributed";
  why: string;
}

export function serviceIdentity(apps: string[], origin: ObjectOrigin): ServiceIdentity {
  const named = (apps ?? []).map((a) => cleanVal(a)).filter(Boolean);
  if (named.length) {
    return { label: named.join(", "), kind: "service", why: "" };
  }
  if (origin.primaryResource) {
    return {
      label: origin.primaryResource,
      kind: "resource",
      why: "No service is mapped to this investigation — showing the primary affected resource instead. Tag the resource with app/owner/env to name its service.",
    };
  }
  return {
    label: "unattributed",
    kind: "unattributed",
    why: "The engine grounded no resource that maps to a service. Tag the affected resources (app/owner/env) or add an attribution rule to name the service.",
  };
}
