// App Observability — shell data hook (#81 P3F+1).
//
// Loads the live cloud inventory ONCE and derives the global scope + data mode +
// readiness summary the CloudScopeBar / ReadinessStrip render. Honest by
// construction: an empty inventory ⇒ "No cloud data connected" and every
// not-yet-ingested source reports "off" (see readiness.ts). A load error ⇒
// inventory "off", not a fabricated healthy state.

import { useEffect, useState } from "react";
import { api, CloudResourceRow, CloudIngestionSource, CloudConnectorInfo } from "../../services/api";
import { fetchCloudInventory } from "./api";
import { useAuth } from "../../hooks/useAuth";
import {
  deriveScope, deriveReadiness, deriveDataMode, deriveConnectorKind, summarize,
  CloudScope, DataMode, ReadinessSummary, IngestionSource,
} from "./readiness";
import { scopeOptions, ScopeOptions } from "./scope";

export interface CloudShell {
  scope: CloudScope;
  mode: DataMode;
  summary: ReadinessSummary;
  loading: boolean;
  /** what the interactive scope bar can offer (Wave 2 #5) — the distinct
   *  provider/account/region/env values present in THIS tenant's inventory.
   *  Derived from the unfiltered shared read, so options never shrink to the
   *  current selection. */
  options: ScopeOptions;
}

export function useCloudShell(): CloudShell {
  const { user } = useAuth();
  const [rows, setRows] = useState<CloudResourceRow[]>([]);
  const [connectors, setConnectors] = useState<CloudConnectorInfo[] | undefined>(undefined);
  const [ingestion, setIngestion] = useState<CloudIngestionSource[] | undefined>(undefined);
  const [err, setErr] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let live = true;
    // Shared 30s-TTL inventory read (review #14) — the shell + tabs coalesce to
    // one GET /api/cloud/resources per visit instead of 3–5.
    fetchCloudInventory().then(
      (r) => { if (live) { setRows(r.resources ?? []); setConnectors(r.connectors); setLoading(false); } },
      () => { if (live) { setErr(true); setLoading(false); } },
    );
    // Per-source ingestion status. A failure here is NOT fatal: readiness falls
    // back to inventory-only (every other source "off") rather than claiming health.
    api.cloudIngestion().then(
      (r) => { if (live) setIngestion(r.sources ?? []); },
      () => { if (live) setIngestion(undefined); },
    );
    return () => { live = false; };
  }, []);

  const tenant = user?.all_tenants ? "All tenants" : (user?.tenant_id || "—");
  const dims = rows.map((r) => ({ provider: r.cloud_provider, account: r.account_id, region: r.region, env: r.env }));
  const scope = deriveScope(dims, tenant);
  const options = scopeOptions(dims);
  // freshest last_seen across the inventory = the inventory's effective sync time.
  const lastSyncIso = rows.reduce((acc, r) => (r.last_seen_at > acc ? r.last_seen_at : acc), "") || undefined;
  const readiness = deriveReadiness({
    inventoryCount: rows.length, inventoryError: err, lastSyncIso,
    ingestion: ingestion as IngestionSource[] | undefined,
  });
  const connectedAccounts = new Set(rows.map((r) => r.account_id).filter(Boolean)).size;
  const summary = summarize(readiness, connectedAccounts);
  // Data mode from MEASURED provenance: the backend reports which inventory
  // files carry the live-poller collection stamp (hard-coding "fixture" here
  // understated a live deployment — #105).
  const mode: DataMode = deriveDataMode({
    inventoryCount: rows.length,
    connector: deriveConnectorKind(connectors, rows.length),
  });

  return { scope, mode, summary, loading, options };
}
