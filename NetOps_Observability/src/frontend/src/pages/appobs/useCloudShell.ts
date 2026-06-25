// App Observability — shell data hook (#81 P3F+1).
//
// Loads the live cloud inventory ONCE and derives the global scope + data mode +
// readiness summary the CloudScopeBar / ReadinessStrip render. Honest by
// construction: an empty inventory ⇒ "No cloud data connected" and every
// not-yet-ingested source reports "off" (see readiness.ts). A load error ⇒
// inventory "off", not a fabricated healthy state.

import { useEffect, useState } from "react";
import { api, CloudResourceRow } from "../../services/api";
import { useAuth } from "../../hooks/useAuth";
import {
  deriveScope, deriveReadiness, deriveDataMode, summarize,
  CloudScope, DataMode, ReadinessSummary,
} from "./readiness";

export interface CloudShell {
  scope: CloudScope;
  mode: DataMode;
  summary: ReadinessSummary;
  loading: boolean;
}

export function useCloudShell(): CloudShell {
  const { user } = useAuth();
  const [rows, setRows] = useState<CloudResourceRow[]>([]);
  const [err, setErr] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let live = true;
    api.cloudResources().then(
      (r) => { if (live) { setRows(r.resources ?? []); setLoading(false); } },
      () => { if (live) { setErr(true); setLoading(false); } },
    );
    return () => { live = false; };
  }, []);

  const tenant = user?.all_tenants ? "All tenants" : (user?.tenant_id || "—");
  const scope = deriveScope(
    rows.map((r) => ({ provider: r.cloud_provider, account: r.account_id, region: r.region, env: r.env })),
    tenant,
  );
  // freshest last_seen across the inventory = the inventory's effective sync time.
  const lastSyncIso = rows.reduce((acc, r) => (r.last_seen_at > acc ? r.last_seen_at : acc), "") || undefined;
  const readiness = deriveReadiness({ inventoryCount: rows.length, inventoryError: err, lastSyncIso });
  const connectedAccounts = new Set(rows.map((r) => r.account_id).filter(Boolean)).size;
  const summary = summarize(readiness, connectedAccounts);
  // No real per-tenant SDK connector exists yet — inventory present ⇒ fixture/demo.
  const mode: DataMode = deriveDataMode({ inventoryCount: rows.length, connector: rows.length ? "fixture" : "none" });

  return { scope, mode, summary, loading };
}
