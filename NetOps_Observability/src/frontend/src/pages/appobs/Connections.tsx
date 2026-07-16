// Cloud Connections list (backlog Wave 1 #3 — the wizard's companion surface).
//
// Renders the tenant's connectors EXACTLY as the connector API returns them
// (GET /api/cloud/connectors — tenant-scoped server-side, owner stamped from the
// token): honest lifecycle status (enabled / validated / failed / incomplete),
// provider, authentication mode, identity health and scope. An incomplete
// connector can be resumed in the wizard at the first step that still needs
// work; setup-stage connectors can be removed. Nothing here is derived from
// discovered inventory — this table is the stored connection truth, while the
// Accounts table below it shows what inventory actually arrived.

import { useEffect, useState } from "react";
import { api, CloudConnectorView } from "../../services/api";
import DataTable from "../../components/DataTable";
import { Skeleton } from "../../components/ui";
import { EmptyState, ProviderBadge } from "./badges";
import { freshnessLabel } from "./readiness";
import { timeRank } from "./sortRanks";
import {
  METHOD_LABEL, connectorStatus, isResumable, scopeSummary, healthLabel, healthTone, errText,
} from "./connectorWizard";

export default function Connections({ nonce, onConnect, onResume }: {
  /** Bump to re-read the connector store (e.g. after the wizard closes). */
  nonce: number;
  onConnect: () => void;
  onResume: (view: CloudConnectorView) => void;
}) {
  const [rows, setRows] = useState<CloudConnectorView[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string>("");
  const [localNonce, setLocalNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setState("loading");
    api.cloudConnectors().then(
      (r) => { if (live) { setRows(r.connectors ?? []); setState("ready"); } },
      (e) => { if (live) { setError(errText(e)); setState("error"); } },
    );
    return () => { live = false; };
  }, [nonce, localNonce]);

  const remove = async (c: CloudConnectorView) => {
    if (!window.confirm(`Remove the connection "${c.display_name || c.id}"?\n\nIts stored trust metadata (and any encrypted credential) is deleted. This cannot be undone.`)) return;
    try {
      await api.cloudDeleteConnector(c.id);
      setLocalNonce((n) => n + 1);
    } catch (e) { setError(errText(e)); setState("error"); }
  };

  if (state === "loading") {
    return <div className="ao-panel"><Skeleton w={200} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={120} /></div></div>;
  }
  if (state === "error") {
    // The API's real message — no fake success, no silent hiding.
    return (
      <div className="ao-panel">
        <EmptyState title="Unable to load cloud connections" hint={error}
          action={<button className="ao-btn" onClick={() => setLocalNonce((n) => n + 1)}>Retry</button>} />
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="ao-panel">
        <EmptyState title="No cloud connections yet"
          hint="Connect an AWS / Azure / GCP account — the guided setup walks you through trust, scope and a live validation."
          action={<button className="ao-btn ao-btn--primary" onClick={onConnect}>Connect a cloud account</button>} />
      </div>
    );
  }

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Cloud connections
        <span className="ao-panel-meta">the stored connection truth · resume an incomplete setup where it left off</span>
      </div>
      <DataTable<CloudConnectorView>
        rows={rows} rowKey={(c) => c.id} ariaLabel="Cloud connections"
        height={Math.min(320, 44 + rows.length * 30)}
        initialSort={{ key: "updated", dir: "desc" }}
        columns={[
          {
            key: "name", header: "Name", width: 200, sortValue: (c) => c.display_name || c.id,
            text: (c) => c.display_name, render: (c) => c.display_name || <span className="ao-muted">Untitled</span>,
          },
          {
            key: "provider", header: "Provider", width: 110, sortValue: (c) => c.provider,
            render: (c) => <ProviderBadge provider={c.provider} />,
          },
          {
            key: "auth", header: "Authentication", width: 190, sortValue: (c) => c.auth_method || "",
            render: (c) => c.auth_method
              ? <span>{METHOD_LABEL[c.auth_method]}{c.auth_federated ? <span className="ao-muted"> · secretless</span> : c.auth_legacy ? <span className="ao-muted"> · stored credential</span> : null}</span>
              : <span className="ao-muted">not chosen</span>,
          },
          {
            key: "status", header: "Status", width: 170, sortValue: (c) => connectorStatus(c).label,
            render: (c) => {
              const s = connectorStatus(c);
              return <span className="ccw-statedot"><i style={{ background: s.tone }} aria-hidden="true" />{s.label}</span>;
            },
          },
          {
            key: "identity", header: "Identity", width: 130, sortValue: (c) => c.identity_health?.state ?? "",
            render: (c) => (
              <span style={{ color: healthTone(c.identity_health?.state ?? "") }}
                title={c.identity_health?.detail || undefined}>
                {healthLabel(c.identity_health?.state ?? "")}
              </span>
            ),
          },
          {
            key: "scope", header: "Scope", width: 180, sortValue: (c) => scopeSummary(c),
            render: (c) => <span className="ao-mono">{scopeSummary(c)}</span>,
          },
          {
            key: "updated", header: "Updated", width: 110, sortValue: (c) => timeRank(c.updated_at),
            render: (c) => <span className="ao-muted">{freshnessLabel(c.updated_at)}</span>,
          },
          {
            key: "act", header: "Actions", width: 170, render: (c) => (
              <span style={{ display: "inline-flex", gap: 6 }}>
                {isResumable(c) && (
                  <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); onResume(c); }}>
                    Resume setup
                  </button>
                )}
                {!c.collecting && (
                  <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); void remove(c); }}>
                    Remove
                  </button>
                )}
              </span>
            ),
          },
        ]}
      />
    </div>
  );
}
