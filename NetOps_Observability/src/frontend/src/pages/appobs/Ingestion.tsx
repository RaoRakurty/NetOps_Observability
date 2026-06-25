// App Observability — Ingestion / Connections (#81 P3F+1 Phase 2).
//
// The trust gate: before any page claims app health/RCA, prove the cloud data is
// connected, flowing, stale or off. Three sub-tabs — Accounts (what's connected),
// Sources (what we ingest per region), Ingestion Status (is data actually
// arriving). Honest by construction: only the inventory source is live today, so
// every other source reads "off" per region — never a fabricated "flowing".

import { useEffect, useState } from "react";
import { api, CloudResourceRow } from "../../services/api";
import { Skeleton } from "../../components/ui";
import { EmptyState } from "./badges";
import { ReadinessStrip, SourceStatusBadge, FreshnessBadge } from "./shell";
import {
  SOURCE_TYPES, SOURCE_LABEL, SourceReadiness, STATUS_META, summarize, freshnessLabel, isMeasured,
} from "./readiness";
import { buildAccounts, buildMatrix, CloudAccount, RegionReadiness } from "./ingestion";

type Sub = "accounts" | "sources" | "status";
const PROVIDER = (p: string) => (p ? p.toUpperCase() : "—");
const goIntegrations = () => { location.hash = "#/incident/integrations"; };

export default function Ingestion() {
  const [sub, setSub] = useState<Sub>("status");
  const [rows, setRows] = useState<CloudResourceRow[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    let live = true;
    api.cloudResources().then(
      (r) => { if (live) { setRows(r.resources ?? []); setState("ready"); } },
      () => { if (live) setState("error"); },
    );
    return () => { live = false; };
  }, []);

  if (state === "loading") {
    return <div className="ao-stack"><div className="ao-panel"><Skeleton w={220} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={260} /></div></div></div>;
  }
  if (state === "error") {
    return <div className="ao-panel"><EmptyState title="Unable to load ingestion status" hint="retry, or open Admin → Integrations to check the cloud connectors" action={<button className="ao-btn" onClick={goIntegrations}>Open Integrations</button>} /></div>;
  }

  const accounts = buildAccounts(rows);
  const matrix = buildMatrix(rows);

  return (
    <div className="ao-stack">
      <div className="ao-tabs ao-tabs--sub" role="tablist" aria-label="Ingestion">
        <button role="tab" aria-selected={sub === "accounts"} className={`ao-tab${sub === "accounts" ? " is-active" : ""}`} onClick={() => setSub("accounts")}>Accounts</button>
        <button role="tab" aria-selected={sub === "sources"} className={`ao-tab${sub === "sources" ? " is-active" : ""}`} onClick={() => setSub("sources")}>Sources</button>
        <button role="tab" aria-selected={sub === "status"} className={`ao-tab${sub === "status" ? " is-active" : ""}`} onClick={() => setSub("status")}>Ingestion Status</button>
      </div>

      {sub === "accounts" && <Accounts accounts={accounts} />}
      {sub === "sources" && <Sources matrix={matrix} />}
      {sub === "status" && <Status matrix={matrix} />}
    </div>
  );
}

// ── Accounts ──────────────────────────────────────────────────────────────────
function Accounts({ accounts }: { accounts: CloudAccount[] }) {
  return (
    <div className="ao-stack">
      <div className="ao-cta">
        <span className="ao-cta-h">Connect and scope AWS, Azure, and GCP accounts for observability.</span>
        <div className="ao-cta-btns">
          <button className="ao-btn ao-btn--primary" onClick={goIntegrations}>Connect AWS</button>
          <button className="ao-btn" onClick={goIntegrations}>Connect Azure</button>
          <button className="ao-btn" onClick={goIntegrations}>Connect GCP</button>
          <button className="ao-btn" onClick={goIntegrations}>View IAM Instructions</button>
          <button className="ao-btn" onClick={goIntegrations}>Open Admin → Integrations</button>
        </div>
      </div>
      {accounts.length === 0 ? (
        <div className="ao-panel"><EmptyState
          title="No cloud accounts connected yet"
          hint="Connect AWS / Azure / GCP from Integrations to begin observability."
          action={<button className="ao-btn ao-btn--primary" onClick={goIntegrations}>Open Integrations</button>} /></div>
      ) : (
        <div className="ao-panel">
          <div className="ao-panel-h">Connected accounts <span className="ao-panel-meta">connection management lives in Admin → Integrations</span></div>
          <div className="ao-table-wrap">
            <table className="ao-tbl">
              <thead><tr>
                <th>Provider</th><th>Account / Subscription / Project</th><th>Tenant</th><th>Regions</th>
                <th>Enabled sources</th><th>Connection</th><th>Permission</th><th>Last sync</th><th>Actions</th>
              </tr></thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.provider + a.accountId}>
                    <td>{PROVIDER(a.provider)}</td>
                    <td><span className="ao-mono">{a.accountId}</span></td>
                    <td className="ao-muted">global</td>
                    <td>{a.regions.join(", ") || "—"}</td>
                    <td>{a.enabledSources} of {SOURCE_TYPES.length}</td>
                    <td><SourceStatusBadge status={a.status} /></td>
                    <td className="ao-muted" title="permission probing arrives with the live cloud connector">not checked</td>
                    <td><FreshnessBadge iso={a.lastSyncIso} status={a.status} /></td>
                    <td><button className="ao-rowaction" onClick={goIntegrations}>Manage</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sources (what we ingest per account/region) ───────────────────────────────
function Sources({ matrix }: { matrix: RegionReadiness[] }) {
  if (matrix.length === 0) return <CloudEmpty />;
  return (
    <div className="ao-stack">
      <div className="ao-panel">
        <div className="ao-panel-h">Sources by account &amp; region <span className="ao-panel-meta">what Correlix ingests · only inventory is live today</span></div>
        <SourceMatrix rows={matrix} detailed={false} />
      </div>
    </div>
  );
}

// ── Ingestion Status (is data actually arriving?) ─────────────────────────────
function Status({ matrix }: { matrix: RegionReadiness[] }) {
  // a flat readiness across all regions for the summary cards.
  const all = matrix.flatMap((m) => m.readiness);
  const accounts = new Set(matrix.map((m) => m.accountId)).size;
  const summary = summarize(all, accounts);
  if (matrix.length === 0) return (
    <div className="ao-stack"><ReadinessStrip summary={summary} /><CloudEmpty /></div>
  );
  return (
    <div className="ao-stack">
      <ReadinessStrip summary={summary} />
      <div className="ao-panel">
        <div className="ao-panel-h">Verify whether cloud observability data is actually arriving
          <span className="ao-panel-meta">per account × region × source · last sync + volume</span></div>
        <SourceMatrix rows={matrix} detailed />
      </div>
      <div className="ao-panel ao-remediation">
        <div className="ao-panel-h">Remediation</div>
        <p className="ao-set-d">When a source is off, stale or permission-denied, fix it at the connector — Correlix never fabricates the missing signal.</p>
        <div className="ao-cta-btns">
          <button className="ao-btn" onClick={goIntegrations}>Fix IAM / permissions</button>
          <button className="ao-btn" onClick={goIntegrations}>Enable a source</button>
          <button className="ao-btn" onClick={goIntegrations}>Check log bucket</button>
          <button className="ao-btn" onClick={goIntegrations}>Re-run sync</button>
          <button className="ao-btn" onClick={goIntegrations}>Open integration</button>
        </div>
      </div>
    </div>
  );
}

// ── Shared matrix ─────────────────────────────────────────────────────────────
function SourceCell({ r, detailed }: { r: SourceReadiness; detailed: boolean }) {
  const meta = STATUS_META[r.status];
  const measured = isMeasured(r.status);
  const title = `${SOURCE_LABEL[r.sourceType]}: ${meta.label}` +
    (measured && r.lastSyncIso ? ` · updated ${freshnessLabel(r.lastSyncIso)}` : "") +
    (r.volume != null && measured ? ` · ${r.volume} resources` : "");
  return (
    <span className={`ao-srccell${measured ? " is-on" : ""}`} title={title}>
      <span className="ao-srccell-dot" style={{ background: meta.tone }} />
      <span className="ao-srccell-l">{SOURCE_LABEL[r.sourceType]}</span>
      {detailed && measured && <span className="ao-srccell-meta">{freshnessLabel(r.lastSyncIso)}{r.volume != null ? ` · ${r.volume}` : ""}</span>}
      {detailed && !measured && <span className="ao-srccell-meta ao-muted">{meta.label.toLowerCase()}</span>}
    </span>
  );
}

function SourceMatrix({ rows, detailed }: { rows: RegionReadiness[]; detailed: boolean }) {
  return (
    <div className="ao-matrix">
      {rows.map((row) => (
        <div className="ao-matrix-row" key={row.provider + row.accountId + row.region}>
          <div className="ao-matrix-scope">
            <span className="ao-matrix-prov">{PROVIDER(row.provider)}</span>
            <span className="ao-mono ao-muted">{row.accountId}</span>
            <span className="ao-matrix-region">{row.region}</span>
            <span className="ao-matrix-count">{row.resourceCount} resources</span>
          </div>
          <div className="ao-matrix-cells">
            {row.readiness.map((r) => <SourceCell key={r.sourceType} r={r} detailed={detailed} />)}
          </div>
        </div>
      ))}
    </div>
  );
}

function CloudEmpty() {
  return <div className="ao-panel"><EmptyState
    title="No cloud inventory yet"
    hint="connect an AWS / Azure / GCP account in Integrations — sources appear here as data starts arriving"
    action={<button className="ao-btn ao-btn--primary" onClick={goIntegrations}>Open Integrations</button>} /></div>;
}
