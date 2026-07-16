// App Observability — Ingestion / Connections (#81 P3F+1 Phase 2).
//
// The trust gate: before any page claims app health/RCA, prove the cloud data is
// connected, flowing, stale or off. Three sub-tabs — Accounts (what's connected),
// Sources (what we ingest per region), Ingestion Status (is data actually
// arriving). Honest by construction: only the inventory source is live today, so
// every other source reads "off" per region — never a fabricated "flowing".

import { ReactNode, useEffect, useState } from "react";
import { api, CloudResourceRow, CloudConnectorView } from "../../services/api";
import { fetchCloudInventory, invalidateCloudInventory } from "./api";
import { Skeleton } from "../../components/ui";
import DataTable from "../../components/DataTable";
import { EmptyState } from "./badges";
import { timeRank } from "./sortRanks";
import { ReadinessStrip, SourceStatusBadge, FreshnessBadge } from "./shell";
import {
  SOURCE_TYPES, SOURCE_LABEL, SourceReadiness, IngestionSource, STATUS_META, summarize, freshnessLabel, isMeasured,
} from "./readiness";
import { buildAccounts, buildMatrix, CloudAccount, ProviderIngestion, RegionReadiness } from "./ingestion";
import ConnectorWizard from "./ConnectorWizard";
import Connections from "./Connections";

type Sub = "accounts" | "sources" | "status";
const PROVIDER = (p: string) => (p ? p.toUpperCase() : "—");
const goIntegrations = () => { location.hash = "#/incident/integrations"; };

const isSub = (v: string): v is Sub => v === "accounts" || v === "sources" || v === "status";

export default function Ingestion({ initialSub = "" }: { initialSub?: string }) {
  // Deep-link target (e.g. Settings → "Connect a cloud account" lands on
  // Accounts). Defaults to Ingestion Status — the trust gate — when unspecified.
  const [sub, setSub] = useState<Sub>(() => (isSub(initialSub) ? initialSub : "status"));
  // A hash change while this component is already mounted must still move the
  // sub-tab; the mount-time initializer alone would silently ignore it.
  useEffect(() => {
    if (isSub(initialSub)) setSub(initialSub);
  }, [initialSub]);
  const [rows, setRows] = useState<CloudResourceRow[]>([]);
  const [byProvider, setByProvider] = useState<ProviderIngestion>({});
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  // Cloud Connector onboarding wizard (Wave 1 #3) — the in-product "connect a
  // cloud account" flow over the done 7-step connector API. `wizard` carries an
  // optional connector to RESUME (re-opened at the first step that still needs
  // work); `nonce` re-reads inventory + connections after the wizard closes.
  const [wizard, setWizard] = useState<{ resume?: CloudConnectorView } | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    Promise.all([
      fetchCloudInventory(), // shared 30s-TTL inventory read (review #14)
      // measured per-provider statuses (audit P0-7); failure keeps the honest
      // inventory-only default — never a fabricated "flowing".
      api.cloudIngestion().catch(() => ({ providers: {} as Record<string, IngestionSource[]> })),
    ]).then(
      ([r, ing]) => {
        if (!live) return;
        setRows(r.resources ?? []);
        setByProvider((ing.providers ?? {}) as ProviderIngestion);
        setState("ready");
      },
      () => { if (live) setState("error"); },
    );
    return () => { live = false; };
  }, [nonce]);

  if (state === "loading") {
    return <div className="ao-stack"><div className="ao-panel"><Skeleton w={220} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={260} /></div></div></div>;
  }
  if (state === "error") {
    return <div className="ao-panel"><EmptyState title="Unable to load ingestion status" hint="retry, or open Admin → Integrations to check the cloud connectors" action={<button className="ao-btn" onClick={goIntegrations}>Open Integrations</button>} /></div>;
  }

  const accounts = buildAccounts(rows, byProvider);
  const matrix = buildMatrix(rows, byProvider);
  const openWizard = () => setWizard({});
  const openResume = (c: CloudConnectorView) => setWizard({ resume: c });
  // The wizard mutates the connector store step-by-step, so closing it (even
  // mid-flow) must re-read the connections list — not only a full activation.
  const closeWizard = () => { setWizard(null); setNonce((n) => n + 1); };

  return (
    <div className="ao-stack">
      <div className="ao-tabs ao-tabs--sub" role="tablist" aria-label="Ingestion">
        <button role="tab" aria-selected={sub === "accounts"} className={`ao-tab${sub === "accounts" ? " is-active" : ""}`} onClick={() => setSub("accounts")}>Accounts</button>
        <button role="tab" aria-selected={sub === "sources"} className={`ao-tab${sub === "sources" ? " is-active" : ""}`} onClick={() => setSub("sources")}>Sources</button>
        <button role="tab" aria-selected={sub === "status"} className={`ao-tab${sub === "status" ? " is-active" : ""}`} onClick={() => setSub("status")}>Ingestion Status</button>
      </div>

      {sub === "accounts" && (
        <Accounts accounts={accounts} onNew={openWizard}
          connections={<Connections nonce={nonce} onConnect={openWizard} onResume={openResume} />} />
      )}
      {sub === "sources" && <Sources matrix={matrix} />}
      {sub === "status" && <Status matrix={matrix} />}

      {wizard && (
        <ConnectorWizard
          resume={wizard.resume}
          onClose={closeWizard}
          onCreated={() => { invalidateCloudInventory(); setNonce((n) => n + 1); }}
        />
      )}
    </div>
  );
}

// ── Accounts ──────────────────────────────────────────────────────────────────
function Accounts({ accounts, onNew, connections }: {
  accounts: CloudAccount[]; onNew: () => void;
  /** The connector-store truth (Connections list) — rendered above the
   *  inventory-derived accounts so config state and arrived data stay distinct. */
  connections: ReactNode;
}) {
  return (
    <div className="ao-stack">
      <div className="ao-cta">
        <span className="ao-cta-h">Connect and scope AWS, Azure, and GCP accounts for observability.</span>
        {/* The guided onboarding wizard (Wave 1 #3) over the done connector API —
            provider → draft → auth → trust → scope → validate → activate. */}
        <div className="ao-cta-btns">
          <button className="ao-btn ao-btn--primary" onClick={onNew}>Connect a cloud account</button>
          <button className="ao-btn" onClick={goIntegrations}>Manage in Integrations</button>
        </div>
      </div>
      {connections}
      {accounts.length === 0 ? (
        /* No duplicate CTA here: the header bar above already carries the ONE
           "Connect a cloud account" primary action (two stacked identical
           buttons read as a double implementation — user report 2026-07-16). */
        <div className="ao-panel"><EmptyState
          title="No cloud inventory has arrived yet"
          hint="Discovered accounts appear here once an enabled connection starts collecting — use “Connect a cloud account” above to link one." /></div>
      ) : (
        <div className="ao-panel">
          <div className="ao-panel-h">Connected accounts <span className="ao-panel-meta">connection management lives in Admin → Integrations · sort any column · open a row to manage</span></div>
          <DataTable<CloudAccount> rows={accounts} rowKey={(a) => a.provider + a.accountId}
            height={Math.min(360, 44 + accounts.length * 30)} ariaLabel="Connected accounts"
            onRowClick={goIntegrations}
            columns={[
              { key: "provider", header: "Provider", width: 90, sortValue: (a) => a.provider, render: (a) => PROVIDER(a.provider) },
              { key: "acct", header: "Account / Subscription / Project", width: 240, sortValue: (a) => a.accountId, render: (a) => <span className="ao-mono">{a.accountId}</span> },
              { key: "tenant", header: "Tenant", width: 120, sortValue: (a) => a.tenant || "global", render: (a) => <span className="ao-muted">{a.tenant || "global"}</span> },
              { key: "regions", header: "Regions", width: 160, sortValue: (a) => a.regions.length, render: (a) => a.regions.join(", ") || "—" },
              { key: "flowing", header: "Flowing sources", width: 130, align: "right", sortValue: (a) => a.enabledSources, render: (a) => `${a.enabledSources} of ${SOURCE_TYPES.length}` },
              { key: "conn", header: "Connection", width: 130, sortValue: (a) => a.status, render: (a) => <SourceStatusBadge status={a.status} /> },
              { key: "sync", header: "Last sync", width: 120, sortValue: (a) => timeRank(a.lastSyncIso), render: (a) => <FreshnessBadge iso={a.lastSyncIso} status={a.status} /> },
              { key: "act", header: "Actions", width: 100, render: () => <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); goIntegrations(); }}>Manage</button> },
            ]} />
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
        <div className="ao-panel-h">Sources by account &amp; region <span className="ao-panel-meta">what Correlix ingests · each chip is measured per provider</span></div>
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
        <p className="ao-set-d">
          When a source is off, stale or permission-denied, fix it at the connector —
          IAM/permissions, source enablement and log-bucket settings all live there.
          Correlix never fabricates the missing signal.
        </p>
        <div className="ao-cta-btns">
          <button className="ao-btn ao-btn--primary" onClick={goIntegrations}>Open Integrations</button>
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
