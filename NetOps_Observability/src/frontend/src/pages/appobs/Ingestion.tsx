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
import { ReadinessStrip, FreshnessBadge } from "./shell";
import { isResumable } from "./connectorWizard";
import {
  SOURCE_TYPES, SOURCE_LABEL, SourceReadiness, IngestionSource, STATUS_META, summarize, freshnessLabel, sinceLabel, isMeasured,
} from "./readiness";
import { mergeAccounts, buildMatrix, MergedAccountRow, ProviderIngestion, RegionReadiness } from "./ingestion";
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
  const [connectors, setConnectors] = useState<CloudConnectorView[]>([]);
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
      // the connector store — accounts exist because they are CONFIGURED
      // (Wave 2 #4), not merely because inventory arrived. Failure (e.g. the
      // 501 no-store deployment) falls back to discovered-only rows.
      api.cloudConnectors().catch(() => ({ connectors: [] as CloudConnectorView[] })),
    ]).then(
      ([r, ing, conn]) => {
        if (!live) return;
        setRows(r.resources ?? []);
        setByProvider((ing.providers ?? {}) as ProviderIngestion);
        setConnectors(conn.connectors ?? []);
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

  const accounts = mergeAccounts(connectors, rows, byProvider);
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
        <Accounts accounts={accounts} onNew={openWizard} onResume={openResume}
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
// Connector-first (Wave 2 #4): a row exists because a connection is CONFIGURED
// (or the deployment's ambient account delivered data) — never only because
// inventory arrived. Identity and telemetry are separate columns: "connection
// OK / telemetry silent" is a red attention row, distinct from "connection
// broken" and from "healthy".

// Telemetry column: the honest data-side verdict, independent of identity.
function TelemetryCell({ a }: { a: MergedAccountRow }) {
  if (a.telemetry === "silent") {
    return <span style={{ color: "var(--crit)" }} title="the connection has produced no data within its expected cadence">No data arriving</span>;
  }
  return <FreshnessBadge iso={a.lastSyncIso} status={a.telemetry === "stale" ? "stale" : "flowing"} />;
}

function Accounts({ accounts, onNew, onResume, connections }: {
  accounts: MergedAccountRow[]; onNew: () => void;
  onResume: (c: CloudConnectorView) => void;
  /** The connector-store truth (Connections list) — rendered above the
   *  merged accounts so setup-stage detail stays one click away. */
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
          title="No cloud accounts yet"
          hint="Accounts appear here as soon as a connection is configured — including before any data arrives — use “Connect a cloud account” above to link one." /></div>
      ) : (
        <div className="ao-panel">
          <div className="ao-panel-h">Accounts <span className="ao-panel-meta">connection health and data delivery are judged separately · a configured account never disappears for lack of data</span></div>
          <DataTable<MergedAccountRow> rows={accounts} rowKey={(a) => a.key}
            height={Math.min(360, 44 + accounts.length * 30)} ariaLabel="Cloud accounts"
            onRowClick={goIntegrations}
            rowClassName={(a) => (a.state.attention ? "ao-row--attention" : "")}
            columns={[
              { key: "provider", header: "Provider", width: 80, sortValue: (a) => a.provider, render: (a) => PROVIDER(a.provider) },
              {
                key: "acct", header: "Account / Subscription / Project", width: 210, sortValue: (a) => a.accountId,
                render: (a) => <span className="ao-mono" title={a.tenant ? `tenant: ${a.tenant}` : undefined}>{a.accountId}</span>,
              },
              {
                key: "name", header: "Connection", width: 150, sortValue: (a) => a.name,
                render: (a) => a.name ? a.name : <span className="ao-muted">{a.connector ? "Untitled" : "Discovered"}</span>,
              },
              {
                key: "identity", header: "Connection health", width: 160, sortValue: (a) => a.connectionLabel,
                render: (a) => <span className="ccw-statedot"><i style={{ background: a.connectionTone }} aria-hidden="true" />{a.connectionLabel}</span>,
              },
              { key: "telemetry", header: "Data delivery", width: 130, sortValue: (a) => a.telemetry, render: (a) => <TelemetryCell a={a} /> },
              { key: "flowing", header: "Flowing sources", width: 120, align: "right", sortValue: (a) => a.flowingSources, render: (a) => `${a.flowingSources} of ${SOURCE_TYPES.length}` },
              { key: "regions", header: "Regions", width: 140, sortValue: (a) => a.regions.length, render: (a) => a.regions.join(", ") || "—" },
              { key: "sync", header: "Last data", width: 110, sortValue: (a) => timeRank(a.lastSyncIso), render: (a) => a.lastSyncIso ? freshnessLabel(a.lastSyncIso) : <span className="ao-muted">never</span> },
              {
                key: "status", header: "Status", width: 210, sortValue: (a) => Number(a.state.attention) * 2 + Number(a.state.tone === "var(--warn)"),
                render: (a) => <span className="ccw-statedot"><i style={{ background: a.state.tone }} aria-hidden="true" />{a.state.label}</span>,
              },
              {
                key: "act", header: "Actions", width: 110, render: (a) => (
                  a.connector && isResumable(a.connector)
                    ? <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); onResume(a.connector!); }}>Resume setup</button>
                    : <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); goIntegrations(); }}>Manage</button>
                ),
              },
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
  // Poller-reported failure (Wave 2 #4): the chip answers the actual operator
  // question — "IAM denied flow logs since Tuesday", not just "off".
  const errored = r.status === "permission_denied" || r.status === "misconfigured";
  const since = errored ? sinceLabel(r.sinceIso) : "";
  const title = `${SOURCE_LABEL[r.sourceType]}: ${meta.label}` +
    (errored && since ? ` ${since}` : "") +
    (errored && r.lastError ? ` · ${r.lastError}` : "") +
    (measured && r.lastSyncIso ? ` · updated ${freshnessLabel(r.lastSyncIso)}` : "") +
    (r.volume != null && measured ? ` · ${r.volume} resources` : "");
  return (
    <span className={`ao-srccell${measured ? " is-on" : ""}`} title={title}>
      <span className="ao-srccell-dot" style={{ background: meta.tone }} />
      <span className="ao-srccell-l">{SOURCE_LABEL[r.sourceType]}</span>
      {detailed && measured && <span className="ao-srccell-meta">{freshnessLabel(r.lastSyncIso)}{r.volume != null ? ` · ${r.volume}` : ""}</span>}
      {detailed && !measured && errored && (
        <span className="ao-srccell-meta" style={{ color: "var(--crit)" }}>
          {meta.label.toLowerCase()}{since ? ` ${since}` : ""}
        </span>
      )}
      {detailed && !measured && !errored && <span className="ao-srccell-meta ao-muted">{meta.label.toLowerCase()}</span>}
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
