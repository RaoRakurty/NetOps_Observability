// App Observability (#81 P3F) — the cloud-native app-to-underlay story under Monitor.
// Identity → Health → Change → Cloud Network → Underlay → RCA, every claim with
// confidence + evidence, unknown first-class. Built entirely on the existing design
// system (NOC kit, ds-*/cc-* classes, var(--*) tokens, Inter/Space-Grotesk/Plex-Mono
// fonts) so it matches the rest of Correlix. Identity surfaces are live from
// /api/cloud/*; not-yet-ingested telemetry is shown as preview, never faked.

import { useEffect, useState } from "react";
import { NocHeader, Chip } from "../components/noc";
import { Skeleton } from "../components/ui";
import DataTable from "../components/DataTable";
import {
  ConfidenceBadge, HealthBadge, RootDomainBadge, AppIdentityPill, MetricCard,
  CardGroup, UnderlayCell, RcaDrawer, EmptyState, FilterBar, EvidenceDrawer,
  fmtBps, fmtBytes, ago,
} from "./appobs/badges";
import AppDetail from "./appobs/AppDetail";
import Ingestion from "./appobs/Ingestion";
import type {
  App, CloudResource, Coverage, EvidenceRow, ImpactedApplication, UnknownContributor,
} from "./appobs/types";
import { loadApps, loadResources, loadCoverage, NOT_MEASURED } from "./appobs/api";
import { useCloudShell } from "./appobs/useCloudShell";
import { CloudScopeBar, ReadinessStrip } from "./appobs/shell";
import type { ReadinessSummary } from "./appobs/readiness";
import {
  mockHealth, mockChanges, mockEvidence,
  mockUnderlay, mockSummary, mockBreakdown, mockImpacted,
} from "./appobs/mock";

// async loader with explicit loading/error/empty states (no fake-data fallback —
// an empty inventory shows an honest "connect a cloud account" state).
function useAsync<T>(fn: () => Promise<T>): { data: T | null; status: LoadState } {
  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<LoadState>("loading");
  useEffect(() => {
    let live = true;
    setStatus("loading");
    fn().then(
      (d) => { if (live) { setData(d); setStatus("ready"); } },
      () => { if (live) setStatus("error"); },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return { data, status };
}

// metric the platform does not measure yet (P3B–D) renders as a muted "—".
const NM = (v: number, fmt: (n: number) => string) =>
  v < 0 ? <span className="ao-muted">—</span> : fmt(v);

// honest banner for surfaces that still render preview/mock data.
function PreviewNote({ what }: { what: string }) {
  return (
    <div className="ao-preview-note">
      <Chip label="preview" tone="var(--fg-subtle)" />
      <span>{what} is not ingested yet — this view shows sample data until cloud telemetry lands (P3B–P3D).</span>
    </div>
  );
}

// shared loading / error / empty states for the live cloud surfaces.
function TableSkeleton() {
  return (
    <div className="ao-stack">
      <div className="ao-panel"><Skeleton w={200} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={300} /></div></div>
    </div>
  );
}
function LoadError({ what }: { what: string }) {
  return <div className="ao-panel"><EmptyState title={`Unable to load ${what}`} hint="retry, or check the cloud connector status in Settings" /></div>;
}
// honest empty: no inventory yet (no connector / no fixtures) — never fabricates rows.
function CloudEmpty() {
  return <div className="ao-panel"><EmptyState title="No cloud inventory yet"
    hint="connect an AWS / Azure / GCP account in Settings (or load inventory fixtures) — identity attribution appears as resources are discovered" /></div>;
}

const TABS = [
  "overview", "ingestion", "applications", "appmap", "resources", "attribution",
  "health", "underlay", "unknowns", "evidence", "settings",
] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview", ingestion: "Ingestion", applications: "Applications", appmap: "App Map",
  resources: "Cloud Resources", attribution: "Attribution", health: "Health & Changes",
  underlay: "Underlay Impact", unknowns: "Unknowns", evidence: "Evidence", settings: "Settings",
};
// Tabs backed by live data (the /api/cloud/* identity surfaces + the inventory-
// derived ingestion readiness). The rest still render preview data pending cloud
// telemetry ingestion (P3B–P3D).
const LIVE_TABS = new Set<Tab>(["ingestion", "applications", "resources", "attribution", "unknowns"]);

export default function AppObservability() {
  const [tab, setTab] = useState<Tab>("overview");
  const [sel, setSel] = useState<App | null>(null);
  const shell = useCloudShell();

  // deep-link: #/monitoring/appobs/applications → opens that tab
  useEffect(() => {
    const suffix = location.hash.split("/").pop() as Tab;
    if (TABS.includes(suffix)) setTab(suffix);
  }, []);

  if (sel) return <AppDetail app={sel} onBack={() => setSel(null)} />;

  return (
    <div className="ao">
      <NocHeader
        title="App Observability"
        subtitle="Cloud app identity, health, change & app-to-underlay RCA — evidence-grounded"
      />
      <CloudScopeBar scope={shell.scope} mode={shell.mode} summary={shell.summary} />

      <nav className="ao-tabs" role="tablist" aria-label="App Observability">
        {TABS.map((tk) => (
          <button key={tk} role="tab" aria-selected={tab === tk}
            className={`ao-tab${tab === tk ? " is-active" : ""}`} onClick={() => setTab(tk)}
            title={LIVE_TABS.has(tk) ? "Live from cloud inventory" : "Preview — awaits cloud telemetry"}>
            {TAB_LABEL[tk]}
            {!LIVE_TABS.has(tk) && tk !== "settings" && <span className="ao-tab-dot" aria-label="preview" />}
          </button>
        ))}
      </nav>

      {tab === "overview" && <Overview onOpen={setSel} goTab={setTab} summary={shell.summary} />}
      {tab === "ingestion" && <Ingestion />}
      {tab === "applications" && <Applications onOpen={setSel} />}
      {tab === "appmap" && <AppMap />}
      {tab === "resources" && <Resources />}
      {tab === "attribution" && <Attribution />}
      {tab === "health" && <HealthChanges />}
      {tab === "underlay" && <Underlay />}
      {tab === "unknowns" && <Unknowns />}
      {tab === "evidence" && <Evidence />}
      {tab === "settings" && <Settings />}
    </div>
  );
}

// ── Overview ─────────────────────────────────────────────────────────────────
type LoadState = "loading" | "ready" | "error";

// converts an impacted-app row → the App shape App Detail expects (synthesized
// from the row; Overview is preview data until the cloud RCA engine lands).
function toApp(im: ImpactedApplication): App {
  return {
    id: im.id, name: im.name, health: im.health, owner: im.owner, env: im.env,
    confidence: im.confidence, source: "cloud_tag", provider: "aws", account: "—", region: "—",
    resources: 0, trafficBps: im.trafficBps, errorPct: 0, p95ms: 0, unknownPct: 0,
    lastSeen: new Date().toISOString(), lastChange: im.lastChange, primarySymptom: "—",
    rootDomain: im.rootDomain,
    underlayImpacted: im.underlay.kind === "confirmed" || im.underlay.kind === "suspected",
  };
}

function Overview({ onOpen, goTab, summary }: { onOpen: (a: App) => void; goTab: (t: Tab) => void; summary: ReadinessSummary }) {
  const [status, setStatus] = useState<LoadState>("loading");
  const [drawer, setDrawer] = useState<ImpactedApplication | null>(null);
  const s = mockSummary;
  const tr = s.trends ?? {};

  // simulate the async load so the skeleton/empty/error states are real (mock data).
  useEffect(() => { const id = setTimeout(() => setStatus("ready"), 350); return () => clearTimeout(id); }, []);

  if (status === "loading") {
    return (
      <div className="ao-stack">
        <div className="ao-groups">{[0, 1, 2].map((g) => (
          <section className="ao-group" key={g}><Skeleton w={90} h={12} />
            <div className="ao-group-cards">{[0, 1, 2].map((i) => <div className="ao-card" key={i}><Skeleton w={60} h={10} /><Skeleton w={80} h={28} /></div>)}</div>
          </section>
        ))}</div>
        <div className="ao-panel"><Skeleton w={180} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={240} /></div></div>
      </div>
    );
  }
  if (status === "error") {
    return <div className="ao-panel"><EmptyState title="Unable to load App Observability summary" hint="retry, or check the cloud connector status in Settings" /></div>;
  }

  return (
    <div className="ao-stack">
      {/* Readiness BEFORE impact — prove the data is connected before any verdict. */}
      <div className="ao-section-l">Data readiness</div>
      <ReadinessStrip summary={summary} />
      <PreviewNote what="App health, RCA & change correlation" />
      {/* A. grouped operational cards */}
      <div className="ao-groups">
        <CardGroup title="Impact">
          <MetricCard label="Apps Degraded" value={s.appsDegraded} trend={tr.appsDegraded} tone="warn" />
          <MetricCard label="Active App RCA" value={s.activeRca} trend={tr.activeRca} tone="warn" />
          <MetricCard label="Underlay Impacted" value={s.underlayImpacted} trend={tr.underlayImpacted} tone={s.underlayImpacted ? "warn" : "good"} />
        </CardGroup>
        <CardGroup title="Coverage">
          <MetricCard label="Apps Observed" value={s.appsObserved.toLocaleString()} trend={tr.appsObserved} tone="accent" />
          <MetricCard label="Resources Mapped" value={s.resourcesMapped.toLocaleString()} trend={tr.resourcesMapped} />
          <MetricCard label="Unknown Attribution" value={`${s.unknownPct}%`} trend={tr.unknownPct} tone={s.unknownPct > 10 ? "warn" : "good"} />
        </CardGroup>
        <CardGroup title="Change">
          <MetricCard label="Recent Cloud Changes" value={s.recentChanges} trend={tr.recentChanges} />
          <MetricCard label="Deploy-linked Incidents" value={s.deployLinkedIncidents} trend={tr.deployLinkedIncidents} tone={s.deployLinkedIncidents ? "warn" : "good"} />
        </CardGroup>
      </div>

      {/* B. root-domain breakdown strip */}
      <div className="ao-breakdown">
        <span className="ao-breakdown-l">Root domain breakdown</span>
        {mockBreakdown.map((b) => (
          <span className="ao-breakdown-i" key={b.domain}><RootDomainBadge domain={b.domain} /><span className="ao-breakdown-n">{b.count}</span></span>
        ))}
      </div>

      {/* C. impacted applications table */}
      <div className="ao-panel">
        <div className="ao-panel-h">Impacted applications <span className="ao-panel-meta">click a row for the RCA + evidence</span></div>
        {mockImpacted.length === 0 ? (
          <EmptyState title="No impacted applications in selected time range" hint="all observed apps are healthy" />
        ) : (
          <DataTable<ImpactedApplication> rows={mockImpacted} rowKey={(a) => a.id} height={Math.min(460, 56 + mockImpacted.length * 34)}
            ariaLabel="Impacted applications" onRowClick={setDrawer} initialSort={{ key: "health", dir: "asc" }}
            columns={[
              { key: "app", header: "App", width: 130, sortable: true, text: (a) => a.name, render: (a) => <strong>{a.name}</strong> },
              { key: "health", header: "Health", width: 100, sortable: true, sortValue: (a) => a.health, render: (a) => <HealthBadge status={a.health} /> },
              { key: "owner", header: "Owner", width: 90, render: (a) => a.owner },
              { key: "env", header: "Env", width: 56, render: (a) => a.env },
              { key: "symptom", header: "Symptom", width: 130, render: (a) => a.symptom },
              { key: "domain", header: "Likely Root", width: 150, render: (a) => <RootDomainBadge domain={a.rootDomain} /> },
              { key: "conf", header: "Confidence", width: 112, render: (a) => <ConfidenceBadge level={a.confidence} /> },
              { key: "why", header: "Why", width: 340, render: (a) => <span className="ao-why" title={a.why}>{a.why}</span> },
              { key: "traffic", header: "Traffic", width: 96, align: "right", render: (a) => fmtBps(a.trafficBps) },
              { key: "change", header: "Last Change", width: 100, render: (a) => ago(a.lastChange) },
              { key: "underlay", header: "Underlay", width: 150, render: (a) => <UnderlayCell u={a.underlay} /> },
              { key: "action", header: "Action", width: 200, render: (a) => <button className="ao-rowaction ao-rowaction--wide" title={a.action} onClick={(e) => { e.stopPropagation(); setDrawer(a); }}>{a.action}</button> },
            ]} />
        )}
      </div>

      {drawer && (
        <RcaDrawer rca={drawer.rca} onClose={() => setDrawer(null)}
          onViewDetail={() => { onOpen(toApp(drawer)); setDrawer(null); }}
          onOpenEvidence={() => { goTab("evidence"); setDrawer(null); }}
          onViewUnderlay={() => { goTab("underlay"); setDrawer(null); }} />
      )}
    </div>
  );
}

// ── Applications (LIVE: /api/cloud/apps) ─────────────────────────────────────
function Applications({ onOpen }: { onOpen: (a: App) => void }) {
  const [f, setF] = useState<Record<string, string>>({});
  const { data, status } = useAsync(loadApps);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="applications" />;
  const apps = data ?? [];
  if (apps.length === 0) return <CloudEmpty />;
  const rows = apps.filter((a) =>
    (!f.provider || a.provider === f.provider) &&
    (!f.env || a.env === f.env) &&
    (!f.confidence || a.confidence === f.confidence) &&
    (!f.source || a.source === f.source));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: [{ value: "aws", label: "AWS" }, { value: "azure", label: "Azure" }, { value: "gcp", label: "GCP" }] },
          { key: "env", label: "Env", options: [...new Set(apps.map((a) => a.env))].filter((e) => e && e !== "—").map((e) => ({ value: e, label: e })) },
          { key: "confidence", label: "Confidence", options: [{ value: "confirmed", label: "confirmed" }, { value: "strong", label: "strong" }, { value: "suspected", label: "suspected" }, { value: "unknown", label: "unknown" }] },
          { key: "source", label: "Identity src", options: [{ value: "cloud_tag", label: "cloud tag" }, { value: "cloud_graph", label: "resource graph" }, { value: "operator_catalog", label: "operator" }, { value: "firewall_appid", label: "firewall" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<App> rows={rows} rowKey={(a) => a.id} height={Math.min(520, 44 + rows.length * 30)}
          ariaLabel="Applications" onRowClick={onOpen} initialSort={{ key: "name", dir: "asc" }}
          columns={[
            { key: "name", header: "App", width: 160, sortable: true, text: (a) => a.name, render: (a) => <strong>{a.name}</strong> },
            { key: "health", header: "Health", width: 100, render: (a) => <HealthBadge status={a.health} /> },
            { key: "owner", header: "Owner", width: 100, render: (a) => a.owner },
            { key: "env", header: "Env", width: 60, render: (a) => a.env },
            { key: "conf", header: "Confidence", width: 110, sortable: true, sortValue: (a) => a.confidence, render: (a) => <ConfidenceBadge level={a.confidence} /> },
            { key: "src", header: "Identity src", width: 120, render: (a) => a.source },
            { key: "provider", header: "Cloud", width: 70, render: (a) => a.provider === "—" ? "—" : a.provider.toUpperCase() },
            { key: "acct", header: "Account", width: 130, render: (a) => <span className="ao-mono ao-muted">{a.account}</span> },
            { key: "region", header: "Region", width: 100, render: (a) => a.region },
            { key: "res", header: "Res", width: 50, align: "right", sortable: true, sortValue: (a) => a.resources, render: (a) => a.resources },
            { key: "traffic", header: "Traffic", width: 95, align: "right", render: (a) => NM(a.trafficBps, fmtBps) },
            { key: "err", header: "Err%", width: 60, align: "right", render: (a) => NM(a.errorPct, (n) => `${n}%`) },
            { key: "p95", header: "P95", width: 70, align: "right", render: (a) => a.p95ms ? `${a.p95ms}ms` : <span className="ao-muted">—</span> },
          ]} />
      </div>
    </div>
  );
}

// ── App Map (graph-ready placeholder) ────────────────────────────────────────
function AppMap() {
  const nodes = ["Application", "Cloud Resource", "Load Balancer", "Database", "Kubernetes Service", "External SaaS", "Network Seam", "Underlay Device", "Unknown Resource"];
  const edges = ["talks_to", "fronted_by", "runs_on", "depends_on", "egresses_via", "impacted_by", "suspected_cause"];
  return (
    <div className="ao-stack">
      <PreviewNote what="The dependency graph" />
      <div className="ao-panel">
        <div className="ao-panel-h">App dependency map</div>
        <EmptyState title="Graph renders here (React Flow — reuses the Topology Canvas renderer)"
          hint="app → resource → LB → DB → seam → underlay, with suspected_cause edges lit on active RCA" />
      </div>
      <div className="ao-legend-grid">
        <div className="ao-panel"><div className="ao-panel-h">Node categories</div><div className="ao-chips">{nodes.map((n) => <Chip key={n} label={n} tone="var(--accent)" />)}</div></div>
        <div className="ao-panel"><div className="ao-panel-h">Edge categories</div><div className="ao-chips">{edges.map((e) => <Chip key={e} label={e} tone={e === "suspected_cause" || e === "impacted_by" ? "var(--warn)" : "var(--fg-subtle)"} />)}</div></div>
      </div>
    </div>
  );
}

// ── Cloud Resources (LIVE: /api/cloud/resources) ─────────────────────────────
function Resources() {
  const [f, setF] = useState<Record<string, string>>({});
  const { data, status } = useAsync(loadResources);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="cloud resources" />;
  const all = data ?? [];
  if (all.length === 0) return <CloudEmpty />;
  const rows = all.filter((r) =>
    (!f.missing || r.missingTags.includes(f.missing)) &&
    (!f.unknown || (f.unknown === "yes") === (r.app === "")) &&
    (!f.provider || r.provider === f.provider));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: [{ value: "aws", label: "AWS" }, { value: "azure", label: "Azure" }, { value: "gcp", label: "GCP" }] },
          { key: "missing", label: "Missing tag", options: [{ value: "app", label: "app" }, { value: "owner", label: "owner" }, { value: "env", label: "env" }] },
          { key: "unknown", label: "Unknown app", options: [{ value: "yes", label: "yes" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<CloudResource> rows={rows} rowKey={(r) => r.id} height={Math.min(520, 44 + rows.length * 30)} ariaLabel="Cloud resources"
          columns={[
            { key: "name", header: "Resource", width: 180, sortable: true, text: (r) => r.name, render: (r) => <strong>{r.name}</strong> },
            { key: "type", header: "Type", width: 120, render: (r) => r.type },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
            { key: "acct", header: "Account", width: 130, render: (r) => <span className="ao-mono ao-muted">{r.account}</span> },
            { key: "region", header: "Region", width: 100, render: (r) => r.region },
            { key: "app", header: "App", width: 150, render: (r) => <AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /> },
            { key: "owner", header: "Owner", width: 90, render: (r) => r.owner },
            { key: "src", header: "Identity src", width: 120, render: (r) => r.source },
            { key: "conf", header: "Confidence", width: 110, sortable: true, sortValue: (r) => r.confidence, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "health", header: "Health", width: 100, render: (r) => <HealthBadge status={r.health} /> },
            { key: "traffic", header: "Traffic", width: 95, align: "right", render: (r) => NM(r.trafficBps, fmtBps) },
            { key: "tags", header: "Missing tags", width: 130, render: (r) => r.missingTags.length ? <Chip label={r.missingTags.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
          ]} />
      </div>
    </div>
  );
}

// ── Attribution (LIVE: /api/cloud/attribution/coverage) ──────────────────────
function Attribution() {
  const { data, status } = useAsync(loadCoverage);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="attribution coverage" />;
  const c: Coverage = data?.coverage ?? { confirmedTag: 0, strongGraph: 0, firewallAppId: 0, suspectedDomainIp: 0, unknown: 0, total: 0 };
  const unknowns: UnknownContributor[] = data?.unknowns ?? [];
  if (c.total === 0) return <CloudEmpty />;
  const pct = (n: number) => Math.round((n / c.total) * 100);
  return (
    <div className="ao-stack">
      <div className="ao-cards">
        <MetricCard label="Confirmed by tag" value={`${pct(c.confirmedTag)}%`} sub={`${c.confirmedTag}`} tone="good" />
        <MetricCard label="Strong by resource graph" value={`${pct(c.strongGraph)}%`} sub={`${c.strongGraph}`} tone="accent" />
        <MetricCard label="Confirmed by firewall App-ID" value={`${pct(c.firewallAppId)}%`} sub={`${c.firewallAppId}`} tone="good" />
        <MetricCard label="Suspected by domain/IP" value={`${pct(c.suspectedDomainIp)}%`} sub={`${c.suspectedDomainIp}`} tone="warn" />
        <MetricCard label="Unknown" value={`${pct(c.unknown)}%`} sub={`${c.unknown}`} tone={pct(c.unknown) > 10 ? "warn" : undefined} />
      </div>
      <div className="ao-panel">
        <div className="ao-panel-h">Top unknown contributors <span className="ao-panel-meta">tag these to lift coverage · traffic ranking arrives with cloud flow logs</span></div>
        {unknowns.length === 0 ? (
          <EmptyState title="No unattributed resources" hint="every discovered resource has an app identity — coverage is complete" />
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Top unknown contributors"
            columns={[
              { key: "entity", header: "Resource / IP / ENI", width: 220, render: (r) => <span className="ao-mono">{r.entity}</span> },
              { key: "kind", header: "Type", width: 120, render: (r) => r.kind },
              { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
              { key: "region", header: "Region", width: 100, render: (r) => r.region },
              { key: "bytes", header: "Bytes", width: 90, align: "right", render: (r) => NM(r.bytes, fmtBytes) },
              { key: "flows", header: "Flows", width: 80, align: "right", render: (r) => NM(r.flows, (n) => n.toLocaleString()) },
              { key: "missing", header: "Missing", width: 140, render: (r) => r.missingFields.length ? <Chip label={r.missingFields.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
              { key: "rec", header: "Recommendation", width: 260, render: (r) => r.recommendation },
            ]} />
        )}
      </div>
    </div>
  );
}

// ── Health & Changes ─────────────────────────────────────────────────────────
function HealthChanges() {
  const [sub, setSub] = useState<"health" | "changes">("health");
  return (
    <div className="ao-stack">
      <PreviewNote what="Cloud health signals & change events" />
      <div className="ao-tabs ao-tabs--sub">
        <button className={`ao-tab${sub === "health" ? " is-active" : ""}`} onClick={() => setSub("health")}>Health Signals</button>
        <button className={`ao-tab${sub === "changes" ? " is-active" : ""}`} onClick={() => setSub("changes")}>Change Events</button>
      </div>
      {sub === "health" ? (
        <div className="ao-panel">
          <DataTable rows={mockHealth} rowKey={(r) => r.time + r.signal} height={Math.min(480, 44 + mockHealth.length * 30)} ariaLabel="Health signals"
            columns={[
              { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
              { key: "app", header: "App", width: 130, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 140, render: (r) => r.resource },
              { key: "sig", header: "Signal", width: 150, render: (r) => r.signal },
              { key: "state", header: "State", width: 100, render: (r) => <HealthBadge status={r.state} /> },
              { key: "metric", header: "Metric", width: 180, render: (r) => <span className="ao-mono">{r.metric}</span> },
              { key: "cur", header: "Current", width: 80, render: (r) => <strong>{r.current}</strong> },
              { key: "base", header: "Baseline", width: 80, render: (r) => <span className="ao-muted">{r.baseline}</span> },
              { key: "sev", header: "Severity", width: 90, render: (r) => <Chip label={r.severity} tone={r.severity === "critical" ? "var(--crit)" : "var(--warn)"} /> },
              { key: "src", header: "Source", width: 150, render: (r) => r.source },
            ]} />
        </div>
      ) : (
        <div className="ao-panel">
          <DataTable rows={mockChanges} rowKey={(r) => r.time + r.changeType} height={Math.min(480, 44 + mockChanges.length * 30)} ariaLabel="Change events"
            columns={[
              { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
              { key: "app", header: "App", width: 130, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 140, render: (r) => r.resource },
              { key: "type", header: "Change type", width: 170, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
              { key: "actor", header: "Actor", width: 160, render: (r) => <span className="ao-mono">{r.actor}</span> },
              { key: "src", header: "Source", width: 130, render: (r) => r.source },
              { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
              { key: "sym", header: "Related symptoms", width: 200, render: (r) => r.relatedSymptoms.length ? r.relatedSymptoms.join(", ") : <span className="ao-muted">—</span> },
            ]} />
        </div>
      )}
    </div>
  );
}

// ── Underlay Impact ──────────────────────────────────────────────────────────
function Underlay() {
  return (
    <div className="ao-stack">
      <PreviewNote what="App-to-underlay correlation" />
      <div className="ao-cards">
        <MetricCard label="Apps impacted by underlay" value={mockUnderlay.length} tone={mockUnderlay.length ? "warn" : "good"} />
        <MetricCard label="Healthy apps on degraded seam" value={0} />
        <MetricCard label="Apps on DX / VPN / ExpressRoute" value={1} />
        <MetricCard label="Hybrid traffic anomalies" value={1} tone="warn" />
      </div>
      <div className="ao-panel">
        <div className="ao-panel-h">App-to-underlay correlation</div>
        <DataTable rows={mockUnderlay} rowKey={(r) => r.app + r.seam} height={Math.min(360, 44 + mockUnderlay.length * 34)} ariaLabel="Underlay impact"
          columns={[
            { key: "app", header: "App", width: 150, render: (r) => <strong>{r.app}</strong> },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider.toUpperCase() },
            { key: "seam", header: "Seam", width: 130, render: (r) => <Chip label={r.seam} tone="var(--warn)" /> },
            { key: "path", header: "Path", width: 200, render: (r) => r.path },
            { key: "ev", header: "Underlay evidence", width: 260, render: (r) => r.underlayEvidence },
            { key: "sym", header: "App symptom", width: 150, render: (r) => r.appSymptom },
            { key: "domain", header: "Root domain", width: 150, render: (r) => <RootDomainBadge domain={r.rootDomain} /> },
            { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "owner", header: "Owner", width: 90, render: (r) => r.owner },
          ]} />
      </div>
    </div>
  );
}

// ── Unknowns (first-class · LIVE) ────────────────────────────────────────────
function Unknowns() {
  const res = useAsync(loadResources);
  const cov = useAsync(loadCoverage);
  if (res.status === "loading" || cov.status === "loading") return <TableSkeleton />;
  if (res.status === "error" || cov.status === "error") return <LoadError what="unknowns" />;
  const resources = res.data ?? [];
  const unknowns = cov.data?.unknowns ?? [];
  if (resources.length === 0) return <CloudEmpty />;
  const cats: { label: string; n: number; measured: boolean }[] = [
    { label: "Unattributed resources", n: resources.filter((r) => r.app === "").length, measured: true },
    { label: "Unknown owners", n: resources.filter((r) => r.owner === "—").length, measured: true },
    { label: "Unknown environment", n: resources.filter((r) => r.env === "—").length, measured: true },
    { label: "Unknown traffic", n: NOT_MEASURED, measured: false },     // P3B
    { label: "Unknown underlay mapping", n: NOT_MEASURED, measured: false }, // P3D
  ];
  return (
    <div className="ao-stack">
      <div className="ao-cards">{cats.map((c) => (
        <MetricCard key={c.label} label={c.label} value={c.measured ? c.n : "—"} tone={c.measured && c.n ? "warn" : undefined} />
      ))}</div>
      <div className="ao-panel">
        <div className="ao-panel-h">Unknown entities <span className="ao-panel-meta">unknown is a real answer — never a guess · traffic arrives with cloud flow logs</span></div>
        {unknowns.length === 0 ? (
          <EmptyState title="No unattributed entities" hint="every discovered resource resolved to an app identity" />
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Unknowns"
            columns={[
              { key: "entity", header: "Entity", width: 220, render: (r) => <span className="ao-mono">{r.entity}</span> },
              { key: "kind", header: "Type", width: 120, render: (r) => r.kind },
              { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
              { key: "bytes", header: "Traffic", width: 90, align: "right", render: (r) => NM(r.bytes, fmtBytes) },
              { key: "guess", header: "Current guess", width: 220, render: (r) => r.likelyResource },
              { key: "why", header: "Why unknown", width: 180, render: (r) => r.missingFields.length ? <Chip label={`missing ${r.missingFields.join("/")}`} tone="var(--fg-subtle)" /> : <span className="ao-muted">—</span> },
              { key: "fix", header: "Recommended fix", width: 260, render: (r) => r.recommendation },
            ]} />
        )}
      </div>
    </div>
  );
}

// ── Evidence Explorer ────────────────────────────────────────────────────────
function Evidence() {
  const [f, setF] = useState<Record<string, string>>({});
  const [sel, setSel] = useState<EvidenceRow | null>(null);
  const rows = mockEvidence.filter((e) =>
    (!f.signal || e.signalType === f.signal) &&
    (!f.confidence || e.confidence === f.confidence) &&
    (!f.app || e.app === f.app));
  return (
    <div className="ao-stack">
      <PreviewNote what="The evidence ledger" />
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "app", label: "App", options: [...new Set(mockEvidence.map((e) => e.app))].map((a) => ({ value: a, label: a })) },
          { key: "signal", label: "Signal type", options: [...new Set(mockEvidence.map((e) => e.signalType))].map((s) => ({ value: s, label: s })) },
          { key: "confidence", label: "Confidence", options: [{ value: "confirmed", label: "confirmed" }, { value: "strong", label: "strong" }, { value: "suspected", label: "suspected" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<EvidenceRow> rows={rows} rowKey={(r) => r.time + r.signalType + r.resource} height={Math.min(480, 44 + rows.length * 30)}
          ariaLabel="Evidence" onRowClick={setSel}
          columns={[
            { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
            { key: "sig", header: "Signal type", width: 150, render: (r) => r.signalType },
            { key: "app", header: "App", width: 130, render: (r) => <strong>{r.app}</strong> },
            { key: "res", header: "Resource", width: 140, render: (r) => r.resource },
            { key: "src", header: "Source", width: 140, render: (r) => r.source },
            { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "reason", header: "Reason", width: 280, render: (r) => r.reason },
            { key: "rca", header: "RCA group", width: 130, render: (r) => r.rcaGroup ? <Chip label={r.rcaGroup} tone="var(--accent)" /> : <span className="ao-muted">—</span> },
          ]} />
      </div>
      {sel && (
        <EvidenceDrawer title={`${sel.signalType} · ${sel.app}`} subtitle={<ConfidenceBadge level={sel.confidence} />} onClose={() => setSel(null)}>
          <table className="ao-kv"><tbody>
            <tr><td>Time</td><td>{new Date(sel.time).toLocaleString()}</td></tr>
            <tr><td>App / Resource</td><td>{sel.app} · {sel.resource}</td></tr>
            <tr><td>Source</td><td>{sel.source}</td></tr>
            <tr><td>Confidence</td><td><ConfidenceBadge level={sel.confidence} /></td></tr>
            <tr><td>Reason</td><td>{sel.reason}</td></tr>
            <tr><td>RCA group</td><td>{sel.rcaGroup || "—"}</td></tr>
            <tr><td>Evidence ref</td><td><span className="ao-mono ao-muted">{sel.evidenceRef}</span></td></tr>
          </tbody></table>
        </EvidenceDrawer>
      )}
    </div>
  );
}

// ── Settings ─────────────────────────────────────────────────────────────────
function Settings() {
  const sections = [
    { t: "Catalog Sources", d: "Vendor IP/domain feeds (AWS/Azure/GCP/M365), refresh cadence." },
    { t: "Cloud Connectors", d: "Connect AWS/Azure/GCP accounts (role/creds), region+account scope, least-priv IAM." },
    { t: "Attribution Rules", d: "Tag keys read for app/owner/env; source precedence (tag>graph>firewall>domain>ip)." },
    { t: "Required Tags", d: "Tags an org requires (app/owner/env) — drives the coverage report." },
    { t: "RCA Windows", d: "deploy→degradation correlation window; verdict thresholds." },
  ];
  return (
    <div className="ao-settings">
      {sections.map((s) => (
        <div key={s.t} className="ao-panel">
          <div className="ao-panel-h">{s.t}</div>
          <p className="ao-set-d">{s.d}</p>
          <EmptyState title="Configuration UI wires here" hint="reuses the existing Integrations control plane" />
        </div>
      ))}
    </div>
  );
}
