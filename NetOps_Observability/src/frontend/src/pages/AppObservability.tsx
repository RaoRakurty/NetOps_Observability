// App Observability (#81 P3F) — the cloud-native app-to-underlay story under Monitor.
// Identity → Health → Change → Cloud Network → Underlay → RCA, every claim with
// confidence + evidence, unknown first-class. Built entirely on the existing design
// system (NOC kit, ds-*/cc-* classes, var(--*) tokens, Inter/Space-Grotesk/Plex-Mono
// fonts) so it matches the rest of Correlix; mock-fed today, wires to /api/cloud/* later.

import { useEffect, useState } from "react";
import { NocHeader, Chip, LiveChip } from "../components/noc";
import { Skeleton } from "../components/ui";
import DataTable from "../components/DataTable";
import {
  ConfidenceBadge, HealthBadge, RootDomainBadge, AppIdentityPill, MetricCard,
  CardGroup, UnderlayCell, RcaDrawer, EmptyState, FilterBar, EvidenceDrawer,
  fmtBps, fmtBytes, ago,
} from "./appobs/badges";
import AppDetail from "./appobs/AppDetail";
import type { App, EvidenceRow, ImpactedApplication } from "./appobs/types";
import {
  mockApps, mockResources, mockHealth, mockChanges, mockEvidence, mockCoverage,
  mockUnknowns, mockUnderlay, mockSummary, mockBreakdown, mockImpacted,
} from "./appobs/mock";

const TABS = [
  "overview", "applications", "appmap", "resources", "attribution",
  "health", "underlay", "unknowns", "evidence", "settings",
] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview", applications: "Applications", appmap: "App Map",
  resources: "Cloud Resources", attribution: "Attribution", health: "Health & Changes",
  underlay: "Underlay Impact", unknowns: "Unknowns", evidence: "Evidence", settings: "Settings",
};

export default function AppObservability() {
  const [tab, setTab] = useState<Tab>("overview");
  const [sel, setSel] = useState<App | null>(null);

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
        chips={<>
          <Chip label={`${mockSummary.appsObserved} apps`} tone="var(--accent)" />
          <Chip label={`${mockSummary.appsDegraded} degraded`} tone="var(--warn)" />
          <Chip label={`${mockSummary.unknownPct}% unknown`} tone="var(--fg-subtle)" />
          <LiveChip detail="mock" />
        </>}
      />

      <nav className="ao-tabs" role="tablist" aria-label="App Observability">
        {TABS.map((tk) => (
          <button key={tk} role="tab" aria-selected={tab === tk}
            className={`ao-tab${tab === tk ? " is-active" : ""}`} onClick={() => setTab(tk)}>
            {TAB_LABEL[tk]}
          </button>
        ))}
      </nav>

      {tab === "overview" && <Overview onOpen={setSel} goTab={setTab} />}
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

// converts an impacted-app row → the App shape App Detail expects (looks up the full
// record when we have it, else synthesizes from the row).
function toApp(im: ImpactedApplication): App {
  const m = mockApps.find((a) => a.id === im.id);
  if (m) return m;
  return {
    id: im.id, name: im.name, health: im.health, owner: im.owner, env: im.env,
    confidence: im.confidence, source: "cloud_tag", provider: "aws", account: "—", region: "—",
    resources: 0, trafficBps: im.trafficBps, errorPct: 0, p95ms: 0, unknownPct: 0,
    lastSeen: new Date().toISOString(), lastChange: im.lastChange, primarySymptom: "—",
    rootDomain: im.rootDomain,
    underlayImpacted: im.underlay.kind === "confirmed" || im.underlay.kind === "suspected",
  };
}

function Overview({ onOpen, goTab }: { onOpen: (a: App) => void; goTab: (t: Tab) => void }) {
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
              { key: "action", header: "Action", width: 150, render: (a) => <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); setDrawer(a); }}>{a.action}</button> },
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

// ── Applications ─────────────────────────────────────────────────────────────
function Applications({ onOpen }: { onOpen: (a: App) => void }) {
  const [f, setF] = useState<Record<string, string>>({});
  const rows = mockApps.filter((a) =>
    (!f.provider || a.provider === f.provider) &&
    (!f.env || a.env === f.env) &&
    (!f.health || a.health === f.health) &&
    (!f.confidence || a.confidence === f.confidence) &&
    (!f.underlay || (f.underlay === "yes") === a.underlayImpacted));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: [{ value: "aws", label: "AWS" }, { value: "azure", label: "Azure" }, { value: "gcp", label: "GCP" }] },
          { key: "env", label: "Env", options: [{ value: "prod", label: "prod" }] },
          { key: "health", label: "Health", options: [{ value: "healthy", label: "healthy" }, { value: "degraded", label: "degraded" }, { value: "down", label: "down" }, { value: "unknown", label: "unknown" }] },
          { key: "confidence", label: "Confidence", options: [{ value: "confirmed", label: "confirmed" }, { value: "strong", label: "strong" }, { value: "unknown", label: "unknown" }] },
          { key: "underlay", label: "Underlay", options: [{ value: "yes", label: "impacted" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<App> rows={rows} rowKey={(a) => a.id} height={Math.min(520, 44 + rows.length * 30)}
          ariaLabel="Applications" onRowClick={onOpen} initialSort={{ key: "health", dir: "asc" }}
          columns={[
            { key: "name", header: "App", width: 160, sortable: true, text: (a) => a.name, render: (a) => <strong>{a.name}</strong> },
            { key: "health", header: "Health", width: 100, sortable: true, sortValue: (a) => a.health, render: (a) => <HealthBadge status={a.health} /> },
            { key: "owner", header: "Owner", width: 100, render: (a) => a.owner },
            { key: "env", header: "Env", width: 60, render: (a) => a.env },
            { key: "conf", header: "Confidence", width: 110, render: (a) => <ConfidenceBadge level={a.confidence} /> },
            { key: "src", header: "Source", width: 110, render: (a) => a.source },
            { key: "provider", header: "Cloud", width: 70, render: (a) => a.provider.toUpperCase() },
            { key: "res", header: "Res", width: 50, align: "right", render: (a) => a.resources },
            { key: "traffic", header: "Traffic", width: 95, align: "right", sortable: true, sortValue: (a) => a.trafficBps, render: (a) => fmtBps(a.trafficBps) },
            { key: "err", header: "Err%", width: 60, align: "right", sortable: true, sortValue: (a) => a.errorPct, render: (a) => <span style={{ color: a.errorPct > 5 ? "var(--crit)" : undefined }}>{a.errorPct}%</span> },
            { key: "p95", header: "P95", width: 70, align: "right", render: (a) => a.p95ms ? `${a.p95ms}ms` : "—" },
            { key: "unk", header: "Unk%", width: 60, align: "right", render: (a) => <span className={a.unknownPct > 20 ? "" : "ao-muted"}>{a.unknownPct}%</span> },
            { key: "seen", header: "Last seen", width: 90, render: (a) => ago(a.lastSeen) },
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

// ── Cloud Resources ──────────────────────────────────────────────────────────
function Resources() {
  const [f, setF] = useState<Record<string, string>>({});
  const rows = mockResources.filter((r) =>
    (!f.missing || r.missingTags.includes(f.missing)) &&
    (!f.unknown || (f.unknown === "yes") === (r.app === "")) &&
    (!f.degraded || (f.degraded === "yes") === (r.health === "degraded" || r.health === "down")));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "missing", label: "Missing tag", options: [{ value: "app", label: "app" }, { value: "owner", label: "owner" }, { value: "env", label: "env" }] },
          { key: "unknown", label: "Unknown app", options: [{ value: "yes", label: "yes" }] },
          { key: "degraded", label: "Degraded", options: [{ value: "yes", label: "yes" }] },
        ]} />
      <div className="ao-panel">
        <DataTable rows={rows} rowKey={(r) => r.id} height={Math.min(520, 44 + rows.length * 30)} ariaLabel="Cloud resources"
          columns={[
            { key: "name", header: "Resource", width: 180, text: (r) => r.name, render: (r) => <strong>{r.name}</strong> },
            { key: "type", header: "Type", width: 90, render: (r) => r.type },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider.toUpperCase() },
            { key: "acct", header: "Account", width: 130, render: (r) => <span className="ao-mono ao-muted">{r.account}</span> },
            { key: "region", header: "Region", width: 100, render: (r) => r.region },
            { key: "app", header: "App", width: 150, render: (r) => <AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /> },
            { key: "owner", header: "Owner", width: 90, render: (r) => r.owner },
            { key: "src", header: "Identity src", width: 110, render: (r) => r.source },
            { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "health", header: "Health", width: 100, render: (r) => <HealthBadge status={r.health} /> },
            { key: "traffic", header: "Traffic", width: 95, align: "right", render: (r) => fmtBps(r.trafficBps) },
            { key: "tags", header: "Missing tags", width: 130, render: (r) => r.missingTags.length ? <Chip label={r.missingTags.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
          ]} />
      </div>
    </div>
  );
}

// ── Attribution ──────────────────────────────────────────────────────────────
function Attribution() {
  const c = mockCoverage;
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
        <div className="ao-panel-h">Top unknown contributors <span className="ao-panel-meta">tag these to lift coverage</span></div>
        <DataTable rows={mockUnknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + mockUnknowns.length * 34)} ariaLabel="Top unknown contributors"
          columns={[
            { key: "entity", header: "Resource / IP / ENI", width: 200, render: (r) => <span className="ao-mono">{r.entity}</span> },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider.toUpperCase() },
            { key: "region", header: "Region", width: 100, render: (r) => r.region },
            { key: "bytes", header: "Bytes", width: 90, align: "right", render: (r) => fmtBytes(r.bytes) },
            { key: "flows", header: "Flows", width: 80, align: "right", render: (r) => r.flows.toLocaleString() },
            { key: "errors", header: "Errors", width: 70, align: "right", render: (r) => r.errors || "—" },
            { key: "likely", header: "Likely resource", width: 200, render: (r) => r.likelyResource },
            { key: "missing", header: "Missing", width: 130, render: (r) => <Chip label={r.missingFields.join(", ")} tone="var(--warn)" /> },
            { key: "rec", header: "Recommendation", width: 240, render: (r) => r.recommendation },
          ]} />
      </div>
    </div>
  );
}

// ── Health & Changes ─────────────────────────────────────────────────────────
function HealthChanges() {
  const [sub, setSub] = useState<"health" | "changes">("health");
  return (
    <div className="ao-stack">
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

// ── Unknowns (first-class) ───────────────────────────────────────────────────
function Unknowns() {
  const cats = [
    { label: "Unknown apps", n: mockApps.filter((a) => a.confidence === "unknown").length },
    { label: "Unknown cloud resources", n: mockResources.filter((r) => r.app === "").length },
    { label: "Unknown traffic", n: mockUnknowns.length },
    { label: "Unknown owners", n: mockResources.filter((r) => r.owner === "—").length },
    { label: "Unknown underlay mapping", n: 0 },
  ];
  return (
    <div className="ao-stack">
      <div className="ao-cards">{cats.map((c) => <MetricCard key={c.label} label={c.label} value={c.n} tone={c.n ? "warn" : undefined} />)}</div>
      <div className="ao-panel">
        <div className="ao-panel-h">Unknown entities <span className="ao-panel-meta">unknown is a real answer — never a guess</span></div>
        <DataTable rows={mockUnknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + mockUnknowns.length * 34)} ariaLabel="Unknowns"
          columns={[
            { key: "entity", header: "Entity", width: 200, render: (r) => <span className="ao-mono">{r.entity}</span> },
            { key: "kind", header: "Type", width: 110, render: (r) => r.kind },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider.toUpperCase() },
            { key: "bytes", header: "Traffic", width: 90, align: "right", render: (r) => fmtBytes(r.bytes) },
            { key: "errors", header: "Errors", width: 70, align: "right", render: (r) => r.errors || "—" },
            { key: "guess", header: "Current guess", width: 200, render: (r) => r.likelyResource },
            { key: "why", header: "Why unknown", width: 160, render: (r) => <Chip label={`missing ${r.missingFields.join("/")}`} tone="var(--fg-subtle)" /> },
            { key: "fix", header: "Recommended fix", width: 240, render: (r) => r.recommendation },
          ]} />
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
