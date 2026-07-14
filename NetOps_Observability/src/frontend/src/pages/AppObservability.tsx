// App Observability (#81 P3F/P3H) — the cloud-native app-to-underlay story under Monitor.
// Identity → Health → Change → Cloud Network → Underlay → RCA, every claim with
// confidence + evidence, unknown first-class. Built entirely on the existing design
// system (NOC kit, ds-*/cc-* classes, var(--*) tokens, Inter/Space-Grotesk/Plex-Mono
// fonts) so it matches the rest of Correlix.
//
// EVERY surface here renders REAL, tenant-scoped cloud telemetry — the cloud
// inventory (/api/cloud/resources|apps|coverage) plus the signals that actually
// landed from the connected AWS / Azure accounts (/api/cloud/health|changes|
// evidence, from corr_signals + the cloud correlation objects). There is no sample
// data left in this page: a tab with nothing ingested shows an honest empty state,
// and a metric we do not measure renders "—" — never a fabricated app or row.

import { useEffect, useState } from "react";
import { NocHeader, Chip } from "../components/noc";
import { Skeleton } from "../components/ui";
import DataTable from "../components/DataTable";
import {
  ConfidenceBadge, HealthBadge, AppIdentityPill, MetricCard,
  CardGroup, EmptyState, FilterBar, EvidenceDrawer,
  EvidenceCategoryBadge, ConsoleLink, consoleName, fmtBps, fmtBytes, ago,
} from "./appobs/badges";
import AppDetail from "./appobs/AppDetail";
import Ingestion from "./appobs/Ingestion";
import type {
  App, ChangeEvent, CloudResource, Confidence, Coverage, EvidenceRow, HealthSignal, UnknownContributor,
} from "./appobs/types";
import {
  loadApps, loadResources, loadCoverage, loadHealthSignals, loadChangeEvents, loadEvidence,
  NOT_MEASURED,
} from "./appobs/api";
import type { CloudRcaObject } from "./appobs/api";
import { signatureNocTitle } from "../components/rca/labels";
import { funnelSteps, coverageByScope, groupByApp, RESOURCE_CATEGORIES } from "./appobs/attribution";
import { useCloudShell } from "./appobs/useCloudShell";
import { CloudScopeBar, ReadinessStrip, SourceStatusBadge } from "./appobs/shell";
import { SOURCE_LABEL } from "./appobs/readiness";
import type { ReadinessSummary, SourceType, SourceStatus } from "./appobs/readiness";
import { api } from "../services/api";

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

// a metric the platform does not measure renders as a muted "—" (never a fake 0).
const NM = (v: number, fmt: (n: number) => string) =>
  v < 0 ? <span className="ao-muted">—</span> : fmt(v);
const DASH = <span className="ao-muted">—</span>;

// the engine's verdict tier → the UI confidence ladder. "undetermined" is honestly
// unknown; we never promote it.
function verdictConf(tier: string): Confidence {
  return tier === "confirmed" ? "confirmed" : tier === "suspected" ? "suspected" : "unknown";
}

// developer identity-source enum → the operator words (audit C: "Mapped by").
const MAPPED_BY: Record<string, string> = {
  cloud_tag: "Tag", cloud_graph: "Resource graph", operator_catalog: "Operator",
  firewall_appid: "Firewall", domain: "Domain", ip_catalog: "IP catalog", unknown: "—",
};

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

// 5-tab IA (audit C): Overview | Services | Investigations | Resources |
// Data sources (+ Settings). The old 11 tab ids stay valid as deep-link
// aliases so every existing bookmark/flyout link lands on the right sub-view.
const TABS = ["overview", "services", "investigations", "resources", "datasources", "settings"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview", services: "Services", investigations: "Investigations",
  resources: "Resources", datasources: "Data sources", settings: "Settings",
};
const TAB_ALIAS: Record<string, { tab: Tab; sub?: string }> = {
  applications: { tab: "services", sub: "applications" },
  appmap: { tab: "services", sub: "map" },
  attribution: { tab: "resources", sub: "mapping" },
  unknowns: { tab: "resources", sub: "untagged" },
  health: { tab: "investigations", sub: "alerts" },
  evidence: { tab: "investigations", sub: "findings" },
  underlay: { tab: "investigations", sub: "network" },
  ingestion: { tab: "datasources" },
};

export default function AppObservability() {
  const [tab, setTab] = useState<Tab>("overview");
  const [sub, setSub] = useState<string>("");
  const [sel, setSel] = useState<App | null>(null);
  const shell = useCloudShell();

  // deep-link: #/monitoring/appobs/<tab-or-alias> → opens that (sub-)view.
  // Re-read on hashchange too, so clicking a flyout sub-item while ALREADY on
  // this page switches tabs (the leaf component stays mounted, so a mount-only
  // effect would never see the new suffix → the click looked dead).
  useEffect(() => {
    const apply = () => {
      const suffix = location.hash.split("?")[0].split("/").pop() ?? "";
      if ((TABS as readonly string[]).includes(suffix)) {
        setTab(suffix as Tab); setSub("");
      } else if (TAB_ALIAS[suffix]) {
        setTab(TAB_ALIAS[suffix].tab); setSub(TAB_ALIAS[suffix].sub ?? "");
      }
    };
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  if (sel) return <AppDetail app={sel} onBack={() => setSel(null)} />;

  return (
    <div className="ao">
      <NocHeader
        title="Service View"
        subtitle="Cloud service identity, health, change & network RCA — evidence-grounded"
      />
      <CloudScopeBar scope={shell.scope} mode={shell.mode} summary={shell.summary} />

      <nav className="ao-tabs" role="tablist" aria-label="Service View">
        {TABS.map((tk) => (
          <button key={tk} role="tab" aria-selected={tab === tk}
            className={`ao-tab${tab === tk ? " is-active" : ""}`}
            onClick={() => { setTab(tk); setSub(""); }} title="Live cloud telemetry">
            {TAB_LABEL[tk]}
          </button>
        ))}
      </nav>

      {tab === "overview" && <Overview goTab={(t, s) => { setTab(t); setSub(s ?? ""); }} summary={shell.summary} />}
      {tab === "services" && <Services initialSub={sub} onOpen={setSel} />}
      {tab === "investigations" && <Investigations initialSub={sub} goDataSources={() => { setTab("datasources"); setSub(""); }} />}
      {tab === "resources" && <ResourcesGroup initialSub={sub} />}
      {tab === "datasources" && <Ingestion />}
      {tab === "settings" && <Settings />}
    </div>
  );
}

// shared sub-tab bar for the grouped views.
function SubTabs<T extends string>({ value, onChange, items }: {
  value: T; onChange: (v: T) => void; items: { key: T; label: string }[];
}) {
  return (
    <div className="ao-tabs ao-tabs--sub">
      {items.map((it) => (
        <button key={it.key} className={`ao-tab${value === it.key ? " is-active" : ""}`}
          onClick={() => onChange(it.key)}>{it.label}</button>
      ))}
    </div>
  );
}

// ── Services (Applications + Service map) ────────────────────────────────────
function Services({ initialSub, onOpen }: { initialSub: string; onOpen: (a: App) => void }) {
  const [sub, setSub] = useState<"applications" | "map">(initialSub === "map" ? "map" : "applications");
  return (
    <div className="ao-stack">
      <SubTabs value={sub} onChange={setSub}
        items={[{ key: "applications", label: "Applications" }, { key: "map", label: "Service map" }]} />
      {sub === "applications" ? <Applications onOpen={onOpen} /> : <AppMap />}
    </div>
  );
}

// ── Investigations (Timeline · Alerts · Changes · Findings · Network) ────────
function Investigations({ initialSub, goDataSources }: { initialSub: string; goDataSources: () => void }) {
  const first = (["alerts", "changes", "findings", "network"].includes(initialSub)
    ? initialSub : "timeline") as "timeline" | "alerts" | "changes" | "findings" | "network";
  const [sub, setSub] = useState(first);
  return (
    <div className="ao-stack">
      <SubTabs value={sub} onChange={setSub} items={[
        { key: "timeline", label: "Timeline" }, { key: "alerts", label: "Alerts" },
        { key: "changes", label: "Changes" }, { key: "findings", label: "Findings" },
        { key: "network", label: "Network connectivity" },
      ]} />
      {(sub === "timeline" || sub === "alerts" || sub === "changes") && <HealthChanges view={sub} />}
      {sub === "findings" && <Evidence />}
      {sub === "network" && <Underlay goDataSources={goDataSources} />}
    </div>
  );
}

// ── Resources group (Resources · Service mapping · Untagged) ─────────────────
function ResourcesGroup({ initialSub }: { initialSub: string }) {
  const first = (initialSub === "mapping" || initialSub === "untagged" ? initialSub : "resources") as
    "resources" | "mapping" | "untagged";
  const [sub, setSub] = useState(first);
  return (
    <div className="ao-stack">
      <SubTabs value={sub} onChange={setSub} items={[
        { key: "resources", label: "Resources" },
        { key: "mapping", label: "Service mapping" },
        { key: "untagged", label: "Untagged" },
      ]} />
      {sub === "resources" && <Resources />}
      {sub === "mapping" && <Attribution />}
      {sub === "untagged" && <Unknowns />}
    </div>
  );
}

// ── Overview ─────────────────────────────────────────────────────────────────
type LoadState = "loading" | "ready" | "error";

// Everything the Overview claims, measured from a live surface. A number we have
// no source for is NOT_MEASURED and renders "—".
interface OverviewData {
  apps: App[];
  resources: CloudResource[];
  coverage: Coverage;
  health: HealthSignal[];
  changes: ChangeEvent[];
  objects: CloudRcaObject[];
  openCount: number;         // dedicated COUNT — never the list length (D-P1-7)
  objectsTruncated: boolean;
}

async function loadOverview(): Promise<OverviewData> {
  const [apps, resources, cov, health, changes, ev] = await Promise.all([
    loadApps(), loadResources(), loadCoverage(), loadHealthSignals(), loadChangeEvents(), loadEvidence(),
  ]);
  return {
    apps, resources, coverage: cov.coverage, health, changes,
    objects: ev.objects, openCount: ev.openCount, objectsTruncated: ev.objectsTruncated,
  };
}

// apps with a health signal that says degraded/down in the window — measured from
// the signals themselves, never a threshold we invented.
function degradedApps(health: HealthSignal[]): string[] {
  return [...new Set(health.filter((h) => h.state === "degraded" || h.state === "down")
    .map((h) => h.app).filter((a) => a && a !== "—"))];
}

function Overview({ goTab, summary }: { goTab: (t: Tab, sub?: string) => void; summary: ReadinessSummary }) {
  const { data, status } = useAsync(loadOverview);

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
  if (status === "error" || !data) {
    return <div className="ao-panel"><EmptyState title="Unable to load the Service View summary" hint="retry, or check the cloud connector status in Settings" /></div>;
  }

  const { apps, resources, coverage, health, changes, objects, openCount, objectsTruncated } = data;
  // Degraded = health-signal verdicts ∪ live measured app health (provider status
  // checks + probe outcomes). A dead health feed must never render as "0 degraded"
  // = "all healthy": with nothing measured at all we say "—", not 0.
  const degraded = [...new Set([
    ...degradedApps(health),
    ...apps.filter((a) => a.health === "degraded" || a.health === "down").map((a) => a.name),
  ])];
  const healthMeasured = health.length > 0 || apps.some((a) => a.health !== "unknown");
  const openRca = objects.filter((o) => o.state === "open");
  const unknownPct = coverage.total ? Math.round((coverage.unknown / coverage.total) * 100) : NOT_MEASURED;

  return (
    <div className="ao-stack">
      {/* Readiness BEFORE impact — prove the data is connected before any verdict. */}
      <div className="ao-section-l">Data readiness</div>
      <ReadinessStrip summary={summary} />

      {/* A. grouped operational cards — each one measured, or an explicit "—". */}
      <div className="ao-groups">
        <CardGroup title="Impact">
          <MetricCard label="Services Degraded" value={healthMeasured ? degraded.length : DASH}
            trend={healthMeasured ? "provider status + health signals · 24h" : "no health feed measured"}
            tone={!healthMeasured ? undefined : degraded.length ? "warn" : "good"} />
          <MetricCard label="Open Investigations" value={openCount} trend="engine-formed · dedicated count" tone={openCount ? "warn" : "good"} />
          <MetricCard label="Network Impact" value={DASH} trend="service→connection correlation not ingested" />
        </CardGroup>
        <CardGroup title="Coverage">
          <MetricCard label="Services Observed" value={apps.length.toLocaleString()} trend="from cloud inventory" tone="accent" />
          <MetricCard label="Resources Mapped" value={resources.length.toLocaleString()} trend="discovered + attributed" />
          <MetricCard label="Untagged Resources"
            value={unknownPct < 0 ? DASH : `${unknownPct}%`}
            trend={coverage.total ? `${coverage.unknown} of ${coverage.total}` : undefined}
            tone={unknownPct > 10 ? "warn" : unknownPct < 0 ? undefined : "good"} />
        </CardGroup>
        <CardGroup title="Change">
          <MetricCard label="Recent Cloud Changes" value={changes.length} trend="provider audit log · 24h" />
          <MetricCard label="Deploy-linked Incidents" value={DASH} trend="deploy events not ingested" />
        </CardGroup>
      </div>

      {/* B. the REAL investigations the engine formed — no heuristic verdicts. */}
      <div className="ao-panel">
        <div className="ao-panel-h">Open investigations
          <span className="ao-panel-meta">
            grounded on cloud signals · click for the full analysis
            {objectsTruncated && openRca.length < openCount &&
              ` · showing ${openRca.length} of ${openCount} open`}
          </span></div>
        {objects.length === 0 ? (
          <EmptyState title="No open investigations in the last 24 hours"
            hint={health.length || changes.length
              ? "cloud signals are landing; none has grounded into an investigation yet"
              : "no cloud health or change signals have landed yet"}
            action={!(health.length || changes.length)
              ? <button className="ao-btn ao-btn--primary" onClick={() => goTab("datasources")}>Check data sources</button>
              : undefined} />
        ) : (
          <DataTable<CloudRcaObject> rows={objects} rowKey={(o) => o.correlationId}
            height={Math.min(460, 56 + objects.length * 34)} ariaLabel="Open investigations"
            onRowClick={(o) => { location.hash = `#/monitoring/correlations?id=${encodeURIComponent(o.correlationId)}`; }}
            columns={[
              { key: "apps", header: "Services", width: 220, render: (o) => o.apps.length ? <strong>{o.apps.join(", ")}</strong> : DASH },
              { key: "verdict", header: "Assessment", width: 120, sortable: true, sortValue: (o) => o.verdictTier, render: (o) => <ConfidenceBadge level={verdictConf(o.verdictTier)} /> },
              { key: "hyp", header: "Probable cause", width: 300, render: (o) => <span className="ao-why" title={o.topHypothesis}>{o.topHypothesis.startsWith("sig.") ? signatureNocTitle(o.topHypothesis) : o.topHypothesis}</span> },
              { key: "conf", header: "Confidence", width: 96, align: "right", render: (o) => `${Math.round(o.confidence * 100)}%` },
              { key: "sig", header: "Signals", width: 80, align: "right", sortable: true, sortValue: (o) => o.signalCount, render: (o) => o.signalCount },
              { key: "state", header: "State", width: 80, render: (o) => o.state },
              { key: "start", header: "Started", width: 110, render: (o) => ago(o.windowStart) },
              { key: "act", header: "Findings", width: 110, render: () => <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); goTab("investigations", "findings"); }}>Findings</button> },
            ]} />
        )}
      </div>
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
    (!f.provider || a.providers.includes(f.provider as App["providers"][number])) &&
    (!f.env || a.env === f.env) &&
    (!f.confidence || a.confidence === f.confidence) &&
    (!f.source || a.source === f.source));
  // provider options come from the DATA — a cloud with no connected inventory is
  // not offered as a dead filter (GCP appears here the day it lands).
  const providerOpts = [...new Set(apps.flatMap((a) => a.providers))]
    .map((p) => ({ value: p, label: p.toUpperCase() }));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: providerOpts },
          { key: "env", label: "Env", options: [...new Set(apps.map((a) => a.env))].filter((e) => e && e !== "—").map((e) => ({ value: e, label: e })) },
          { key: "confidence", label: "Confidence", options: [{ value: "confirmed", label: "confirmed" }, { value: "strong", label: "strong" }, { value: "suspected", label: "suspected" }, { value: "unknown", label: "unknown" }] },
          { key: "source", label: "Mapped by", options: [{ value: "cloud_tag", label: "tag" }, { value: "cloud_graph", label: "resource graph" }, { value: "operator_catalog", label: "operator" }, { value: "firewall_appid", label: "firewall" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<App> rows={rows} rowKey={(a) => a.id} height={Math.min(520, 44 + rows.length * 30)}
          ariaLabel="Applications" onRowClick={onOpen} initialSort={{ key: "name", dir: "asc" }}
          columns={[
            { key: "name", header: "Service", width: 160, sortable: true, text: (a) => a.name, render: (a) => <strong>{a.name}</strong> },
            { key: "health", header: "Health", width: 100, render: (a) => <HealthBadge status={a.health} /> },
            { key: "owner", header: "Owner", width: 100, render: (a) => a.owner },
            { key: "env", header: "Env", width: 60, render: (a) => a.env },
            { key: "conf", header: "Confidence", width: 110, sortable: true, sortValue: (a) => a.confidence, render: (a) => <ConfidenceBadge level={a.confidence} /> },
            { key: "src", header: "Mapped by", width: 120, render: (a) => MAPPED_BY[a.source] ?? a.source },
            { key: "provider", header: "Cloud", width: 90, render: (a) => a.providers.length ? a.providers.map((p) => p.toUpperCase()).join(" + ") : "—" },
            { key: "acct", header: "Account", width: 130, render: (a) => <span className="ao-mono ao-muted">{a.account}</span> },
            { key: "region", header: "Region", width: 100, render: (a) => a.region },
            { key: "res", header: "Res", width: 50, align: "right", sortable: true, sortValue: (a) => a.resources, render: (a) => a.resources },
            { key: "traffic", header: "Traffic", width: 95, align: "right", render: (a) => NM(a.trafficBps, fmtBps) },
            { key: "err", header: "Err%", width: 60, align: "right", render: (a) => NM(a.errorPct, (n) => `${n}%`) },
            { key: "p95", header: "P95", width: 70, align: "right", render: (a) => NM(a.p95ms, (n) => `${n}ms`) },
          ]} />
      </div>
    </div>
  );
}

// ── App Map (graph-ready placeholder) ────────────────────────────────────────
// App Map — the STRUCTURAL app→resource map from the live inventory (real). The
// traffic-dependency layer (talks_to / egresses_via / suspected_cause edges) needs
// cloud flow logs and is honestly deferred, not faked.
function AppMap() {
  const { data, status } = useAsync(loadResources);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="app map" />;
  const resources = data ?? [];
  if (resources.length === 0) return <CloudEmpty />;
  const groups = groupByApp(resources);
  return (
    <div className="ao-stack">
      <div className="ao-preview-note">
        <Chip label="structural" tone="var(--good)" />
        <span>App→resource structure is live from the inventory. Traffic dependencies (talks_to / egresses_via) and RCA edges appear when cloud flow logs are ingested.</span>
      </div>
      <div className="ao-appmap">
        {groups.map((g) => (
          <div className={`ao-appmap-card${g.app === "" ? " ao-appmap-card--unknown" : ""}`} key={g.app || "__unattributed"}>
            <div className="ao-appmap-h">
              {g.app ? <strong>{g.app}</strong> : <span className="ao-unknown">unattributed</span>}
              <span className="ao-appmap-n">{g.resources.length} resources</span>
            </div>
            {RESOURCE_CATEGORIES.filter((cat) => g.byCategory[cat].length).map((cat) => (
              <div className="ao-appmap-cat" key={cat}>
                <span className="ao-appmap-cat-l">{cat}</span>
                <div className="ao-chips">
                  {g.byCategory[cat].map((r) => <Chip key={r.id} label={`${r.name} · ${r.type}`} tone={g.app === "" ? "var(--fg-subtle)" : "var(--accent)"} title={`${r.provider === "—" ? "" : r.provider.toUpperCase() + " · "}${r.region}`} />)}
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Cloud Resources (LIVE: /api/cloud/resources) ─────────────────────────────
function Resources() {
  const [f, setF] = useState<Record<string, string>>({});
  const [sel, setSel] = useState<CloudResource | null>(null);
  const { data, status } = useAsync(loadResources);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="cloud resources" />;
  const all = data ?? [];
  if (all.length === 0) return <CloudEmpty />;
  const rows = all.filter((r) =>
    (!f.missing || r.missingTags.includes(f.missing)) &&
    (!f.unknown || (f.unknown === "yes") === (r.app === "")) &&
    (!f.provider || r.provider === f.provider));
  const providerOpts = [...new Set(all.map((r) => r.provider))]
    .filter((p) => p !== "—").map((p) => ({ value: p, label: p.toUpperCase() }));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: providerOpts },
          { key: "missing", label: "Missing tag", options: [{ value: "app", label: "app" }, { value: "owner", label: "owner" }, { value: "env", label: "env" }] },
          { key: "unknown", label: "Untagged service", options: [{ value: "yes", label: "yes" }] },
        ]} />
      <div className="ao-panel">
        <DataTable<CloudResource> rows={rows} rowKey={(r) => r.id} height={Math.min(520, 44 + rows.length * 30)} ariaLabel="Cloud resources" onRowClick={setSel}
          columns={[
            { key: "name", header: "Resource", width: 180, sortable: true, text: (r) => r.name, render: (r) => <><strong>{r.name}</strong>{r.consoleUrl && <ConsoleLink compact href={r.consoleUrl} label={`Open in ${consoleName(r.provider)}`} />}</> },
            { key: "type", header: "Type", width: 120, render: (r) => r.type },
            { key: "power", header: "State", width: 90, sortable: true, sortValue: (r) => r.powerState, render: (r) => r.powerState === "—" ? DASH : (
              <span style={{ color: r.powerState === "running" ? "var(--ok)" : "var(--warn)", fontWeight: 600 }}>
                {r.powerState.charAt(0).toUpperCase() + r.powerState.slice(1)}
              </span>
            ) },
            { key: "provider", header: "Cloud", width: 65, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
            { key: "acct", header: "Account", width: 130, render: (r) => <span className="ao-mono ao-muted">{r.account}</span> },
            { key: "region", header: "Region", width: 100, render: (r) => r.region },
            { key: "app", header: "Service", width: 150, render: (r) => <AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /> },
            { key: "owner", header: "Owner", width: 90, render: (r) => r.owner },
            { key: "src", header: "Mapped by", width: 120, render: (r) => MAPPED_BY[r.source] ?? r.source },
            { key: "conf", header: "Confidence", width: 110, sortable: true, sortValue: (r) => r.confidence, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "health", header: "Health", width: 100, render: (r) => <HealthBadge status={r.health} /> },
            { key: "traffic", header: "Traffic", width: 95, align: "right", render: (r) => NM(r.trafficBps, fmtBps) },
            { key: "tags", header: "Missing tags", width: 130, render: (r) => r.missingTags.length ? <Chip label={r.missingTags.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
          ]} />
      </div>
      {sel && <ResourceDrawer r={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

// Cloud Resource detail drawer — identity, attribution provenance, tags, and the
// honest not-measured signals (health/traffic arrive with cloud telemetry).
function ResourceDrawer({ r, onClose }: { r: CloudResource; onClose: () => void }) {
  const tags = r.tags ?? {};
  const tagKeys = Object.keys(tags);
  return (
    <EvidenceDrawer title={r.name}
      subtitle={<span className="ao-drawer-badges"><AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /><ConfidenceBadge level={r.confidence} /></span>}
      onClose={onClose}>
      <table className="ao-kv"><tbody>
        <tr><td>Type</td><td>{r.type}</td></tr>
        <tr><td>Resource id</td><td>
          <span className="ao-mono ao-muted">{r.resourceId}</span>
          {r.consoleUrl && <> · <ConsoleLink href={r.consoleUrl} label={`Open in ${consoleName(r.provider)}`} /></>}
        </td></tr>
        <tr><td>Cloud</td><td>{r.provider === "—" ? "—" : r.provider.toUpperCase()} · {r.account} · {r.region}</td></tr>
        <tr><td>Service mapping</td><td><AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /> {r.app ? `(mapped by ${MAPPED_BY[r.source] ?? r.source})` : "— untagged"}</td></tr>
        <tr><td>Owner / Env</td><td>{r.owner} · {r.env}</td></tr>
        <tr><td>Health</td><td><HealthBadge status={r.health} />{r.health === "unknown" && <span className="ao-muted"> — not measured</span>}</td></tr>
        <tr><td>Traffic</td><td>{NM(r.trafficBps, fmtBps)}{r.trafficBps < 0 && <span className="ao-muted"> — not measured (flow logs)</span>}</td></tr>
        <tr><td>Last seen</td><td>{ago(r.lastSeen)}</td></tr>
      </tbody></table>

      <div className="ao-ev-h">Tags</div>
      {tagKeys.length ? (
        <div className="ao-chips">{tagKeys.map((k) => <Chip key={k} label={`${k}=${tags[k]}`} tone="var(--fg-subtle)" />)}</div>
      ) : <div className="ao-muted">no tags</div>}

      {r.missingTags.length > 0 && (<>
        <div className="ao-ev-h">Recommended action</div>
        <div className="ao-next-v">Tag {r.name} with {r.missingTags.join(", ")} to lift attribution coverage.</div>
      </>)}
    </EvidenceDrawer>
  );
}

// ── Attribution (LIVE: /api/cloud/attribution/coverage) ──────────────────────
function Attribution() {
  const { data, status } = useAsync(loadCoverage);
  const resq = useAsync(loadResources);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="attribution coverage" />;
  const c: Coverage = data?.coverage ?? { confirmedTag: 0, strongGraph: 0, firewallAppId: 0, suspectedDomainIp: 0, unknown: 0, total: 0 };
  const unknowns: UnknownContributor[] = data?.unknowns ?? [];
  if (c.total === 0) return <CloudEmpty />;
  const pct = (n: number) => Math.round((n / c.total) * 100);
  const resources = resq.data ?? [];
  const byScope = coverageByScope(resources, (r) => `${r.provider === "—" ? "—" : r.provider.toUpperCase()} / ${r.region || "—"}`);
  return (
    <div className="ao-stack">
      <div className="ao-cards">
        <MetricCard label="Confirmed by tag" value={`${pct(c.confirmedTag)}%`} sub={`${c.confirmedTag}`} tone="good" />
        <MetricCard label="From resource relationships" value={`${pct(c.strongGraph)}%`} sub={`${c.strongGraph}`} tone="accent" />
        <MetricCard label="Confirmed by firewall App-ID" value={`${pct(c.firewallAppId)}%`} sub={`${c.firewallAppId}`} tone="good" />
        <MetricCard label="Suspected by domain/IP" value={`${pct(c.suspectedDomainIp)}%`} sub={`${c.suspectedDomainIp}`} tone="warn" />
        <MetricCard label="Untagged" value={`${pct(c.unknown)}%`} sub={`${c.unknown}`} tone={pct(c.unknown) > 10 ? "warn" : undefined} />
      </div>

      {/* coverage funnel — total → confirmed → strong → firewall → suspected → unknown */}
      <div className="ao-panel">
        <div className="ao-panel-h">Service-mapping coverage <span className="ao-panel-meta">{c.total} observed · how each was identified</span></div>
        <div className="ao-funnel">
          {funnelSteps(c).map((s) => (
            <div className="ao-funnel-row" key={s.label}>
              <span className="ao-funnel-l">{s.label}</span>
              <span className="ao-funnel-bar"><span className="ao-funnel-fill" style={{ width: `${s.pct}%`, background: s.tone }} /></span>
              <span className="ao-funnel-n">{s.pct}% · {s.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* coverage by scope (provider / region) — real, from the inventory */}
      <div className="ao-panel">
        <div className="ao-panel-h">Coverage by scope <span className="ao-panel-meta">attributed resources per provider / region</span></div>
        {byScope.length === 0 ? <EmptyState title="No resources in scope" /> : (
          <table className="ao-tbl">
            <thead><tr><th>Provider / Region</th><th>Attributed</th><th>Total</th><th>Coverage</th></tr></thead>
            <tbody>
              {byScope.map((s) => (
                <tr key={s.scope}>
                  <td>{s.scope}</td>
                  <td>{s.attributed}</td>
                  <td>{s.total}</td>
                  <td><span className="ao-funnel-bar ao-funnel-bar--inline"><span className="ao-funnel-fill" style={{ width: `${s.pct}%`, background: s.pct >= 80 ? "var(--ok)" : s.pct >= 50 ? "var(--warn)" : "var(--crit)" }} /></span> {s.pct}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="ao-panel">
        <div className="ao-panel-h">Untagged resources <span className="ao-panel-meta">tag these to complete your service map · traffic ranking arrives with cloud flow logs</span></div>
        {unknowns.length === 0 ? (
          <EmptyState title="Every discovered resource is mapped to a service"
            hint="untagged resources appear here with a fix path when discovery finds one" />
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Untagged resources"
            columns={[
              { key: "entity", header: "Resource", width: 220, render: (r) => <><strong>{r.name}</strong>{r.address && <span className="ao-mono ao-muted"> {r.address}</span>}</> },
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

// ── Health & Changes (LIVE: /api/cloud/health · /api/cloud/changes) ──────────
// The source-freshness strip is MEASURED (/api/cloud/ingestion) — it reports what
// actually landed, so the tables below can be trusted to be what the cloud sent.
function SourceFreshnessStrip() {
  const srcs: SourceType[] = ["cloud_health", "change_audit", "flow_logs", "traces"];
  const [status, setStatus] = useState<Record<string, SourceStatus>>({});
  useEffect(() => {
    let live = true;
    api.cloudIngestion().then(
      (r) => {
        if (!live) return;
        const m: Record<string, SourceStatus> = {};
        for (const s of r.sources ?? []) m[s.source_type] = s.status as SourceStatus;
        setStatus(m);
      },
      () => { /* no reading ⇒ "off" below — never a fabricated "flowing" */ },
    );
    return () => { live = false; };
  }, []);
  return (
    <div className="ao-freshstrip">
      <span className="ao-freshstrip-h">Source freshness</span>
      {srcs.map((s) => (
        <span className="ao-freshstrip-i" key={s}>
          <span className="ao-freshstrip-l">{SOURCE_LABEL[s]}</span>
          <SourceStatusBadge status={status[s] ?? "off"} />
        </span>
      ))}
    </div>
  );
}

// merged change + health timeline, newest first — the NOC "what happened, when".
function HCTimeline({ health, changes }: { health: HealthSignal[]; changes: ChangeEvent[] }) {
  const items = [
    ...changes.map((c) => ({ time: c.time, kind: "change", tone: "var(--warn)", app: c.app, label: `${c.changeType.replace(/_/g, " ")} on ${c.resource}` })),
    ...health.map((h) => ({ time: h.time, kind: h.state === "down" ? "down" : "health", tone: h.severity === "critical" ? "var(--crit)" : "var(--warn)", app: h.app, label: `${h.signal} ${h.metric} ${h.current} (baseline ${h.baseline})` })),
  ].sort((a, b) => b.time.localeCompare(a.time)).slice(0, 200);
  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Event timeline <span className="ao-panel-meta">change + health, newest first · last 24h</span></div>
      {items.length === 0 ? <EmptyState title="No cloud events in the last 24h" hint="health + change signals appear here as the connected cloud accounts report them" /> : (
        <ul className="ao-timeline">
          {items.map((it, i) => (
            <li key={i}><span className="ao-tl-t">{ago(it.time)}</span><Chip label={it.kind} tone={it.tone} /> <strong>{it.app}</strong> · {it.label}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

async function loadHealthChanges(): Promise<{ health: HealthSignal[]; changes: ChangeEvent[] }> {
  const [health, changes] = await Promise.all([loadHealthSignals(), loadChangeEvents()]);
  return { health, changes };
}

function HealthChanges({ view }: { view: "timeline" | "alerts" | "changes" }) {
  const { data, status } = useAsync(loadHealthChanges);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error" || !data) return <LoadError what="cloud health & change signals" />;
  const { health, changes } = data;
  return (
    <div className="ao-stack">
      <SourceFreshnessStrip />
      {view === "timeline" && <HCTimeline health={health} changes={changes} />}
      {view === "alerts" && (
        <div className="ao-panel">
          {health.length === 0 ? (
            <EmptyState title="No cloud alerts in the last 24 hours"
              hint="provider health reports appear here when a connected account reports a problem" />
          ) : (
          <DataTable<HealthSignal> rows={health} rowKey={(r) => r.time + r.signal + r.app + r.metric} height={Math.min(480, 44 + health.length * 30)} ariaLabel="Health signals"
            columns={[
              { key: "time", header: "Time", width: 84, render: (r) => ago(r.time) },
              { key: "app", header: "Service", width: 130, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 160, render: (r) => r.resource },
              { key: "sig", header: "Signal", width: 150, render: (r) => r.signal },
              { key: "state", header: "State", width: 96, render: (r) => <HealthBadge status={r.state} /> },
              { key: "metric", header: "Metric", width: 170, render: (r) => <span className="ao-mono">{r.metric}</span> },
              { key: "cur", header: "Current", width: 76, render: (r) => <strong>{r.current}</strong> },
              { key: "base", header: "Baseline", width: 76, render: (r) => <span className="ao-muted">{r.baseline}</span> },
              { key: "sev", header: "Severity", width: 86, sortable: true, sortValue: (r) => r.severity, render: (r) => <Chip label={r.severity} tone={r.severity === "critical" ? "var(--crit)" : "var(--warn)"} /> },
              { key: "src", header: "Cloud", width: 90, render: (r) => r.source.toUpperCase() },
            ]} />
          )}
        </div>
      )}
      {view === "changes" && (
        <div className="ao-panel">
          {changes.length === 0 ? (
            <EmptyState title="No cloud change events in the last 24 hours"
              hint="management-plane changes (CloudTrail / Activity Log) appear here as the provider audits them" />
          ) : (
          <DataTable<ChangeEvent> rows={changes} rowKey={(r) => r.time + r.changeType + r.resource + r.actor} height={Math.min(480, 44 + changes.length * 30)} ariaLabel="Change events"
            columns={[
              { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
              { key: "app", header: "Service", width: 130, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 190, render: (r) => <><span className="ao-mono">{r.resource}</span>{r.cloudRef?.consoleUrl && <ConsoleLink compact href={r.cloudRef.consoleUrl} label={`Open in ${consoleName(r.cloudRef.provider)}`} />}</> },
              { key: "type", header: "Change type", width: 170, sortable: true, sortValue: (r) => r.changeType, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
              { key: "actor", header: "Actor", width: 190, render: (r) => <span className="ao-mono">{r.actor}</span> },
              { key: "src", header: "Source", width: 160, render: (r) => <>{r.source}{r.cloudRef?.logUrl && <ConsoleLink compact href={r.cloudRef.logUrl} label={r.cloudRef.provider === "aws" ? "View CloudTrail event" : "View Activity Log"} />}</> },
              { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
              { key: "sym", header: "Related symptoms", width: 180, render: (r) => r.relatedSymptoms.length ? r.relatedSymptoms.join(", ") : DASH },
            ]} />
          )}
        </div>
      )}
    </div>
  );
}

// ── Network connectivity (Investigations sub-view) ──────────────────────────
// Service→network correlation has NO ingested source today. AWS/Azure never
// ship an empty tab as an apology — this is an ENABLEMENT card (audit C): what
// the view will show, what it needs, and the one button that starts setup.
function Underlay({ goDataSources }: { goDataSources: () => void }) {
  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Network connectivity</div>
      <p className="ao-set-d">
        Correlates a service's symptoms with the network connections it rides —
        Direct Connect, VPN, ExpressRoute — so a connection fault names the
        services it degrades. Shows real connections only; nothing is simulated.
      </p>
      <div className="ao-set-v">Needs: connection telemetry (tunnel/link state + per-connection path metrics) joined to service health.</div>
      <div className="ao-cta-btns">
        <button className="ao-btn ao-btn--primary" onClick={goDataSources}>Set up in Data sources</button>
      </div>
    </div>
  );
}

// ── Untagged resources (first-class · LIVE) ──────────────────────────────────
function openIntegrations() { location.hash = "#/incident/integrations"; }

function Unknowns() {
  const [fix, setFix] = useState<UnknownContributor | null>(null);
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
        <div className="ao-panel-h">Remediation queue <span className="ao-panel-meta">tag these resources to complete your service map</span></div>
        {unknowns.length === 0 ? (
          <EmptyState title="Every discovered resource is mapped to a service"
            hint="untagged resources appear here with a fix path when discovery finds one" />
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Untagged resources" onRowClick={setFix}
            columns={[
              { key: "entity", header: "Resource", width: 210, render: (r) => <><strong>{r.name}</strong>{r.address && <span className="ao-mono ao-muted"> {r.address}</span>}</> },
              { key: "kind", header: "Type", width: 116, render: (r) => r.kind },
              { key: "provider", header: "Cloud", width: 60, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
              { key: "region", header: "Region", width: 96, render: (r) => r.region },
              { key: "bytes", header: "Traffic", width: 86, align: "right", render: (r) => NM(r.bytes, fmtBytes) },
              { key: "why", header: "Why untagged", width: 170, render: (r) => r.missingFields.length ? <Chip label={`missing ${r.missingFields.join("/")}`} tone="var(--fg-subtle)" /> : <span className="ao-muted">—</span> },
              { key: "fix", header: "Recommended fix", width: 240, render: (r) => r.recommendation },
              { key: "act", header: "Action", width: 110, render: (r) => <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); setFix(r); }}>Remediate</button> },
            ]} />
        )}
      </div>

      {fix && (
        <EvidenceDrawer title={`Remediate · ${fix.name}`} subtitle={<span className="ao-muted">{fix.kind} · {fix.provider === "—" ? "—" : fix.provider.toUpperCase()} · {fix.region}</span>} onClose={() => setFix(null)}>
          <table className="ao-kv"><tbody>
            <tr><td>Resource</td><td><strong>{fix.name}</strong>{fix.address && <> · <span className="ao-mono ao-muted">{fix.address}</span></>}</td></tr>
            <tr><td>Resource id</td><td><span className="ao-mono ao-muted">{fix.resourceId}</span></td></tr>
            <tr><td>Why untagged</td><td>{fix.missingFields.length ? `missing ${fix.missingFields.join(", ")}` : "—"}</td></tr>
            <tr><td>Recommended fix</td><td>{fix.recommendation}</td></tr>
          </tbody></table>
          <div className="ao-ev-h">Actions</div>
          {/* Only buttons that DO what they say (audit C: six buttons all led to
              one page — and "open in console" didn't open the console). Tagging
              happens in the provider console; rules/precedence live in
              Integrations. Everything else is guidance, not a fake button. */}
          <div className="ao-cta-btns">
            {(() => {
              const url = consoleUrlFor(fix, resources);
              return url ? <ConsoleLink href={url} label={`Tag in ${consoleName(fix.provider)}`} /> : null;
            })()}
            <button className="ao-btn ao-btn--primary" onClick={openIntegrations}>Attribution rules · Integrations</button>
          </div>
        </EvidenceDrawer>
      )}
    </div>
  );
}

// the console pivot for an untagged row — resolved from the resources list the
// tab already loaded (same server-built, safeConsoleUrl-gated links).
function consoleUrlFor(u: UnknownContributor, resources: CloudResource[]): string {
  const hit = resources.find((r) => r.id === u.resourceId);
  return hit?.consoleUrl ?? "";
}

// ── Evidence Explorer (LIVE: /api/cloud/evidence) ────────────────────────────
// The ledger of what the engine actually grounded: every cloud signal ATTACHED to
// a cloud correlation object (used in the verdict) plus that object's own declared
// gaps (category "missing"). The engine records no contradicting/discriminating
// role today, so those categories simply do not appear — we never claim one.
function Evidence() {
  const [f, setF] = useState<Record<string, string>>({});
  const [sel, setSel] = useState<EvidenceRow | null>(null);
  const { data, status } = useAsync(loadEvidence);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error" || !data) return <LoadError what="the evidence ledger" />;
  const all = data.rows;
  if (all.length === 0) {
    return (
      <div className="ao-panel">
        <EmptyState title="No findings in the last 24 hours"
          hint="findings appear when the engine grounds a cloud signal into an investigation — check Data sources if no cloud signals are landing at all" />
      </div>
    );
  }
  const rows = all.filter((e) =>
    (!f.signal || e.signalType === f.signal) &&
    (!f.confidence || e.confidence === f.confidence) &&
    (!f.category || e.category === f.category) &&
    (!f.grounded || (f.grounded === "yes") === e.grounded) &&
    (!f.app || e.app === f.app));
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "app", label: "Service", options: [...new Set(all.map((e) => e.app))].map((a) => ({ value: a, label: a })) },
          { key: "category", label: "Category", options: [...new Set(all.map((e) => e.category))].map((c) => ({ value: c, label: c })) },
          { key: "signal", label: "Signal type", options: [...new Set(all.map((e) => e.signalType))].map((s) => ({ value: s, label: s })) },
          { key: "confidence", label: "Confidence", options: [...new Set(all.map((e) => e.confidence))].map((c) => ({ value: c, label: c })) },
          { key: "grounded", label: "Grounded", options: [{ value: "yes", label: "yes" }, { value: "no", label: "gap" }] },
        ]} />
      <div className="ao-panel">
        {data.total > rows.length && (
          <div className="ao-panel-meta" style={{ marginBottom: 6 }}>
            showing {rows.length} of {data.total.toLocaleString()} findings (true count — the page is bounded)
          </div>
        )}
        <DataTable<EvidenceRow> rows={rows} rowKey={(r) => `${r.evidenceRef}|${r.rcaGroup}|${r.time}|${r.reason}`} height={Math.min(480, 44 + rows.length * 30)}
          ariaLabel="Findings" onRowClick={setSel}
          columns={[
            { key: "time", header: "Time", width: 84, render: (r) => ago(r.time) },
            { key: "cat", header: "Category", width: 130, sortable: true, sortValue: (r) => r.category, render: (r) => <EvidenceCategoryBadge category={r.category} /> },
            { key: "sig", header: "Signal type", width: 140, render: (r) => r.signalType },
            { key: "app", header: "Service", width: 110, render: (r) => <strong>{r.app}</strong> },
            { key: "res", header: "Resource", width: 130, render: (r) => <>{r.resource}{r.cloudRef?.consoleUrl && <ConsoleLink compact href={r.cloudRef.consoleUrl} label={`Open in ${consoleName(r.cloudRef.provider)}`} />}</> },
            { key: "src", header: "Source", width: 130, render: (r) => r.source },
            { key: "conf", header: "Confidence", width: 104, render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "reason", header: "Reason", width: 320, render: (r) => <span className="ao-why" title={r.reason}>{r.reason}</span> },
            { key: "grounded", header: "Grounded", width: 90, render: (r) => r.grounded ? <Chip label="yes" tone="var(--accent)" /> : <span className="ao-muted">gap</span> },
            { key: "rca", header: "Investigation", width: 130, render: (r) => r.rcaGroup ? (
              <a className="ao-rowaction" href={`#/monitoring/correlations?id=${encodeURIComponent(r.rcaGroup)}`}
                onClick={(e) => e.stopPropagation()} title={r.rcaGroup}>Open</a>
            ) : DASH },
          ]} />
      </div>
      {sel && (
        <EvidenceDrawer title={`${sel.signalType} · ${sel.app}`} subtitle={<span className="ao-drawer-badges"><EvidenceCategoryBadge category={sel.category} /><ConfidenceBadge level={sel.confidence} /></span>} onClose={() => setSel(null)}>
          <table className="ao-kv"><tbody>
            <tr><td>Time</td><td>{new Date(sel.time).toLocaleString()}</td></tr>
            <tr><td>Category</td><td><EvidenceCategoryBadge category={sel.category} /></td></tr>
            <tr><td>Service / Resource</td><td>{sel.app} · {sel.resource}</td></tr>
            <tr><td>Source</td><td>{sel.source}</td></tr>
            <tr><td>Confidence</td><td><ConfidenceBadge level={sel.confidence} /></td></tr>
            <tr><td>Grounded</td><td>{sel.grounded ? "yes — attached to the investigation by the engine" : "no — a declared gap"}</td></tr>
            <tr><td>Reason</td><td>{sel.reason}</td></tr>
            <tr><td>Investigation</td><td>{sel.rcaGroup
              ? <a href={`#/monitoring/correlations?id=${encodeURIComponent(sel.rcaGroup)}`}>Open the full analysis</a>
              : "—"}</td></tr>
            <tr><td>Evidence ref</td><td><span className="ao-mono ao-muted">{sel.evidenceRef}</span></td></tr>
            {sel.cloudRef && (
              <tr><td>Cloud resource</td><td>
                <span className="ao-mono ao-muted">{sel.cloudRef.resourceId || "—"}</span>
                {sel.cloudRef.consoleUrl && <> · <ConsoleLink href={sel.cloudRef.consoleUrl} label={`Open in ${consoleName(sel.cloudRef.provider)}`} /></>}
              </td></tr>
            )}
            {sel.cloudRef?.logUrl && (
              <tr><td>Provider record</td><td>
                <ConsoleLink href={sel.cloudRef.logUrl}
                  label={sel.cloudRef.provider === "aws" ? "View CloudTrail event" : "View Activity Log"} />
              </td></tr>
            )}
          </tbody></table>
        </EvidenceDrawer>
      )}
    </div>
  );
}

// ── Settings ─────────────────────────────────────────────────────────────────
// Advanced configuration only — connector setup lives in the first-class
// Ingestion tab + Admin → Integrations, not here. Each card shows the current
// effective config (real resolver defaults) with a single manage action.
function Settings() {
  const sections: { t: string; d: string; value: string; cta: string }[] = [
    { t: "Catalog Sources", d: "Managed vendor IP/domain feeds used for catalog-based attribution.", value: "AWS · Azure · GCP · Microsoft 365 (refreshed every 6h)", cta: "Configure catalog sources" },
    { t: "Cloud Connectors", d: "Cloud account setup is managed in Admin → Integrations.", value: "Connect AWS / Azure / GCP accounts (least-privilege IAM)", cta: "Open Integrations" },
    { t: "Attribution Rules", d: "Source precedence when signals disagree.", value: "cloud tag → resource graph → firewall App-ID → domain → IP catalog", cta: "Edit attribution precedence" },
    { t: "Required Tags", d: "Tags an org requires — drives the coverage report.", value: "app · owner · env (case-insensitive)", cta: "Edit required tags" },
    { t: "RCA Windows", d: "Deploy-to-degradation correlation window + verdict thresholds.", value: "Default deploy→degradation window: 30 minutes", cta: "Edit RCA windows" },
  ];
  return (
    <div className="ao-settings">
      {sections.map((s) => (
        <div key={s.t} className="ao-panel">
          <div className="ao-panel-h">{s.t}</div>
          <p className="ao-set-d">{s.d}</p>
          <div className="ao-set-v">{s.value}</div>
          <button className="ao-btn" onClick={openIntegrations}>{s.cta}</button>
        </div>
      ))}
    </div>
  );
}
