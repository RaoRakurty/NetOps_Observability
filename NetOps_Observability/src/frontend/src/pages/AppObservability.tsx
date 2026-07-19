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

import { fmtDateTime } from "../lib/time";
import { useEffect, useState } from "react";
import { NocHeader, Chip } from "../components/noc";
import { Segmented, Skeleton } from "../components/ui";
import DataTable from "../components/DataTable";
import {
  ConfidenceBadge, HealthBadge, AppIdentityPill, MetricCard,
  CardGroup, EmptyState, FilterBar, EvidenceDrawer,
  EvidenceCategoryBadge, ConsoleLink, consoleName, fmtBps, fmtBytes, ago, OriginCell,
} from "./appobs/badges";
import { serviceIdentity } from "./appobs/origin";
import { FeedBar } from "./appobs/FeedBar";
import {
  filterByRange, feedCount, newestIso, rangeWords, windowHoursFor, withinRange,
} from "./appobs/range";
import { useCloudScope, CloudScopeControl } from "./appobs/useCloudScope";
import { scopeKey, isScopeActive } from "./appobs/scopeUrl";
import type { CloudScopeState } from "./appobs/scopeUrl";
import {
  appInScope, buildScopeIndex, signalInScope, healthScopeKey, changeScopeKey,
  evidenceScopeKey, objectInScope, unknownInScope, scopedToNothing,
} from "./appobs/scope";
import type { ScopeIndex } from "./appobs/scope";
import AppDetail from "./appobs/AppDetail";
import Ingestion from "./appobs/Ingestion";
import AssignServiceDrawer from "./appobs/AssignService";
import ResourceMetricsPanel from "./appobs/ResourceMetricsPanel";
import MonitorsSettings from "./appobs/MonitorsSettings";
import { RequiredTagsCard, RcaWindowCard, AttributionPrecedenceCard, GovernanceAuditCard, SeamOwnersCard } from "./appobs/GovernanceSettings";
import ServiceCatalog, { CriticalityBadge } from "./appobs/ServiceCatalog";
import ServiceMap from "./appobs/ServiceMap";
import { catalogByName, nameKey, criticalityRank } from "./appobs/catalog";
import { buildDegradedRows, fmtDuration } from "./appobs/impact";
import type { DegradedServiceRow } from "./appobs/impact";
import type { BusinessServiceRow } from "../services/api";
import { toggleSelection, toggleAllVisible } from "./appobs/assign";
import type {
  App, ChangeEvent, CloudResource, Confidence, Coverage, EvidenceRow, HealthSignal, UnknownContributor,
} from "./appobs/types";
import {
  loadApps, loadResources, loadCoverage, loadHealthSignals, loadChangeEvents, loadEvidence,
  loadHealthPage, loadChangesPage, downloadCloudExport,
  invalidateCloudInventory, NOT_MEASURED,
} from "./appobs/api";
import { sqFromHash, hashWithSq, listViews, saveView, deleteView } from "./appobs/signalPage";
import { getActiveScope } from "../services/api";
import type { CloudRcaObject } from "./appobs/api";
import { signatureNocTitle } from "../components/rca/labels";
import { funnelSteps, coverageByScope, groupByApp, RESOURCE_CATEGORIES, WORKLOAD_CLASSES, WORKLOAD_CLASS_META, workloadClass } from "./appobs/attribution";
import type { WorkloadClass } from "./appobs/attribution";
import { useCloudShell } from "./appobs/useCloudShell";
import { CloudScopeBar, ReadinessStrip, SourceStatusBadge } from "./appobs/shell";
import { SOURCE_LABEL } from "./appobs/readiness";
import type { ReadinessSummary, SourceType, SourceStatus } from "./appobs/readiness";
import { api } from "../services/api";
import { friendlyProblemId } from "../components/rca/labels";
import InvestigationDrawer from "./appobs/InvestigationDrawer";
import { useInvestigationDrawer } from "./appobs/useInvestigationDrawer";
import { severityRank } from "../theme/severity";
import { healthRank, confidenceRank, verdictRank, timeRank } from "./appobs/sortRanks";
import { buildTimeline, cleanVal, isStateEvent, stateLabel, stateReason } from "./appobs/timeline";
import type { TimelineEpisode } from "./appobs/timeline";
import {
  healthMetricCell, healthCurrentCell, healthBaselineCell, healthReasonCell,
} from "./appobs/healthCells";

// async loader with explicit loading/error/empty states (no fake-data fallback —
// an empty inventory shows an honest "connect a cloud account" state).
function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): { data: T | null; status: LoadState } {
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
    // deps let a caller force a refetch (e.g. after a bulk service assignment).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
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

// The Service cell of an investigation (owner review #1). A blank cell told the
// operator nothing; this always names something and always explains what it is
// naming — the real service, the primary affected resource as an explicit
// fallback, or "unattributed" with the reason there is no service mapping.
function ServiceCell({ o }: { o: CloudRcaObject }) {
  const id = serviceIdentity(o.apps, o.origin);
  if (id.kind === "service") return <strong>{id.label}</strong>;
  if (id.kind === "resource") {
    return (
      <span className="ao-svc-fallback" title={id.why}>
        <span className="ao-mono">{id.label}</span>
        <span className="ao-muted ao-svc-note"> · resource</span>
      </span>
    );
  }
  return <span className="ao-unknown" title={id.why}>unattributed</span>;
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

// Empty-scope honesty (Wave 2 #5): data EXISTS, the active scope just matches
// none of it. A distinct state from "nothing ingested" — the fix is the filter,
// not a connector — so it says so and offers the one-click way out.
function ScopeEmpty({ what, ctl }: { what: string; ctl: CloudScopeControl }) {
  return (
    <div className="ao-panel">
      <EmptyState title={`No ${what} in this scope`}
        hint="the provider / account / region / env filters above match nothing here"
        action={<button className="ao-btn ao-btn--primary" onClick={ctl.clearFilters}>Clear filters</button>} />
    </div>
  );
}

// A surface built from CURRENT inventory is inherently range-less: the global
// time range parameterizes the SIGNAL surfaces, never this one — and the label
// says so instead of pretending (Wave 2 #5 honesty rule).
function CurrentNote() {
  return <span className="ao-panel-meta" title="the time range applies to signal views (alerts, changes, findings); inventory is always the current state">current inventory · not a time-range view</span>;
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
  catalog: { tab: "services", sub: "catalog" },
  appmap: { tab: "services", sub: "map" },
  attribution: { tab: "resources", sub: "mapping" },
  unknowns: { tab: "resources", sub: "untagged" },
  health: { tab: "investigations", sub: "alerts" },
  evidence: { tab: "investigations", sub: "findings" },
  underlay: { tab: "investigations", sub: "network" },
  ingestion: { tab: "datasources" },
  // Deep-link straight to the REAL cloud-account onboarding surface
  // (Data sources → Accounts → "Connect a cloud account"). Settings' Cloud
  // Connectors card points here; it used to point at the ITSM Integrations page,
  // which has nothing to do with cloud accounts (owner review #3/#4).
  accounts: { tab: "datasources", sub: "accounts" },
};

export default function AppObservability() {
  const [tab, setTab] = useState<Tab>("overview");
  const [sub, setSub] = useState<string>("");
  const [sel, setSel] = useState<App | null>(null);
  const shell = useCloudShell();
  // Embedded investigation drawer (#7): a correlation object opens INSIDE this
  // page (docked Inspector under shell-v2, page drawer on the v1 shell) and its
  // id is mirrored to ?inv=<id> so refresh / a shared link reopens it here.
  const inv = useInvestigationDrawer();
  // Global scope + time range (Wave 2 #5): URL-backed (shares the hash query
  // with ?inv=), feeds EVERY tab below. Narrows within the tenant view only.
  const scopeCtl = useCloudScope();

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
      <CloudScopeBar scope={shell.scope} mode={shell.mode} summary={shell.summary}
        control={{
          scope: scopeCtl.scope, options: shell.options, active: scopeCtl.active,
          add: scopeCtl.add, remove: scopeCtl.remove,
          clearFilters: scopeCtl.clearFilters, setRangeMinutes: scopeCtl.setRangeMinutes,
        }} />

      <nav className="ao-tabs" role="tablist" aria-label="Service View">
        {TABS.map((tk) => (
          <button key={tk} role="tab" aria-selected={tab === tk}
            className={`ao-tab${tab === tk ? " is-active" : ""}`}
            onClick={() => { setTab(tk); setSub(""); }} title="Live cloud telemetry">
            {TAB_LABEL[tk]}
          </button>
        ))}
      </nav>

      {tab === "overview" && <Overview goTab={(t, s) => { setTab(t); setSub(s ?? ""); }} summary={shell.summary} openInvestigation={inv.open} ctl={scopeCtl} />}
      {tab === "services" && <Services initialSub={sub} onOpen={setSel} ctl={scopeCtl} />}
      {tab === "investigations" && <Investigations initialSub={sub} goDataSources={() => { setTab("datasources"); setSub(""); }} openInvestigation={inv.open} ctl={scopeCtl} />}
      {tab === "resources" && <ResourcesGroup initialSub={sub} ctl={scopeCtl} />}
      {tab === "datasources" && <Ingestion initialSub={sub} scope={scopeCtl.scope} onClearScope={scopeCtl.clearFilters} />}
      {tab === "settings" && <Settings />}

      {/* v1-shell fallback: same drawer content in the page-local panel (ESC/X/scrim). */}
      {inv.inlineId && (
        <EvidenceDrawer title={`Investigation · ${friendlyProblemId(inv.inlineId)}`}
          subtitle="Service View" onClose={inv.closeInline}>
          <InvestigationDrawer id={inv.inlineId} />
        </EvidenceDrawer>
      )}
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

// ── Services (Applications + Catalog + Service map) ──────────────────────────
function Services({ initialSub, onOpen, ctl }: {
  initialSub: string; onOpen: (a: App) => void; ctl: CloudScopeControl;
}) {
  const [sub, setSub] = useState<"applications" | "catalog" | "map">(
    initialSub === "map" ? "map" : initialSub === "catalog" ? "catalog" : "applications");
  return (
    <div className="ao-stack">
      <SubTabs value={sub} onChange={setSub}
        items={[
          { key: "applications", label: "Applications" },
          { key: "catalog", label: "Catalog" },
          { key: "map", label: "Service map" },
        ]} />
      {sub === "applications" && <Applications onOpen={onOpen} ctl={ctl} />}
      {sub === "catalog" && <ServiceCatalog />}
      {sub === "map" && <MapView ctl={ctl} />}
    </div>
  );
}

// ── Investigations (Timeline · Alerts · Changes · Findings · Network) ────────
function Investigations({ initialSub, goDataSources, openInvestigation, ctl }: {
  initialSub: string; goDataSources: () => void; openInvestigation: (id: string) => void;
  ctl: CloudScopeControl;
}) {
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
      {(sub === "timeline" || sub === "alerts" || sub === "changes") && <HealthChanges view={sub} ctl={ctl} />}
      {sub === "findings" && <Evidence openInvestigation={openInvestigation} ctl={ctl} />}
      {sub === "network" && <Underlay goDataSources={goDataSources} />}
    </div>
  );
}

// ── Resources group (Resources · Service mapping · Untagged) ─────────────────
function ResourcesGroup({ initialSub, ctl }: { initialSub: string; ctl: CloudScopeControl }) {
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
      {sub === "resources" && <Resources ctl={ctl} />}
      {sub === "mapping" && <Attribution ctl={ctl} />}
      {sub === "untagged" && <Unknowns ctl={ctl} />}
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
  /** rows the ACTIVE scope filtered away (drives "no matches in scope"). */
  hadObjects: boolean;
  /** operator catalog (criticality/owner for the degraded strip); [] on 501. */
  catalog: BusinessServiceRow[];
}

async function loadOverview(scope: CloudScopeState): Promise<OverviewData> {
  const wh = windowHoursFor(scope.rangeMinutes);
  // Resources arrive SERVER-filtered (Wave-1 SQL filters); the signal reads take
  // the real range window. Signals/apps/objects are then narrowed CLIENT-side —
  // these sets are already loaded and LIMIT-bounded, and the signal store has no
  // provider/account columns to filter on server-side (see scope.ts header).
  const [apps, resources, cov, health, changes, ev, allRes, catalog] = await Promise.all([
    loadApps(), loadResources(scope), loadCoverage(),
    loadHealthSignals(undefined, wh), loadChangeEvents(undefined, wh), loadEvidence(undefined, wh),
    // The UNFILTERED inventory backs the signal→scope join: a signal on an
    // out-of-scope resource must RESOLVE (and be excluded), not float through
    // as "unresolvable". Same shared 30s-TTL cache — no extra request when the
    // scope is empty, one when it is not.
    loadResources(),
    // catalog = enrichment for the degraded strip (criticality/owner); a
    // deployment without the catalog store still renders the strip un-ranked.
    api.cloudBusinessServices().then((r) => r.business_services ?? [], () => [] as BusinessServiceRow[]),
  ]);
  const idx = buildScopeIndex(allRes);
  const minutes = scope.rangeMinutes;
  return {
    apps: apps.filter((a) => appInScope(a, scope)),
    resources,
    coverage: cov.coverage,
    health: filterByRange(health, minutes).filter((h) => signalInScope(healthScopeKey(h), scope, idx)),
    changes: filterByRange(changes, minutes).filter((c) => signalInScope(changeScopeKey(c), scope, idx)),
    objects: ev.objects.filter((o) => objectInScope(o, scope, idx)),
    openCount: ev.openCount,
    objectsTruncated: ev.objectsTruncated,
    hadObjects: ev.objects.length > 0,
    catalog,
  };
}

// apps with a health signal that says degraded/down in the window — measured from
// the signals themselves, never a threshold we invented.
function degradedApps(health: HealthSignal[]): string[] {
  return [...new Set(health.filter((h) => h.state === "degraded" || h.state === "down")
    .map((h) => h.app).filter((a) => a && a !== "—"))];
}

function Overview({ goTab, summary, openInvestigation, ctl }: {
  goTab: (t: Tab, sub?: string) => void; summary: ReadinessSummary;
  openInvestigation: (id: string) => void; ctl: CloudScopeControl;
}) {
  const scope = ctl.scope;
  const { data, status } = useAsync(() => loadOverview(scope), [scopeKey(scope)]);

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

  const { apps, resources, coverage, health, changes, objects, openCount, objectsTruncated, hadObjects, catalog } = data;
  // Degraded = health-signal verdicts ∪ live measured app health (provider status
  // checks + probe outcomes). A dead health feed must never render as "0 degraded"
  // = "all healthy": with nothing measured at all we say "—", not 0.
  const degraded = [...new Set([
    ...degradedApps(health),
    ...apps.filter((a) => a.health === "degraded" || a.health === "down").map((a) => a.name),
  ])];
  const healthMeasured = health.length > 0 || apps.some((a) => a.health !== "unknown");
  // The worst-first strip rows (rev #22): name · duration · criticality · blast
  // radius, joined with the operator catalog for criticality/owner.
  const degradedRows = buildDegradedRows(apps, health, resources, catalog, Date.now());
  const bizCritical = degradedRows.filter((r) => r.criticality === "critical").length;
  const openRca = objects.filter((o) => o.state === "open");
  const unknownPct = coverage.total ? Math.round((coverage.unknown / coverage.total) * 100) : NOT_MEASURED;
  const scoped = isScopeActive(scope);
  // signal-window words: what the health/changes cards actually cover.
  const rangeText = rangeWords(scope.rangeMinutes);
  // the investigations window is the SERVER window (sub-day ranges keep the 24h
  // read: an open investigation that started 20h ago must not vanish at "1h").
  const objWindowText = rangeWords(windowHoursFor(scope.rangeMinutes) * 60);

  return (
    <div className="ao-stack">
      {/* Readiness BEFORE impact — prove the data is connected before any verdict. */}
      <div className="ao-section-l">Data readiness</div>
      <ReadinessStrip summary={summary} />

      {/* A. grouped operational cards — each one measured, or an explicit "—". */}
      <div className="ao-groups">
        <CardGroup title="Impact">
          <MetricCard label="Services Degraded" value={healthMeasured ? degraded.length : DASH}
            trend={healthMeasured
              ? (bizCritical
                ? `${bizCritical} business-critical · ${rangeText}`
                : `provider status + health signals · ${rangeText}`)
              : "no health feed measured"}
            tone={!healthMeasured ? undefined : degraded.length ? "warn" : "good"} />
          {/* scoped: the count is of the investigations IN scope (the tenant-wide
              dedicated count stays visible in the trend, never silently replaced) */}
          <MetricCard label="Open Investigations"
            value={scoped ? openRca.length : openCount}
            trend={scoped ? `in scope · ${openCount} open tenant-wide` : "engine-formed · dedicated count"}
            tone={(scoped ? openRca.length : openCount) ? "warn" : "good"} />
        </CardGroup>
        <CardGroup title="Coverage">
          <MetricCard label="Services Observed" value={apps.length.toLocaleString()} trend="current inventory" tone="accent" />
          <MetricCard label="Resources Mapped" value={resources.length.toLocaleString()} trend="current inventory · discovered + attributed" />
          <MetricCard label="Untagged Resources"
            value={unknownPct < 0 ? DASH : `${unknownPct}%`}
            trend={coverage.total ? `${coverage.unknown} of ${coverage.total}${scoped ? " · tenant-wide" : ""}` : undefined}
            tone={unknownPct > 10 ? "warn" : unknownPct < 0 ? undefined : "good"} />
        </CardGroup>
        <CardGroup title="Change">
          <MetricCard label="Recent Cloud Changes" value={changes.length} trend={`provider audit log · ${rangeText}`} />
        </CardGroup>
      </div>
      {/* Roadmap honesty (rev #22): the impact metric we do NOT measure yet
          stays out of the cards — a permanent "—" card reads as broken, a
          footnote reads as a roadmap. Deploy-linked change correlation shipped
          per-investigation (Wave 4 #12: the "Changes near onset" card in the
          investigation drawer); an Overview-level aggregate returns here when
          its feed lands. */}
      <div className="ao-muted" style={{ fontSize: 12 }}>
        Coming soon: network impact (service→connection correlation)
      </div>

      {/* A2. worst-first degraded services (rev #22): name · duration ·
          criticality · blast radius — the "what do I act on" answer. */}
      <div className="ao-panel">
        <div className="ao-panel-h">Degraded services
          <span className="ao-panel-meta">worst first · duration from the first degraded signal in the {rangeText}</span></div>
        {!healthMeasured ? (
          <EmptyState title="No health feed measured"
            hint="provider status checks and health signals light this up — check Data sources"
            action={<button className="ao-btn ao-btn--primary" onClick={() => goTab("datasources")}>Check data sources</button>} />
        ) : degradedRows.length === 0 ? (
          <EmptyState title={`No degraded services in the ${rangeText}`}
            hint="every service with measured health is healthy in this window" />
        ) : (
          <DataTable<DegradedServiceRow> rows={degradedRows} rowKey={(r) => r.name}
            height={Math.min(300, 56 + degradedRows.length * 34)} ariaLabel="Degraded services"
            onRowClick={() => goTab("services", "applications")}
            columns={[
              { key: "name", header: "Service", width: 200, text: (r) => r.name,
                render: (r) => <strong>{r.name}</strong> },
              { key: "state", header: "Health", width: 110,
                render: (r) => <HealthBadge status={r.state} /> },
              { key: "crit", header: "Criticality", width: 175,
                sortValue: (r) => criticalityRank(r.criticality),
                render: (r) => <CriticalityBadge value={r.criticality} /> },
              { key: "dur", header: "Duration", width: 130, sortValue: (r) => r.durationMs,
                render: (r) => r.sinceIso
                  ? <span title={`first degraded signal ${fmtDateTime(r.sinceIso)}`}>{fmtDuration(r.durationMs)}</span>
                  : <span className="ao-muted" title="live provider status says degraded; no timestamped signal in the window">duration unknown</span> },
              { key: "blast", header: "Blast radius", width: 180,
                sortValue: (r) => r.affected,
                render: (r) => r.affected
                  ? <span>{r.affected}{r.total ? ` of ${r.total}` : ""} resource{(r.total || r.affected) === 1 ? "" : "s"}</span>
                  : <span className="ao-muted" title="the signals did not name specific resources">extent not measured</span> },
              { key: "owner", header: "Owner", width: 140,
                render: (r) => r.owner === "—" ? <span className="ao-muted">—</span> : r.owner },
            ]} />
        )}
      </div>

      {/* B. the REAL investigations the engine formed — no heuristic verdicts. */}
      <div className="ao-panel">
        <div className="ao-panel-h">Open investigations
          <span className="ao-panel-meta">
            grounded on cloud signals · click a row to open it here
            {objectsTruncated && openRca.length < openCount &&
              ` · showing ${openRca.length} of ${openCount} open`}
          </span></div>
        {objects.length === 0 ? (
          scopedToNothing(scope, Number(hadObjects), 0) ? (
            <EmptyState title="No investigations in this scope"
              hint="investigations exist outside the current provider / account / region / env filters"
              action={<button className="ao-btn ao-btn--primary" onClick={ctl.clearFilters}>Clear filters</button>} />
          ) : (
          <EmptyState title={`No open investigations in the ${objWindowText}`}
            hint={health.length || changes.length
              ? "cloud signals are landing; none has grounded into an investigation yet"
              : "no cloud health or change signals have landed yet"}
            action={!(health.length || changes.length)
              ? <button className="ao-btn ao-btn--primary" onClick={() => goTab("datasources")}>Check data sources</button>
              : undefined} />
          )
        ) : (
          <DataTable<CloudRcaObject> rows={objects} rowKey={(o) => o.correlationId}
            height={Math.min(460, 56 + objects.length * 34)} ariaLabel="Open investigations"
            initialSort={{ key: "verdict", dir: "asc" }}
            onRowClick={(o) => openInvestigation(o.correlationId)}
            columns={[
              // Service: the engine's named service, else the primary affected
              // resource, else an explicit "unattributed" that says WHY — never
              // the old silent dash the owner had to guess at (review #1).
              { key: "apps", header: "Service", width: 220,
                sortValue: (o) => serviceIdentity(o.apps, o.origin).label,
                render: (o) => <ServiceCell o={o} /> },
              // Origin: which cloud this actually came from, proven by the
              // providers present in the object's own evidence (review #5).
              { key: "origin", header: "Origin", width: 160,
                sortValue: (o) => o.origin.providers.join("+") || "~onprem",
                render: (o) => <OriginCell providers={o.origin.providers} /> },
              { key: "verdict", header: "Assessment", width: 120, sortValue: (o) => verdictRank(o.verdictTier), render: (o) => <ConfidenceBadge level={verdictConf(o.verdictTier)} /> },
              { key: "hyp", header: "Probable cause", width: 300, sortValue: (o) => o.topHypothesis, render: (o) => <span className="ao-why" title={o.topHypothesis}>{o.topHypothesis.startsWith("sig.") ? signatureNocTitle(o.topHypothesis) : o.topHypothesis}</span> },
              { key: "conf", header: "Confidence", width: 96, align: "right", sortValue: (o) => o.confidence, render: (o) => `${Math.round(o.confidence * 100)}%` },
              { key: "sig", header: "Signals", width: 80, align: "right", sortValue: (o) => o.signalCount, render: (o) => o.signalCount },
              { key: "state", header: "State", width: 80, sortValue: (o) => o.state, render: (o) => o.state },
              { key: "start", header: "Started", width: 110, sortValue: (o) => timeRank(o.windowStart), render: (o) => ago(o.windowStart) },
              { key: "act", header: "Findings", width: 110, render: () => <button className="ao-rowaction" onClick={(e) => { e.stopPropagation(); goTab("investigations", "findings"); }}>Findings</button> },
            ]} />
        )}
      </div>
    </div>
  );
}

// ── Applications (LIVE: /api/cloud/apps, joined with the operator catalog) ───
function Applications({ onOpen, ctl }: { onOpen: (a: App) => void; ctl: CloudScopeControl }) {
  const [f, setF] = useState<Record<string, string>>({});
  // The catalog join is enrichment: a deployment without the catalog store
  // (501) still renders the derived apps — criticality shows "—".
  const { data, status } = useAsync(async () => {
    const [apps, cat] = await Promise.all([
      loadApps(),
      api.cloudBusinessServices().then((r) => r.business_services ?? [], () => [] as BusinessServiceRow[]),
    ]);
    return { apps, cat };
  });
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="applications" />;
  const all = data?.apps ?? [];
  const catalog = catalogByName(data?.cat ?? []);
  if (all.length === 0) return <CloudEmpty />;
  // Global scope first (client-side: apps are DERIVED rows the tab already
  // loaded whole — there is no server filter on /api/cloud/apps), then the
  // tab's own FilterBar refines within it.
  const apps = all.filter((a) => appInScope(a, ctl.scope));
  if (apps.length === 0) return <ScopeEmpty what="services" ctl={ctl} />;
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
        {/* range-less honesty: services come from the inventory, not a window */}
        <div className="ao-panel-h">Services <CurrentNote /></div>
        <DataTable<App> rows={rows} rowKey={(a) => a.id} height={Math.min(520, 44 + rows.length * 30)}
          ariaLabel="Applications" onRowClick={onOpen} initialSort={{ key: "name", dir: "asc" }}
          columns={[
            { key: "name", header: "Service", width: 160, sortable: true, text: (a) => a.name, render: (a) => <strong>{a.name}</strong> },
            { key: "health", header: "Health", width: 100, sortValue: (a) => healthRank(a.health), render: (a) => <HealthBadge status={a.health} /> },
            // Criticality is the operator catalog's word (Services → Catalog);
            // an app not in the catalog shows "—", never an assumed tier.
            { key: "crit", header: "Criticality", width: 175,
              sortValue: (a) => criticalityRank(catalog.get(nameKey(a.name))?.criticality ?? ""),
              render: (a) => <CriticalityBadge value={catalog.get(nameKey(a.name))?.criticality ?? ""} /> },
            { key: "owner", header: "Owner", width: 100,
              sortValue: (a) => catalog.get(nameKey(a.name))?.owner || a.owner,
              render: (a) => catalog.get(nameKey(a.name))?.owner || a.owner },
            { key: "env", header: "Env", width: 60, sortValue: (a) => a.env, render: (a) => a.env },
            { key: "conf", header: "Confidence", width: 110, sortValue: (a) => confidenceRank(a.confidence), render: (a) => <ConfidenceBadge level={a.confidence} /> },
            { key: "src", header: "Mapped by", width: 120, sortValue: (a) => MAPPED_BY[a.source] ?? a.source, render: (a) => MAPPED_BY[a.source] ?? a.source },
            { key: "provider", header: "Cloud", width: 90, sortValue: (a) => a.providers.join("+"), render: (a) => a.providers.length ? a.providers.map((p) => p.toUpperCase()).join(" + ") : "—" },
            { key: "acct", header: "Account", width: 130, sortValue: (a) => a.account, render: (a) => <span className="ao-mono ao-muted">{a.account}</span> },
            { key: "region", header: "Region", width: 100, sortValue: (a) => a.region, render: (a) => a.region },
            { key: "res", header: "Res", width: 50, align: "right", sortable: true, sortValue: (a) => a.resources, render: (a) => a.resources },
            { key: "traffic", header: "Traffic", width: 95, align: "right", sortValue: (a) => a.trafficBps, render: (a) => NM(a.trafficBps, fmtBps) },
            { key: "err", header: "Err%", width: 60, align: "right", sortValue: (a) => a.errorPct, render: (a) => NM(a.errorPct, (n) => `${n}%`) },
            { key: "p95", header: "P95", width: 70, align: "right", sortValue: (a) => a.p95ms, render: (a) => NM(a.p95ms, (n) => `${n}ms`) },
          ]} />
      </div>
    </div>
  );
}

// ── Service map group (tracker #110, Wave 3 #9 carried) ──────────────────────
// The OBSERVED talks_to dependency graph (/api/cloud/service-map — cloud flow
// pairs + REJECT evidence) is the default view; the inventory-derived
// structural map below stays one click away — two honest views, never merged
// into one map that would mix observed traffic with static structure.
function MapView({ ctl }: { ctl: CloudScopeControl }) {
  const [mode, setMode] = useState<"observed" | "structure">("observed");
  return (
    <div className="ao-stack">
      <SubTabs value={mode} onChange={setMode} items={[
        { key: "observed", label: "Observed dependencies" },
        { key: "structure", label: "Structure" },
      ]} />
      {mode === "observed" ? <ServiceMap ctl={ctl} /> : <AppMap ctl={ctl} />}
    </div>
  );
}

// ── App Map (graph-ready placeholder) ────────────────────────────────────────
// App Map — the STRUCTURAL app→resource map from the live inventory (real). The
// traffic-dependency layer (talks_to / egresses_via / suspected_cause edges) needs
// cloud flow logs and is honestly deferred, not faked.
function AppMap({ ctl }: { ctl: CloudScopeControl }) {
  // Server-side scope (Wave-1 SQL filters) — the map shows the scoped structure.
  const { data, status } = useAsync(() => loadResources(ctl.scope), [scopeKey(ctl.scope)]);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="app map" />;
  const resources = data ?? [];
  if (resources.length === 0) {
    return ctl.active ? <ScopeEmpty what="resources" ctl={ctl} /> : <CloudEmpty />;
  }
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
function Resources({ ctl }: { ctl: CloudScopeControl }) {
  const [f, setF] = useState<Record<string, string>>({});
  const [sel, setSel] = useState<CloudResource | null>(null);
  // Bulk service-attribution (2026-07 review imp #5): select resources → assign
  // them to a business service via the operator-authoritative override API.
  const [picked, setPicked] = useState<ReadonlySet<string>>(new Set());
  const [assigning, setAssigning] = useState(false);
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  // SERVER-side scope: provider/account/region ride the Wave-1 SQL filters on
  // /api/cloud/resources (env narrows client-side inside loadResources — it is
  // a resolved tag, not a store column).
  const { data, status } = useAsync(() => loadResources(ctl.scope), [reloadKey, scopeKey(ctl.scope)]);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="cloud resources" />;
  const all = data ?? [];
  if (all.length === 0) {
    return ctl.active ? <ScopeEmpty what="resources" ctl={ctl} /> : <CloudEmpty />;
  }
  const rows = all.filter((r) =>
    (!f.missing || r.missingTags.includes(f.missing)) &&
    (!f.unknown || (f.unknown === "yes") === (r.app === "")) &&
    (!f.provider || r.provider === f.provider) &&
    (!f.class || workloadClass(r.type) === f.class));
  const providerOpts = [...new Set(all.map((r) => r.provider))]
    .filter((p) => p !== "—").map((p) => ({ value: p, label: p.toUpperCase() }));
  // Workload classes (Wave 5 #15): always offered — an empty class renders its
  // honest "nothing discovered + needed permission" state, never a bare table.
  const classOpts = WORKLOAD_CLASSES.map((c) => ({ value: c, label: WORKLOAD_CLASS_META[c].label }));
  const classEmpty = f.class && rows.length === 0
    ? WORKLOAD_CLASS_META[f.class as WorkloadClass] : null;
  const visibleIds = rows.map((r) => r.id);
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => picked.has(id));
  // After a write the cached inventory is stale — drop it and refetch so the
  // table shows the stored truth (operator mapping now wins over inference).
  const reload = () => { invalidateCloudInventory(); setReloadKey((k) => k + 1); };
  return (
    <div className="ao-stack">
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "provider", label: "Provider", options: providerOpts },
          { key: "class", label: "Workload class", options: classOpts },
          { key: "missing", label: "Missing tag", options: [{ value: "app", label: "app" }, { value: "owner", label: "owner" }, { value: "env", label: "env" }] },
          { key: "unknown", label: "Untagged service", options: [{ value: "yes", label: "yes" }] },
        ]} />
      {picked.size > 0 && (
        <div className="ao-selbar" role="region" aria-label="Selection actions">
          <span className="ao-selbar-n">{picked.size.toLocaleString()} selected</span>
          <button className="ao-btn ao-btn--primary" onClick={() => setAssigning(true)}>Assign to service</button>
          <button className="ao-btn" onClick={() => setPicked(new Set())}>Clear</button>
        </div>
      )}
      {notice && <div className="ao-selbar-note" role="status">{notice}</div>}
      {classEmpty && (
        <EmptyState title={classEmpty.emptyTitle} hint={classEmpty.emptyHint} />
      )}
      {!classEmpty && <div className="ao-panel">
        {/* range-less honesty: inventory is the current state, not a window */}
        <div className="ao-panel-h">Resources <CurrentNote /></div>
        <DataTable<CloudResource> rows={rows} rowKey={(r) => r.id} height={Math.min(520, 44 + rows.length * 30)} ariaLabel="Cloud resources" onRowClick={setSel}
          columns={[
            { key: "_sel", width: 34,
              header: <input type="checkbox" aria-label="Select all shown resources" checked={allVisibleSelected}
                onChange={() => setPicked((s) => toggleAllVisible(s, visibleIds))} onClick={(e) => e.stopPropagation()} />,
              render: (r) => <input type="checkbox" aria-label={`Select ${r.name}`} checked={picked.has(r.id)}
                onChange={() => setPicked((s) => toggleSelection(s, r.id))} onClick={(e) => e.stopPropagation()} /> },
            { key: "name", header: "Resource", width: 180, sortable: true, text: (r) => r.name, render: (r) => <><strong>{r.name}</strong>{r.consoleUrl && <ConsoleLink compact href={r.consoleUrl} label={`Open in ${consoleName(r.provider)}`} />}</> },
            { key: "type", header: "Type", width: 120, sortValue: (r) => r.type, render: (r) => r.type },
            { key: "power", header: "State", width: 90, sortable: true, sortValue: (r) => r.powerState, render: (r) => r.powerState === "—" ? DASH : (
              <span style={{ color: r.powerState === "running" ? "var(--ok)" : "var(--warn)", fontWeight: 600 }}>
                {r.powerState.charAt(0).toUpperCase() + r.powerState.slice(1)}
              </span>
            ) },
            { key: "provider", header: "Cloud", width: 65, sortValue: (r) => r.provider, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
            { key: "acct", header: "Account", width: 130, sortValue: (r) => r.account, render: (r) => <span className="ao-mono ao-muted">{r.account}</span> },
            { key: "region", header: "Region", width: 100, sortValue: (r) => r.region, render: (r) => r.region },
            { key: "app", header: "Service", width: 150, sortValue: (r) => r.app, render: (r) => <AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /> },
            { key: "owner", header: "Owner", width: 90, sortValue: (r) => r.owner, render: (r) => r.owner },
            { key: "src", header: "Mapped by", width: 120, sortValue: (r) => MAPPED_BY[r.source] ?? r.source, render: (r) => MAPPED_BY[r.source] ?? r.source },
            { key: "conf", header: "Confidence", width: 110, sortable: true, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "health", header: "Health", width: 100, sortValue: (r) => healthRank(r.health), render: (r) => <HealthBadge status={r.health} /> },
            { key: "traffic", header: "Traffic", width: 95, align: "right", sortValue: (r) => r.trafficBps, render: (r) => NM(r.trafficBps, fmtBps) },
            { key: "tags", header: "Missing tags", width: 130, sortValue: (r) => r.missingTags.length, render: (r) => r.missingTags.length ? <Chip label={r.missingTags.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
          ]} />
      </div>}
      {sel && <ResourceDrawer r={sel} onClose={() => setSel(null)} />}
      {assigning && (
        <AssignServiceDrawer
          resourceIds={[...picked]}
          onClose={() => setAssigning(false)}
          onAssigned={(n, label) => {
            setAssigning(false);
            setPicked(new Set());
            setNotice(`Assigned ${n.toLocaleString()} resource${n === 1 ? "" : "s"} to ${label}.`);
            reload();
          }}
        />
      )}
    </div>
  );
}

// Cloud Resource detail drawer — identity, attribution provenance, tags, and the
// honest not-measured signals (health/traffic arrive with cloud telemetry).
// The Metrics tab (Wave 5 #14) charts this resource's provider metric lane.
function ResourceDrawer({ r, onClose }: { r: CloudResource; onClose: () => void }) {
  const tags = r.tags ?? {};
  const tagKeys = Object.keys(tags);
  const [view, setView] = useState<"details" | "metrics">("details");
  return (
    <EvidenceDrawer title={r.name}
      subtitle={<span className="ao-drawer-badges"><AppIdentityPill app={r.app} source={r.source} confidence={r.confidence} /><ConfidenceBadge level={r.confidence} /></span>}
      onClose={onClose}>
      <Segmented value={view} onChange={(v) => setView(v as "details" | "metrics")}
        ariaLabel={`${r.name} drawer view`}
        options={[{ value: "details", label: "Details" }, { value: "metrics", label: "Metrics" }]} />
      {view === "metrics" && (
        <ResourceMetricsPanel targets={[{ id: r.id, name: r.name }]} subject={r.name} />
      )}
      {view === "details" && (<>
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
      </>)}
    </EvidenceDrawer>
  );
}

// ── Attribution (LIVE: /api/cloud/attribution/coverage) ──────────────────────
function Attribution({ ctl }: { ctl: CloudScopeControl }) {
  const { data, status } = useAsync(loadCoverage);
  // resources SERVER-scoped → the by-scope table follows the global filters;
  // the coverage AGGREGATE stays tenant-wide (the endpoint computes it over the
  // whole inventory) and says so when a scope is active — never re-labeled.
  const resq = useAsync(() => loadResources(ctl.scope), [scopeKey(ctl.scope)]);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error") return <LoadError what="attribution coverage" />;
  const c: Coverage = data?.coverage ?? { confirmedTag: 0, strongGraph: 0, firewallAppId: 0, suspectedDomainIp: 0, unknown: 0, total: 0 };
  // untagged rows are resolved inventory facts → the scope applies client-side
  // over this already-loaded top-N list (see scope.ts unknownInScope).
  const unknowns: UnknownContributor[] = (data?.unknowns ?? [])
    .filter((u) => unknownInScope(u, ctl.scope));
  if (c.total === 0) return <CloudEmpty />;
  const pct = (n: number) => Math.round((n / c.total) * 100);
  const resources = resq.data ?? [];
  const tenantWide = ctl.active ? " · tenant-wide (scope applies to the tables below)" : "";
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
        <div className="ao-panel-h">Service-mapping coverage <span className="ao-panel-meta">{c.total} observed · how each was identified{tenantWide}</span></div>
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
        <div className="ao-panel-h">Coverage by scope <span className="ao-panel-meta">attributed resources per provider / region{ctl.active ? " · filtered by the scope bar" : ""}</span></div>
        {byScope.length === 0 ? (
          <EmptyState title={ctl.active ? "No resources in this scope" : "No resources in scope"}
            action={ctl.active ? <button className="ao-btn" onClick={ctl.clearFilters}>Clear filters</button> : undefined} />
        ) : (
          <DataTable rows={byScope} rowKey={(s) => s.scope} height={Math.min(360, 44 + byScope.length * 30)}
            ariaLabel="Coverage by scope" initialSort={{ key: "pct", dir: "asc" }}
            columns={[
              { key: "scope", header: "Provider / Region", width: 220, sortValue: (s) => s.scope, render: (s) => s.scope },
              { key: "attributed", header: "Attributed", width: 110, align: "right", sortValue: (s) => s.attributed, render: (s) => s.attributed },
              { key: "total", header: "Total", width: 90, align: "right", sortValue: (s) => s.total, render: (s) => s.total },
              { key: "pct", header: "Coverage", width: 200, sortValue: (s) => s.pct, render: (s) => <><span className="ao-funnel-bar ao-funnel-bar--inline"><span className="ao-funnel-fill" style={{ width: `${s.pct}%`, background: s.pct >= 80 ? "var(--ok)" : s.pct >= 50 ? "var(--warn)" : "var(--crit)" }} /></span> {s.pct}%</> },
            ]} />
        )}
      </div>

      <div className="ao-panel">
        <div className="ao-panel-h">Untagged resources <span className="ao-panel-meta">tag these to complete your service map · traffic ranking arrives with cloud flow logs</span></div>
        {unknowns.length === 0 ? (
          // scope-filtered-empty ≠ fully-mapped: never claim the win the scope created
          scopedToNothing(ctl.scope, (data?.unknowns ?? []).length, 0) ? (
            <EmptyState title="No untagged resources in this scope"
              hint="untagged resources exist outside the current scope filters"
              action={<button className="ao-btn" onClick={ctl.clearFilters}>Clear filters</button>} />
          ) : (
          <EmptyState title="Every discovered resource is mapped to a service"
            hint="untagged resources appear here with a fix path when discovery finds one" />
          )
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Untagged resources"
            columns={[
              { key: "entity", header: "Resource", width: 220, sortValue: (r) => r.name, render: (r) => <><strong>{r.name}</strong>{r.address && <span className="ao-mono ao-muted"> {r.address}</span>}</> },
              { key: "kind", header: "Type", width: 120, sortValue: (r) => r.kind, render: (r) => r.kind },
              { key: "provider", header: "Cloud", width: 65, sortValue: (r) => r.provider, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
              { key: "region", header: "Region", width: 100, sortValue: (r) => r.region, render: (r) => r.region },
              { key: "bytes", header: "Bytes", width: 90, align: "right", sortValue: (r) => r.bytes, render: (r) => NM(r.bytes, fmtBytes) },
              { key: "flows", header: "Flows", width: 80, align: "right", sortValue: (r) => r.flows, render: (r) => NM(r.flows, (n) => n.toLocaleString()) },
              { key: "missing", header: "Missing", width: 140, sortValue: (r) => r.missingFields.length, render: (r) => r.missingFields.length ? <Chip label={r.missingFields.join(", ")} tone="var(--warn)" /> : <span className="ao-muted">—</span> },
              { key: "rec", header: "Recommendation", width: 260, sortValue: (r) => r.recommendation, render: (r) => r.recommendation },
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

// The health reading for a timeline episode — resource identity + metric live in
// their own columns; this cell is the value vs baseline, rendered HONESTLY: a
// change row has no reading, and a health signal that reported no value shows one
// muted "no reading" rather than the old "— — (baseline —)" wall (audit defect #1c).
function timelineReading(e: TimelineEpisode): React.ReactNode {
  if (e.kind === "change") return DASH;
  // A provider STATE event has no metric by design (it declares a state, it does
  // not measure one). Its reading IS the state + the provider's reasonType — the
  // old "no reading" was true but useless, and hid the one fact the row carried.
  if (e.stateEvent) {
    return (
      <span className="ao-state-read">
        <strong>{stateLabel(e.state)}</strong>
        {e.reason
          ? <span className="ao-muted"> · {e.reason}</span>
          : <span className="ao-muted" title="the provider declared this state without a reason"> · no reason stated</span>}
      </span>
    );
  }
  if (!e.current && !e.baseline) {
    return <span className="ao-muted" title="the provider health signal carried no metric value">no reading</span>;
  }
  return <><strong>{e.current || "—"}</strong>{e.baseline && <span className="ao-muted"> vs {e.baseline} baseline</span>}</>;
}


// merged change + health timeline, newest first — the NOC "what happened, when".
// Consecutive identical events collapse into one EPISODE with a ×N count + a
// first→last span, and every column is click-to-sort (audit defects #1 + #2).
function HCTimeline({ health, changes, minutes, staleHint }: {
  health: HealthSignal[]; changes: ChangeEvent[]; minutes: number; staleHint: string;
}) {
  const episodes = buildTimeline(health, changes);
  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Event timeline <span className="ao-panel-meta">change + health · repeats collapsed into episodes · newest first · {rangeWords(minutes)}</span></div>
      {episodes.length === 0 ? <EmptyState title={`No cloud events in the ${rangeWords(minutes)}`} hint={staleHint} /> : (
        <DataTable<TimelineEpisode> rows={episodes} rowKey={(e) => `${e.key}|${e.firstSeen}|${e.lastSeen}`}
          height={Math.min(480, 56 + episodes.length * 30)} ariaLabel="Event timeline"
          initialSort={{ key: "when", dir: "desc" }}
          columns={[
            { key: "when", header: "Last seen", width: 150, sortValue: (e) => timeRank(e.lastSeen),
              render: (e) => <span className="ao-tl-when"><span className="ao-tl-t">{ago(e.lastSeen)}</span>{e.count > 1 && <span className="ao-muted ao-tl-span"> · first {ago(e.firstSeen)}</span>}</span> },
            { key: "count", header: "Count", width: 74, align: "right", sortValue: (e) => e.count,
              render: (e) => e.count > 1
                ? <span className="ao-count" title={`${e.count} occurrences · ${ago(e.firstSeen)} → ${ago(e.lastSeen)}`}>×{e.count}</span>
                : <span className="ao-muted">1</span> },
            { key: "kind", header: "Kind", width: 96, sortValue: (e) => e.kind, render: (e) => <Chip label={e.kind} tone={e.tone} /> },
            { key: "app", header: "Service", width: 150, sortValue: (e) => e.app, render: (e) => <strong>{e.app}</strong> },
            { key: "res", header: "Resource", width: 180, sortValue: (e) => e.resource, render: (e) => e.resource === "—" ? DASH : <span className="ao-mono">{e.resource}</span> },
            { key: "what", header: "Event", width: 220, sortValue: (e) => e.detail,
              render: (e) => <span className="ao-why" title={e.metric ? `${e.detail} · ${e.metric}` : e.detail}>{e.detail}{(e.metric || e.actor) && <span className="ao-mono ao-muted"> · {e.metric || e.actor}</span>}</span> },
            { key: "val", header: "Reading", width: 170, sortValue: (e) => e.current || e.actor || "", render: (e) => timelineReading(e) },
            { key: "sev", header: "Severity", width: 100, sortValue: (e) => e.severity ? severityRank(e.severity) : 99,
              render: (e) => e.severity ? <Chip label={e.severity} tone={e.tone} /> : DASH },
          ]} />
      )}
    </div>
  );
}

// The cloud signal feed with an explicit freshness stamp + an operator refresh.
// `loadedAt` is what makes the "live · updated Ns ago" cue truthful: it is set
// only on a SUCCESSFUL fetch, so a failing refresh can never age-reset the label
// and make stale data look fresh. `windowHours` is the REAL server read window
// (Wave 2 #5): changing it refetches — never a re-labeled stale set.
// Wave 3 #10: `q` narrows the SERVER read (?q=), and each surface pages by its
// keyset cursor — "Load more" APPENDS the next page; changing window/search
// resets to page one.
function useCloudFeed(windowHours: number, q: string) {
  const [data, setData] = useState<{ health: HealthSignal[]; changes: ChangeEvent[] } | null>(null);
  const [cursors, setCursors] = useState({ health: "", changes: "" });
  const [status, setStatus] = useState<LoadState>("loading");
  const [loadedAt, setLoadedAt] = useState<number>(() => Date.now());
  const [busy, setBusy] = useState(false);
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    let live = true;
    if (nonce > 0) setBusy(true);
    Promise.all([
      loadHealthPage(undefined, windowHours, q, ""),
      loadChangesPage(undefined, windowHours, q, ""),
    ]).then(
      ([h, c]) => {
        if (!live) return;
        setData({ health: h.rows, changes: c.rows });
        setCursors({ health: h.nextCursor, changes: c.nextCursor });
        setStatus("ready"); setLoadedAt(Date.now()); setBusy(false);
      },
      () => { if (!live) return; setStatus("error"); setBusy(false); },
    );
    return () => { live = false; };
  }, [nonce, windowHours, q]);
  const loadMore = async () => {
    setBusy(true);
    try {
      const [h, c] = await Promise.all([
        cursors.health ? loadHealthPage(undefined, windowHours, q, cursors.health) : Promise.resolve(null),
        cursors.changes ? loadChangesPage(undefined, windowHours, q, cursors.changes) : Promise.resolve(null),
      ]);
      setData((d) => d && {
        health: h ? [...d.health, ...h.rows] : d.health,
        changes: c ? [...d.changes, ...c.rows] : d.changes,
      });
      setCursors((cur) => ({
        health: h ? h.nextCursor : cur.health,
        changes: c ? c.nextCursor : cur.changes,
      }));
      setLoadedAt(Date.now());
    } catch {
      // the loaded pages stay; the operator can retry — never silently reset
    } finally {
      setBusy(false);
    }
  };
  return {
    data, status, loadedAt, busy, loadMore,
    hasMore: !!(cursors.health || cursors.changes),
    refresh: () => setNonce((n) => n + 1),
  };
}

// ── Wave 3 #10 toolbar: server-side search · export · saved views ────────────

// The `sq` search term, URL-backed like every other filter on this page: a
// pasted link reproduces the same narrowed table, and hashchange (scope bar,
// saved views) is the single source of truth.
function useSignalSearch(): [string, (t: string) => void] {
  const [sq, setSqState] = useState(() => sqFromHash(window.location.hash));
  useEffect(() => {
    const on = () => setSqState(sqFromHash(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [sq, (t: string) => { window.location.hash = hashWithSq(window.location.hash, t); }];
}

// Debounced search input: local echo types instantly, the URL (and so the
// server read) commits 400ms after the operator stops typing.
function SignalSearchInput({ value, onCommit }: { value: string; onCommit: (t: string) => void }) {
  const [text, setText] = useState(value);
  useEffect(() => { setText(value); }, [value]);
  useEffect(() => {
    if (text === value) return;
    const t = setTimeout(() => onCommit(text.trim()), 400);
    return () => clearTimeout(t);
  }, [text, value, onCommit]);
  return (
    <input className="ao-search" type="search" value={text} placeholder="Search signals (server-side)…"
      aria-label="Search signals" onChange={(e) => setText(e.target.value)} />
  );
}

// Named saved views: the current hash query (scope + range + search + drawer)
// under a name, per tenant scope (signalPage.ts). Applying one restores the
// exact URL state; every consumer re-reads via hashchange.
function SavedViewsControl() {
  const scope = getActiveScope();
  const [views, setViews] = useState(() => listViews(localStorage, scope));
  const [sel, setSel] = useState("");
  const apply = (name: string) => {
    setSel(name);
    const v = listViews(localStorage, scope).find((x) => x.name === name);
    if (!v) return;
    const path = window.location.hash.split("?")[0];
    window.location.hash = v.query ? `${path}?${v.query}` : path;
  };
  const save = () => {
    const name = window.prompt("Save the current filters + search as a view named:");
    if (!name) return;
    setViews(saveView(localStorage, scope, name, window.location.hash.split("?")[1] ?? ""));
    setSel(name.trim().slice(0, 60));
  };
  const remove = () => {
    if (!sel) return;
    setViews(deleteView(localStorage, scope, sel));
    setSel("");
  };
  return (
    <span className="ao-savedviews">
      <select className="ao-select" aria-label="Saved views" value={sel} onChange={(e) => apply(e.target.value)}>
        <option value="">Saved views…</option>
        {views.map((v) => <option key={v.name} value={v.name}>{v.name}</option>)}
      </select>
      <button className="ao-btn" onClick={save} title="Save the current filters + search as a named view">Save view</button>
      {sel && <button className="ao-btn" onClick={remove} title={`Delete the saved view "${sel}"`}>Delete</button>}
    </span>
  );
}

// Export buttons: the download is the SAME tenant-scoped, filtered server read
// as the table (?format= on the signal surface), capped server-side at 5000
// rows — never a client-side dump of whatever happened to be loaded.
function ExportButtons({ surfaces, windowHours, q }: {
  surfaces: ("health" | "changes" | "evidence")[]; windowHours: number; q: string;
}) {
  const [err, setErr] = useState("");
  const run = (surface: "health" | "changes" | "evidence", format: "csv" | "json") =>
    downloadCloudExport(surface, format, undefined, windowHours, q)
      .then(() => setErr(""), (e: unknown) => setErr(e instanceof Error ? e.message : "export failed"));
  return (
    <span className="ao-export">
      {surfaces.map((s) => (
        <span key={s} className="ao-export-g">
          <button className="ao-btn" onClick={() => run(s, "csv")} title={`Download the ${s} table (current search + window, server-side, up to 5000 rows) as CSV`}>
            {surfaces.length > 1 ? `${s} CSV` : "Export CSV"}
          </button>
          <button className="ao-btn" onClick={() => run(s, "json")} title={`Download the ${s} table (current search + window, server-side, up to 5000 rows) as JSON`}>
            {surfaces.length > 1 ? `${s} JSON` : "JSON"}
          </button>
        </span>
      ))}
      {err && <span className="ao-muted" role="alert">{err}</span>}
    </span>
  );
}

function SignalToolbar({ surfaces, windowHours, sq, setSq }: {
  surfaces: ("health" | "changes" | "evidence")[]; windowHours: number;
  sq: string; setSq: (t: string) => void;
}) {
  return (
    <div className="ao-signal-toolbar" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <SignalSearchInput value={sq} onCommit={setSq} />
      <ExportButtons surfaces={surfaces} windowHours={windowHours} q={sq} />
      <SavedViewsControl />
    </div>
  );
}

function HealthChanges({ view, ctl }: { view: "timeline" | "alerts" | "changes"; ctl: CloudScopeControl }) {
  // The GLOBAL range (URL-backed, Wave 2 #5): sub-24h ranges narrow client-side
  // inside the fetched window; >24h changes the server read (windowHoursFor).
  const minutes = ctl.scope.rangeMinutes;
  // Wave 3 #10: URL-backed server-side search narrows the read for all views.
  const [sq, setSq] = useSignalSearch();
  const feed = useCloudFeed(windowHoursFor(minutes), sq);
  // The unfiltered inventory backs the signal→scope join (account/region/env
  // live on the resource, not the signal). Shared 30s-TTL read — no new fetch
  // beyond what the shell already did.
  const invq = useAsync(() => loadResources(), []);
  const scopeIdx: ScopeIndex = buildScopeIndex(invq.data ?? []);
  // Row drill-in (audit defect #4): open the full record for an alert / change.
  const [alertSel, setAlertSel] = useState<HealthSignal | null>(null);
  const [changeSel, setChangeSel] = useState<ChangeEvent | null>(null);
  if (feed.status === "loading") return <TableSkeleton />;
  if (feed.status === "error" || !feed.data) return <LoadError what="cloud health & change signals" />;
  const allHealth = feed.data.health;
  const allChanges = feed.data.changes;
  // range first, then the global scope (client-side over the LIMIT-bounded,
  // already-loaded window — the signal store has no scope columns; scope.ts).
  const health = filterByRange(allHealth, minutes)
    .filter((h) => signalInScope(healthScopeKey(h), ctl.scope, scopeIdx));
  const changes = filterByRange(allChanges, minutes)
    .filter((c) => signalInScope(changeScopeKey(c), ctl.scope, scopeIdx));

  // Counts are per view, so the bar always describes the table under it.
  const count = view === "alerts" ? feedCount(health.length, allHealth.length, minutes)
    : view === "changes" ? feedCount(changes.length, allChanges.length, minutes)
      : feedCount(health.length + changes.length, allHealth.length + allChanges.length, minutes);

  // An empty window is not necessarily an empty feed: when signals exist but all
  // fall OUTSIDE the selected range (or scope), say so — and say WHICH filter is
  // hiding them. "nothing here", "nothing recent" and "nothing in scope" are
  // three different answers (owner review #2 + Wave 2 #5).
  const newest = newestIso([...allHealth, ...allChanges]);
  const emptyHint = (kind: string) => {
    const all = view === "alerts" ? allHealth.length : view === "changes" ? allChanges.length : allHealth.length + allChanges.length;
    if (all > 0 && ctl.active) {
      return `Nothing matches the current scope filters in the ${rangeWords(minutes)} — clear or adjust the scope above.`;
    }
    if (all > 0 && newest) {
      return `Nothing in the ${rangeWords(minutes)} — the most recent ${kind} landed ${ago(newest)}. Widen the range to see it.`;
    }
    return `${kind} appear here as the connected cloud accounts report them`;
  };

  const sevTone = (s: string) => s === "critical" ? "var(--crit)" : s === "warning" ? "var(--warn)" : "var(--fg-subtle)";
  return (
    <div className="ao-stack">
      <SourceFreshnessStrip />
      {/* onRange writes the GLOBAL range (URL) — the scope-bar Range select and
          this control are the same state, so they can never disagree. */}
      <FeedBar minutes={minutes} onRange={ctl.setRangeMinutes} count={count}
        loadedAt={feed.loadedAt} onRefresh={feed.refresh} busy={feed.busy}
        label={`${view === "alerts" ? "Alerts" : view === "changes" ? "Changes" : "Timeline"} time range`} />
      <SignalToolbar windowHours={windowHoursFor(minutes)} sq={sq} setSq={setSq}
        surfaces={view === "alerts" ? ["health"] : view === "changes" ? ["changes"] : ["health", "changes"]} />
      {view === "timeline" && <HCTimeline health={health} changes={changes} minutes={minutes} staleHint={emptyHint("cloud events")} />}
      {view === "alerts" && (
        <div className="ao-panel">
          {health.length === 0 ? (
            <EmptyState title={`No cloud alerts in the ${rangeWords(minutes)}`}
              hint={emptyHint("provider health reports")} />
          ) : (
          <DataTable<HealthSignal> rows={health} rowKey={(r) => r.time + r.signal + r.app + r.metric} height={Math.min(480, 44 + health.length * 30)} ariaLabel="Health signals" onRowClick={setAlertSel}
            columns={[
              { key: "time", header: "Time", width: 84, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
              { key: "app", header: "Service", width: 130, sortValue: (r) => r.app, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 160, sortValue: (r) => r.resource, render: (r) => r.resource },
              { key: "sig", header: "Signal", width: 150, sortValue: (r) => r.signal, render: (r) => r.signal },
              { key: "state", header: "State", width: 96, sortValue: (r) => healthRank(r.state), render: (r) => <HealthBadge status={r.state} /> },
              // metric/current/baseline are the METRIC-ANOMALY story; a provider
              // state event answers each of them differently rather than blank.
              { key: "metric", header: "Metric", width: 170, sortValue: (r) => r.metric, render: healthMetricCell },
              { key: "cur", header: "Current", width: 84, sortValue: (r) => r.current, render: healthCurrentCell },
              { key: "base", header: "Baseline", width: 76, sortValue: (r) => r.baseline, render: healthBaselineCell },
              // The provider's declared cause — a state event's real substance.
              { key: "reason", header: "Reason", width: 150, sortValue: (r) => stateReason(r), render: healthReasonCell },
              { key: "sev", header: "Severity", width: 86, sortValue: (r) => severityRank(r.severity), render: (r) => <Chip label={r.severity} tone={sevTone(r.severity)} /> },
              { key: "src", header: "Cloud", width: 90, sortValue: (r) => r.source, render: (r) => r.source.toUpperCase() },
            ]} />
          )}
        </div>
      )}
      {view === "changes" && (
        <div className="ao-panel">
          {changes.length === 0 ? (
            <EmptyState title={`No cloud change events in the ${rangeWords(minutes)}`}
              hint={emptyHint("management-plane changes (CloudTrail / Activity Log)")} />
          ) : (
          <DataTable<ChangeEvent> rows={changes} rowKey={(r) => r.time + r.changeType + r.resource + r.actor} height={Math.min(480, 44 + changes.length * 30)} ariaLabel="Change events" onRowClick={setChangeSel}
            columns={[
              { key: "time", header: "Time", width: 90, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
              { key: "app", header: "Service", width: 130, sortValue: (r) => r.app, render: (r) => <strong>{r.app}</strong> },
              { key: "res", header: "Resource", width: 190, sortValue: (r) => r.resource, render: (r) => <><span className="ao-mono">{r.resource}</span>{r.cloudRef?.consoleUrl && <ConsoleLink compact href={r.cloudRef.consoleUrl} label={`Open in ${consoleName(r.cloudRef.provider)}`} />}</> },
              { key: "type", header: "Change type", width: 170, sortable: true, sortValue: (r) => r.changeType, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
              { key: "actor", header: "Actor", width: 190, sortValue: (r) => r.actor, render: (r) => <span className="ao-mono">{r.actor}</span> },
              { key: "src", header: "Source", width: 160, sortValue: (r) => r.source, render: (r) => <>{r.source}{r.cloudRef?.logUrl && <ConsoleLink compact href={r.cloudRef.logUrl} label={r.cloudRef.provider === "aws" ? "View CloudTrail event" : "View Activity Log"} />}</> },
              { key: "conf", header: "Confidence", width: 110, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <ConfidenceBadge level={r.confidence} /> },
              { key: "sym", header: "Related symptoms", width: 180, sortValue: (r) => r.relatedSymptoms.length, render: (r) => r.relatedSymptoms.length ? r.relatedSymptoms.join(", ") : DASH },
            ]} />
          )}
        </div>
      )}
      {/* Keyset pagination (#10): the server said there are more rows in the
          window than the loaded pages — APPEND the next page, never re-read. */}
      {feed.hasMore && (
        <div className="ao-panel-meta" style={{ textAlign: "center" }}>
          <button className="ao-btn" onClick={feed.loadMore} disabled={feed.busy}>
            {feed.busy ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
      {alertSel && <HealthSignalDrawer s={alertSel} onClose={() => setAlertSel(null)} sevTone={sevTone} />}
      {changeSel && <ChangeDrawer c={changeSel} onClose={() => setChangeSel(null)} />}
    </div>
  );
}

// Alert (health-signal) detail — the full record behind a timeline/alerts row:
// exact time, resource identity, metric, the reading vs baseline (honest when the
// provider reported none), severity and the reporting cloud source.
function HealthSignalDrawer({ s, onClose, sevTone }: { s: HealthSignal; onClose: () => void; sevTone: (s: string) => string }) {
  return (
    <EvidenceDrawer title={`${s.signal} · ${s.app}`}
      subtitle={<span className="ao-drawer-badges"><HealthBadge status={s.state} /><Chip label={s.severity} tone={sevTone(s.severity)} /></span>}
      onClose={onClose}>
      <table className="ao-kv"><tbody>
        <tr><td>Time</td><td>{fmtDateTime(s.time)}</td></tr>
        <tr><td>Service</td><td><strong>{s.app}</strong></td></tr>
        <tr><td>Resource</td><td>{cleanVal(s.resource) ? <span className="ao-mono">{s.resource}</span> : DASH}</td></tr>
        <tr><td>Signal</td><td>{s.signal}</td></tr>
        <tr><td>State</td><td><HealthBadge status={s.state} /></td></tr>
        {/* A provider STATE event declares a state and its cause; it measures
            nothing. Show the cause, and say plainly that there is no metric —
            rather than three empty rows the operator has to interpret. */}
        {isStateEvent(s) ? (<>
          <tr><td>Kind</td><td>Provider health-state declaration <span className="ao-muted">— reports a state, not a measurement</span></td></tr>
          <tr><td>Reason</td><td>{stateReason(s)
            ? <strong>{stateReason(s)}</strong>
            : <span className="ao-muted">the provider declared this state without a reason</span>}</td></tr>
          <tr><td>Reading</td><td><span className="ao-muted">not applicable — a declared state carries no metric or baseline</span></td></tr>
        </>) : (<>
          <tr><td>Metric</td><td>{cleanVal(s.metric) ? <span className="ao-mono">{s.metric}</span> : DASH}</td></tr>
          <tr><td>Reading</td><td>{cleanVal(s.current)
            ? <><strong>{s.current}</strong>{cleanVal(s.baseline) && <span className="ao-muted"> vs {s.baseline} baseline</span>}</>
            : <span className="ao-muted">no reading reported by the provider signal</span>}</td></tr>
        </>)}
        <tr><td>Severity</td><td>{s.severity}</td></tr>
        <tr><td>Cloud source</td><td>{s.source.toUpperCase()}</td></tr>
      </tbody></table>
    </EvidenceDrawer>
  );
}

// Change detail — the full management-plane record behind a change row, with the
// console + provider-log pivots (CloudTrail event / Activity Log) when resolvable.
function ChangeDrawer({ c, onClose }: { c: ChangeEvent; onClose: () => void }) {
  return (
    <EvidenceDrawer title={`${c.changeType.replace(/_/g, " ")} · ${c.app}`}
      subtitle={<span className="ao-drawer-badges"><Chip label={c.changeType.replace(/_/g, " ")} tone="var(--warn)" /><ConfidenceBadge level={c.confidence} /></span>}
      onClose={onClose}>
      <table className="ao-kv"><tbody>
        <tr><td>Time</td><td>{fmtDateTime(c.time)}</td></tr>
        <tr><td>Service</td><td><strong>{c.app}</strong></td></tr>
        <tr><td>Resource</td><td><span className="ao-mono">{c.resource}</span>{c.cloudRef?.consoleUrl && <> · <ConsoleLink href={c.cloudRef.consoleUrl} label={`Open in ${consoleName(c.cloudRef.provider)}`} /></>}</td></tr>
        <tr><td>Change type</td><td>{c.changeType.replace(/_/g, " ")}</td></tr>
        <tr><td>Actor</td><td><span className="ao-mono">{c.actor}</span></td></tr>
        <tr><td>Source</td><td>{c.source}{c.cloudRef?.logUrl && <> · <ConsoleLink href={c.cloudRef.logUrl} label={c.cloudRef.provider === "aws" ? "View CloudTrail event" : "View Activity Log"} /></>}</td></tr>
        <tr><td>Confidence</td><td><ConfidenceBadge level={c.confidence} /></td></tr>
        <tr><td>Related symptoms</td><td>{c.relatedSymptoms.length ? c.relatedSymptoms.join(", ") : "—"}</td></tr>
      </tbody></table>
    </EvidenceDrawer>
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
// In-page navigation (owner review #3/#4: every one of these used to resolve to
// the ITSM Integrations page regardless of what its label promised). Each helper
// is named for the destination it actually opens; the deep-link suffixes are the
// TAB / TAB_ALIAS keys this page already routes on.
//
// Cloud accounts live in Data sources → Accounts (the connector wizard) — NOT in
// Admin → Integrations, which is the ServiceNow / Jira ticketing gallery.
function openCloudAccounts() { location.hash = "#/monitoring/appobs/accounts"; }
// Attribution rules + precedence are Service View settings, not an ITSM concern.
function openAttributionSettings() { location.hash = "#/monitoring/appobs/settings"; }

function Unknowns({ ctl }: { ctl: CloudScopeControl }) {
  const [fix, setFix] = useState<UnknownContributor | null>(null);
  // In-product remediation (2026-07 review imp #5): assign an untagged resource
  // to a business service instead of dead-ending at "go tag it in the console".
  const [assignRes, setAssignRes] = useState<UnknownContributor | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  // resources SERVER-scoped (Wave-1 SQL filters); the coverage top-N narrows
  // client-side over its already-loaded list (scope.ts unknownInScope).
  const res = useAsync(() => loadResources(ctl.scope), [reloadKey, scopeKey(ctl.scope)]);
  const cov = useAsync(loadCoverage, [reloadKey]);
  const reload = () => { invalidateCloudInventory(); setReloadKey((k) => k + 1); };
  if (res.status === "loading" || cov.status === "loading") return <TableSkeleton />;
  if (res.status === "error" || cov.status === "error") return <LoadError what="unknowns" />;
  const resources = res.data ?? [];
  const allUnknowns = cov.data?.unknowns ?? [];
  const unknowns = allUnknowns.filter((u) => unknownInScope(u, ctl.scope));
  if (resources.length === 0) {
    return ctl.active ? <ScopeEmpty what="resources" ctl={ctl} /> : <CloudEmpty />;
  }
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
          // scope-filtered-empty ≠ fully-mapped (same honesty rule as Attribution)
          scopedToNothing(ctl.scope, allUnknowns.length, 0) ? (
            <EmptyState title="No untagged resources in this scope"
              hint="untagged resources exist outside the current scope filters"
              action={<button className="ao-btn" onClick={ctl.clearFilters}>Clear filters</button>} />
          ) : (
          <EmptyState title="Every discovered resource is mapped to a service"
            hint="untagged resources appear here with a fix path when discovery finds one" />
          )
        ) : (
          <DataTable<UnknownContributor> rows={unknowns} rowKey={(r) => r.entity} height={Math.min(420, 44 + unknowns.length * 34)} ariaLabel="Untagged resources" onRowClick={setFix}
            columns={[
              { key: "entity", header: "Resource", width: 210, sortValue: (r) => r.name, render: (r) => <><strong>{r.name}</strong>{r.address && <span className="ao-mono ao-muted"> {r.address}</span>}</> },
              { key: "kind", header: "Type", width: 116, sortValue: (r) => r.kind, render: (r) => r.kind },
              { key: "provider", header: "Cloud", width: 60, sortValue: (r) => r.provider, render: (r) => r.provider === "—" ? "—" : r.provider.toUpperCase() },
              { key: "region", header: "Region", width: 96, sortValue: (r) => r.region, render: (r) => r.region },
              { key: "bytes", header: "Traffic", width: 86, align: "right", sortValue: (r) => r.bytes, render: (r) => NM(r.bytes, fmtBytes) },
              { key: "why", header: "Why untagged", width: 170, sortValue: (r) => r.missingFields.length, render: (r) => r.missingFields.length ? <Chip label={`missing ${r.missingFields.join("/")}`} tone="var(--fg-subtle)" /> : <span className="ao-muted">—</span> },
              { key: "fix", header: "Recommended fix", width: 240, sortValue: (r) => r.recommendation, render: (r) => r.recommendation },
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
              happens in the provider console; attribution precedence lives in
              this page's own Settings. Everything else is guidance, not a fake
              button. (owner review #3/#4: the last button said "Attribution
              rules" and opened the ServiceNow/Jira gallery.) */}
          <div className="ao-cta-btns">
            <button className="ao-btn ao-btn--primary" onClick={() => { setAssignRes(fix); setFix(null); }}>Assign to a service</button>
            {(() => {
              const url = consoleUrlFor(fix, resources);
              return url ? <ConsoleLink href={url} label={`Tag in ${consoleName(fix.provider)}`} /> : null;
            })()}
            <button className="ao-btn" onClick={openAttributionSettings}>View attribution rules</button>
          </div>
        </EvidenceDrawer>
      )}

      {assignRes && (
        <AssignServiceDrawer
          resourceIds={[assignRes.resourceId]}
          onClose={() => setAssignRes(null)}
          onAssigned={() => { setAssignRes(null); reload(); }}
        />
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
function Evidence({ openInvestigation, ctl }: {
  openInvestigation: (id: string) => void; ctl: CloudScopeControl;
}) {
  const [f, setF] = useState<Record<string, string>>({});
  const [sel, setSel] = useState<EvidenceRow | null>(null);
  // REAL range window (Wave 2 #5): the ledger read carries ?window_hours=.
  const minutes = ctl.scope.rangeMinutes;
  const wh = windowHoursFor(minutes);
  // Wave 3 #10: URL-backed server-side search + keyset "Load more". Follow-on
  // pages APPEND under the first (gap rows ride the first page only, server-
  // side); changing window/search resets the accumulation.
  const [sq, setSq] = useSignalSearch();
  const { data, status } = useAsync(() => loadEvidence(undefined, wh, sq), [wh, sq]);
  const [more, setMore] = useState<{ rows: EvidenceRow[]; cursor: string } | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  useEffect(() => { setMore(null); }, [wh, sq]);
  // unfiltered inventory backs the finding→scope join (see scope.ts header).
  const invq = useAsync(() => loadResources(), []);
  if (status === "loading") return <TableSkeleton />;
  if (status === "error" || !data) return <LoadError what="the evidence ledger" />;
  const all = [...data.rows, ...(more?.rows ?? [])];
  const nextCursor = more ? more.cursor : data.nextCursor;
  const loadMore = async () => {
    setMoreBusy(true);
    try {
      const b = await loadEvidence(undefined, wh, sq, nextCursor);
      setMore((m) => ({ rows: [...(m?.rows ?? []), ...b.rows], cursor: b.nextCursor }));
    } catch {
      // loaded pages stay; the operator can retry
    } finally {
      setMoreBusy(false);
    }
  };
  if (all.length === 0) {
    return (
      <div className="ao-stack">
        <SignalToolbar surfaces={["evidence"]} windowHours={wh} sq={sq} setSq={setSq} />
        <div className="ao-panel">
          <EmptyState title={sq ? `No findings match “${sq}” in the ${rangeWords(wh * 60)}` : `No findings in the ${rangeWords(wh * 60)}`}
            hint={sq
              ? "the search runs server-side over the full window — clear it to see every finding"
              : "findings appear when the engine grounds a cloud signal into an investigation — check Data sources if no cloud signals are landing at all"} />
        </div>
      </div>
    );
  }
  const scopeIdx = buildScopeIndex(invq.data ?? []);
  // global scope + range first (client-side: the page is LIMIT-bounded and
  // already loaded), then the tab's own FilterBar refines within it.
  const inScope = all
    .filter((e) => withinRange(e.time, minutes))
    .filter((e) => signalInScope(evidenceScopeKey(e), ctl.scope, scopeIdx));
  if (inScope.length === 0) {
    return (
      <div className="ao-panel">
        <EmptyState title={ctl.active ? "No findings in this scope" : `No findings in the ${rangeWords(minutes)}`}
          hint={ctl.active
            ? "findings exist outside the current scope/range — clear or adjust the filters above"
            : `the most recent finding is older than the selected range — widen it to see more`}
          action={ctl.active ? <button className="ao-btn" onClick={ctl.clearFilters}>Clear filters</button> : undefined} />
      </div>
    );
  }
  const rows = inScope.filter((e) =>
    (!f.signal || e.signalType === f.signal) &&
    (!f.confidence || e.confidence === f.confidence) &&
    (!f.category || e.category === f.category) &&
    (!f.grounded || (f.grounded === "yes") === e.grounded) &&
    (!f.app || e.app === f.app));
  return (
    <div className="ao-stack">
      <SignalToolbar surfaces={["evidence"]} windowHours={wh} sq={sq} setSq={setSq} />
      <FilterBar value={f} onChange={(k, v) => setF((p) => ({ ...p, [k]: v }))}
        filters={[
          { key: "app", label: "Service", options: [...new Set(inScope.map((e) => e.app))].map((a) => ({ value: a, label: a })) },
          { key: "category", label: "Category", options: [...new Set(inScope.map((e) => e.category))].map((c) => ({ value: c, label: c })) },
          { key: "signal", label: "Signal type", options: [...new Set(inScope.map((e) => e.signalType))].map((s) => ({ value: s, label: s })) },
          { key: "confidence", label: "Confidence", options: [...new Set(inScope.map((e) => e.confidence))].map((c) => ({ value: c, label: c })) },
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
            { key: "time", header: "Time", width: 84, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
            { key: "cat", header: "Category", width: 130, sortable: true, sortValue: (r) => r.category, render: (r) => <EvidenceCategoryBadge category={r.category} /> },
            { key: "sig", header: "Signal type", width: 140, sortValue: (r) => r.signalType, render: (r) => r.signalType },
            { key: "app", header: "Service", width: 110, sortValue: (r) => r.app, render: (r) => <strong>{r.app}</strong> },
            { key: "res", header: "Resource", width: 130, sortValue: (r) => r.resource, render: (r) => <>{r.resource}{r.cloudRef?.consoleUrl && <ConsoleLink compact href={r.cloudRef.consoleUrl} label={`Open in ${consoleName(r.cloudRef.provider)}`} />}</> },
            { key: "src", header: "Source", width: 130, sortValue: (r) => String(r.source), render: (r) => r.source },
            { key: "conf", header: "Confidence", width: 104, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <ConfidenceBadge level={r.confidence} /> },
            { key: "reason", header: "Reason", width: 320, sortValue: (r) => r.reason, render: (r) => <span className="ao-why" title={r.reason}>{r.reason}</span> },
            { key: "grounded", header: "Grounded", width: 90, sortValue: (r) => (r.grounded ? 0 : 1), render: (r) => r.grounded ? <Chip label="yes" tone="var(--accent)" /> : <span className="ao-muted">gap</span> },
            { key: "rca", header: "Investigation", width: 130, sortValue: (r) => (r.rcaGroup ? 0 : 1), render: (r) => r.rcaGroup ? (
              <button className="ao-rowaction" title={r.rcaGroup}
                onClick={(e) => { e.stopPropagation(); openInvestigation(r.rcaGroup); }}>Open</button>
            ) : DASH },
          ]} />
        {nextCursor && (
          <div className="ao-panel-meta" style={{ textAlign: "center", marginTop: 6 }}>
            <button className="ao-btn" onClick={loadMore} disabled={moreBusy}>
              {moreBusy ? "Loading…" : "Load more"}
            </button>
          </div>
        )}
      </div>
      {sel && (
        <EvidenceDrawer title={`${sel.signalType} · ${sel.app}`} subtitle={<span className="ao-drawer-badges"><EvidenceCategoryBadge category={sel.category} /><ConfidenceBadge level={sel.confidence} /></span>} onClose={() => setSel(null)}>
          <table className="ao-kv"><tbody>
            <tr><td>Time</td><td>{fmtDateTime(sel.time)}</td></tr>
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
// Advanced configuration — REAL per-tenant editors (Wave 4 #11).
//
// History: owner review #3/#4 found every card here rendered one button that
// opened the ITSM ticketing gallery, and four cards promised editors that did
// not exist (the backlog's "fake CTAs"). Those placeholders are now the real
// thing — each editor below persists an audited, admin-gated tenant setting
// that its surface actually reads:
//   · Cloud Connectors → Data sources → Accounts (live connector wizard).
//   · Attribution Precedence → /api/settings/attribution-precedence, consumed
//     by the appid resolver (/api/appid/resolve fusion order).
//   · Required Tags → /api/settings/required-tags, drives missing-tags +
//     the coverage compliance report.
//   · RCA Window → /api/settings/rca-window, the default read window for the
//     cloud signal surfaces.
// Catalog Sources stays a value row: it states what the platform ships, and
// feed refresh is an out-of-band operator job — no button pretends otherwise.
function Settings() {
  const sections: { t: string; d: string; value: string; cta?: string; onClick?: () => void }[] = [
    { t: "Catalog Sources", d: "Managed vendor IP/domain feeds used for catalog-based attribution.", value: "AWS · Azure · GCP · Microsoft 365 (refreshed every 6h)" },
    {
      t: "Cloud Connectors",
      d: "Connect an AWS, Azure or GCP account with least-privilege access. Setup runs in Data sources → Accounts.",
      value: "Connect AWS / Azure / GCP accounts (least-privilege IAM)",
      cta: "Connect a cloud account",
      onClick: openCloudAccounts,
    },
  ];
  return (
    <div className="ao-settings">
      {sections.map((s) => (
        <div key={s.t} className="ao-panel">
          <div className="ao-panel-h">{s.t}</div>
          <p className="ao-set-d">{s.d}</p>
          <div className="ao-set-v">{s.value}</div>
          {s.cta && s.onClick && (
            <button className="ao-btn ao-btn--primary" onClick={s.onClick}>{s.cta}</button>
          )}
        </div>
      ))}
      {/* Wave 4 #11: REAL per-tenant editors (persisted, audited, admin-gated). */}
      <AttributionPrecedenceCard />
      <RequiredTagsCard />
      <RcaWindowCard />
      <SeamOwnersCard />
      {/* Wave 5 #14: per-tenant cloud monitor authoring (threshold/anomaly). */}
      <MonitorsSettings />
      {/* Read-only change log: every save above is audited and listed here. */}
      <GovernanceAuditCard />
    </div>
  );
}
