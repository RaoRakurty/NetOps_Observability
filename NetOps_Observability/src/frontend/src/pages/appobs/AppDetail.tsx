// App Observability — App Detail drill-in (#81 P3F/P3H).
// The six-part story for one app: Identity → Health → Change → Traffic → Dependencies
// → Underlay → Evidence, with an RCA summary that always shows confidence + evidence.
//
// Every panel is LIVE and tenant-scoped: resources from the cloud inventory, health /
// change / evidence from the signals this app's connected cloud account actually
// emitted (/api/cloud/health|changes|evidence). Nothing is sample data; a panel with
// no ingested signal shows its empty state instead.

import { useState, useEffect, ReactNode } from "react";
import { Segmented } from "../../components/ui";
import { Chip } from "../../components/noc";
import DataTable from "../../components/DataTable";
import type {
  App, ChangeEvent, CloudResource, EvidenceRow, EvidenceCategory, HealthSignal, AppRca,
} from "./types";
import {
  HealthBadge, ConfidenceBadge, RootDomainBadge, MetricCard, EmptyState,
  fmtBps, ago,
} from "./badges";
import { loadResources, loadAppRca, loadHealthSignals, loadChangeEvents, loadEvidence } from "./api";
import { resourceCategory } from "./attribution";

type DetailTab = "overview" | "identity" | "health" | "changes" | "traffic" | "dependencies" | "underlay" | "evidence";

// a metric with no ingested source renders "—", never a fabricated 0.
const NM = (v: number, fmt: (n: number) => string): ReactNode =>
  v < 0 ? <span className="ao-muted">—</span> : fmt(v);

// the app's health, measured from its OWN signals: the worst state any cloud health
// signal reported in the window. No signals ⇒ whatever identity gave us (unknown) —
// silence is never upgraded to "healthy", and neither is a signal whose own state
// is "unknown" (audit D-P2-9: only an explicit healthy report may say healthy).
function worstHealth(health: HealthSignal[], app: App): App["health"] {
  if (health.some((h) => h.state === "down")) return "down";
  if (health.some((h) => h.state === "degraded")) return "degraded";
  if (health.some((h) => h.state === "healthy")) return "healthy";
  if (health.length > 0) return "unknown"; // signals exist but none states a health
  return app.health;
}

// the app's own cloud signals — health, change and the evidence the engine grounded.
function useAppSignals(app: App) {
  const [health, setHealth] = useState<HealthSignal[]>([]);
  const [changes, setChanges] = useState<ChangeEvent[]>([]);
  const [evidence, setEvidence] = useState<EvidenceRow[]>([]);
  useEffect(() => {
    let live = true;
    const key = app.name || app.id;
    loadHealthSignals(key).then((r) => { if (live) setHealth(r); }, () => { if (live) setHealth([]); });
    loadChangeEvents(key).then((r) => { if (live) setChanges(r); }, () => { if (live) setChanges([]); });
    loadEvidence(key).then((r) => { if (live) setEvidence(r.rows); }, () => { if (live) setEvidence([]); });
    return () => { live = false; };
  }, [app.name, app.id]);
  return { health, changes, evidence };
}

export default function AppDetail({ app, onBack }: { app: App; onBack: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  const { health, changes, evidence } = useAppSignals(app);
  // App resources are LIVE from the inventory (real), filtered to this app.
  const [resources, setResources] = useState<CloudResource[]>([]);
  useEffect(() => {
    let live = true;
    loadResources().then(
      (all) => { if (live) setResources(all.filter((r) => r.app === app.name || r.app === app.id)); },
      () => { /* leave empty on error */ },
    );
    return () => { live = false; };
  }, [app.name, app.id]);

  return (
    <div className="ao-detail">
      <div className="ao-detail-bar">
        <button className="ao-link" onClick={onBack}>← Applications</button>
      </div>

      <div className="ao-detail-head">
        <div className="ao-detail-id">
          <h2>{app.name}</h2>
          <HealthBadge status={app.health} />
          <ConfidenceBadge level={app.confidence} title={`identity by ${app.source}`} />
        </div>
        <div className="ao-detail-meta">
          <span>{app.owner} · {app.env}</span>
          <span>{(app.providers.length ? app.providers.map((p) => p.toUpperCase()).join(" + ") : "—")} · {app.account} · {app.region}</span>
          {app.rootDomain !== "unknown" && <span>RCA: <RootDomainBadge domain={app.rootDomain} /></span>}
        </div>
      </div>

      <Segmented
        value={tab}
        onChange={(v) => setTab(v as DetailTab)}
        ariaLabel="App detail view"
        options={[
          { value: "overview", label: "Overview" }, { value: "identity", label: "Identity" },
          { value: "health", label: "Health" }, { value: "changes", label: "Changes" },
          { value: "traffic", label: "Traffic" }, { value: "dependencies", label: "Dependencies" },
          { value: "underlay", label: "Underlay" }, { value: "evidence", label: "Evidence" },
        ]}
      />

      {tab === "overview" && (
        <div className="ao-stack">
          <div className="ao-cards">
            {/* Health is MEASURED from this app's own cloud health signals; the
                traffic/latency cards stay "—" until cloud flow + metric land. */}
            <MetricCard label="Health" value={<HealthBadge status={worstHealth(health, app)} />} tone={worstHealth(health, app) === "down" ? "bad" : worstHealth(health, app) === "degraded" ? "warn" : "good"} />
            <MetricCard label="Health signals (24h)" value={health.length} tone={health.length ? "warn" : "good"} />
            <MetricCard label="Cloud changes (24h)" value={changes.length} />
            <MetricCard label="P95 latency" value={NM(app.p95ms, (n) => `${n} ms`)} sub="not ingested" />
            <MetricCard label="Traffic" value={NM(app.trafficBps, fmtBps)} sub="not ingested" tone="accent" />
            <MetricCard label="Last change" value={changes.length ? ago(changes[0].time) : <span className="ao-muted">—</span>} sub={changes.length ? changes[0].changeType.replace(/_/g, " ") : undefined} />
            <MetricCard label="Impacted seams" value={<span className="ao-muted">—</span>} sub="not ingested" />
          </div>
          <RcaPanel app={app} evidence={evidence} />
          <div className="ao-panel">
            <div className="ao-panel-h">Incident timeline <span className="ao-panel-meta">this app's cloud signals · last 24h</span></div>
            <ul className="ao-timeline">
              {changes.map((c, i) => <li key={"c" + i}><span className="ao-tl-t">{ago(c.time)}</span><Chip label="change" tone="var(--warn)" /> {c.changeType.replace(/_/g, " ")} on {c.resource}</li>)}
              {health.map((h, i) => <li key={"h" + i}><span className="ao-tl-t">{ago(h.time)}</span><Chip label="health" tone="var(--crit)" /> {h.signal} {h.metric} {h.current} (baseline {h.baseline})</li>)}
              {changes.length + health.length === 0 && <li><EmptyState title="No cloud events for this app in the last 24h" hint="health + change signals appear here as the connected cloud account reports them" /></li>}
            </ul>
          </div>
        </div>
      )}

      {tab === "identity" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Identity evidence</div>
          <table className="ao-kv">
            <tbody>
              <tr><td>App</td><td><strong>{app.name}</strong></td></tr>
              <tr><td>Attributed by</td><td>{app.source} <ConfidenceBadge level={app.confidence} /></td></tr>
              <tr><td>Why this identity</td><td>{identityWhy(app)}</td></tr>
              <tr><td>Owner / Env</td><td>{app.owner} · {app.env}</td></tr>
              <tr><td>Cloud</td><td>{(app.providers.length ? app.providers.map((p) => p.toUpperCase()).join(" + ") : "—")} · {app.account} · {app.region}</td></tr>
              <tr><td>Resources mapped</td><td>{app.resources}</td></tr>
              <tr><td>Unknown traffic</td><td>{NM(app.unknownPct, (n) => `${n}%`)} <span className="ao-muted">— not ingested (cloud flow logs)</span></td></tr>
            </tbody>
          </table>
          <div className="ao-panel-h">Resources <span className="ao-panel-meta">{resources.length} mapped · live from inventory</span></div>
          {resources.length === 0 ? (
            <EmptyState title="No resources mapped to this app yet" hint="resources appear as the cloud inventory is discovered and attributed" />
          ) : (
          <DataTable<CloudResource> rows={resources} rowKey={(r) => r.id} height={Math.min(320, 44 + resources.length * 30)} ariaLabel="App resources"
            columns={[
              { key: "name", header: "Resource", width: 190, text: (r) => r.name, render: (r) => <strong>{r.name}</strong> },
              { key: "cat", header: "Category", width: 116, sortable: true, sortValue: (r) => resourceCategory(r.type), render: (r) => <Chip label={resourceCategory(r.type)} tone="var(--fg-subtle)" /> },
              { key: "type", header: "Type", width: 120, render: (r) => r.type },
              { key: "region", header: "Region", width: 100, render: (r) => r.region },
              { key: "src", header: "Identity source", width: 130, render: (r) => <>{r.source} <ConfidenceBadge level={r.confidence} /></> },
              { key: "health", header: "Health", width: 110, render: (r) => <HealthBadge status={r.health} /> },
            ]} />
          )}
        </div>
      )}

      {tab === "health" && <HealthTable rows={health} />}
      {tab === "changes" && <ChangeTable rows={changes} />}
      {tab === "evidence" && <EvidenceTable rows={evidence} />}

      {tab === "traffic" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Traffic</div>
          <div className="ao-cards">
            <MetricCard label="Throughput" value={NM(app.trafficBps, fmtBps)} sub="not ingested" tone="accent" />
            <MetricCard label="5xx rate" value={NM(app.errorPct, (n) => `${n}%`)} sub="not ingested" />
            <MetricCard label="Unknown" value={NM(app.unknownPct, (n) => `${n}%`)} sub="not ingested" />
          </div>
          <EmptyState title="Per-app cloud traffic is not ingested yet" hint="cloud flow + load-balancer logs feed this panel; connect them in Ingestion — no sample traffic is shown" />
        </div>
      )}

      {tab === "dependencies" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Dependencies</div>
          <EmptyState title="Dependency graph renders on the App Map" hint="talks_to / depends_on / backed_by edges from cloud_flow + traces (P3D/P3E)" />
        </div>
      )}

      {tab === "underlay" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Underlay impact</div>
          <EmptyState title="App-to-underlay correlation is not ingested yet"
            hint="needs cloud seam telemetry (Direct Connect / VPN / ExpressRoute) joined to this app's symptoms — until then no seam is claimed for this app" />
        </div>
      )}
    </div>
  );
}

// a labelled list of evidence reasons (one category of the chain).
function EvBlock({ title, badge, rows, mark, tone }: {
  title: string; badge?: ReactNode; rows: EvidenceRow[]; mark: string; tone?: string;
}) {
  if (!rows.length) return null;
  return (
    <div className="ao-chain-block">
      <div className="ao-chain-h">{title} {badge}</div>
      <ul className="ao-ev-list">
        {rows.map((e, i) => (
          <li key={i} className="ao-ev"><span className="ao-ev-i" style={tone ? { color: tone } : undefined}>{mark}</span>{e.reason}</li>
        ))}
      </ul>
    </div>
  );
}

// EngineRcaBanner — the REAL correlation-engine RCA for this app (#81 P3G), not the
// heuristic root-domain verdict. Present only when the engine has grounded a cloud
// object for the app; links to the full RCA detail. crossPlane = an independent
// (non-cloud) observer corroborates → the engine can confirm; single cloud vantage
// is suspected-at-best, stated honestly.
const VERDICT_LABEL: Record<string, string> = {
  confirmed: "Confirmed", suspected: "Suspected · not confirmed",
  undetermined: "Under review", recovered: "Recovered", contradicted: "Ruled out",
};
function EngineRcaBanner({ rca }: { rca: AppRca }) {
  return (
    <div className="ao-rca-engine">
      <div className="ao-rca-engine-h">
        <span>Correlation engine RCA</span>
        <Chip
          label={rca.crossPlane ? "Corroborated cross-plane" : "Single-plane · suspected"}
          tone={rca.crossPlane ? "var(--ok)" : "var(--warn)"}
        />
      </div>
      <div className="ao-rca-grid">
        <div><div className="ao-rca-l">Assessment</div><div className="ao-rca-v">{VERDICT_LABEL[rca.verdictTier] ?? rca.verdictTier}</div></div>
        <div><div className="ao-rca-l">Signals</div><div className="ao-rca-v">{rca.signalCount}</div></div>
        {/* Observers = distinct observer identities (audit D-P2-12: the old cell
            printed the source PLANES and called them observers). */}
        <div><div className="ao-rca-l">Observers</div><div className="ao-rca-v"
          title={rca.observers.join(", ")}>{rca.observerCount || "—"}</div></div>
        <div><div className="ao-rca-l">Planes</div><div className="ao-rca-v">{rca.planeCount || rca.sources.length || "—"}</div></div>
        <div><div className="ao-rca-l">State</div><div className="ao-rca-v">{rca.state}</div></div>
      </div>
      <a className="ao-rca-link" href={`#/monitoring/correlations?id=${encodeURIComponent(rca.correlationId)}`}>
        View full RCA →
      </a>
    </div>
  );
}

function useAppRca(appId: string): AppRca | null {
  const [rca, setRca] = useState<AppRca | null>(null);
  useEffect(() => {
    let live = true;
    loadAppRca(appId).then((r) => { if (live) setRca(r); }).catch(() => { if (live) setRca(null); });
    return () => { live = false; };
  }, [appId]);
  return rca;
}

function RcaPanel({ app, evidence }: { app: App; evidence: EvidenceRow[] }) {
  const engineRca = useAppRca(app.id);
  const banner = engineRca ? <EngineRcaBanner rca={engineRca} /> : null;
  const byCat = (c: EvidenceCategory) => evidence.filter((e) => e.category === c);
  const grounded = byCat("grounded");
  const missing = byCat("missing");

  // The engine is the ONLY source of a cloud verdict. No engine object ⇒ no verdict:
  // "unknown" is first-class and we never synthesize a root domain for the app.
  if (!engineRca) {
    return (
      <div className="ao-panel ao-rca">
        <div className="ao-panel-h">RCA</div>
        <EmptyState title="No investigation for this service in the last 24 hours"
          hint="an investigation opens automatically when correlated signals point at this service" />
      </div>
    );
  }

  return (
    <div className="ao-panel ao-rca">
      <div className="ao-panel-h">RCA</div>
      {banner}
      {/* the evidence ledger, exactly as the engine recorded it: what it grounded,
          and the gaps it itself declared. No invented categories. */}
      <div className="ao-chain">
        <EvBlock title="Grounded findings" rows={grounded.slice(0, 12)} mark="✓" tone="var(--ok)" />
        <EvBlock title="Missing evidence (the engine's own gaps)" rows={missing} mark="–" tone="var(--fg-subtle)" />
        {!grounded.length && !missing.length && (
          <div className="ao-muted ao-chain-empty">No cloud signals are attached to this RCA object yet.</div>
        )}
      </div>
    </div>
  );
}

// plain-language provenance for the app's identity — never a bare source token.
const identityWhy = (a: App): string => {
  switch (a.source) {
    case "cloud_tag": return `cloud tags (app/owner/env) on the resources resolve to "${a.name}"`;
    case "cloud_graph": return `resource-graph name matches "${a.name}" (no app tag present)`;
    case "operator_catalog": return `operator-defined attribution rule maps these resources to "${a.name}"`;
    case "firewall_appid": return `firewall App-ID on crossing flows identifies "${a.name}"`;
    case "domain": return `observed domain/SNI maps to "${a.name}"`;
    case "ip_catalog": return `vendor IP/prefix catalog suggests "${a.name}" (suspected)`;
    default: return "no confident attribution — identity is unknown";
  }
};

// ── Per-app signal tables (LIVE: /api/cloud/health|changes|evidence) ─────────
function HealthTable({ rows }: { rows: HealthSignal[] }) {
  return <div className="ao-panel"><div className="ao-panel-h">Health signals <span className="ao-panel-meta">last 24h · from the connected cloud account</span></div>
    {rows.length === 0 ? <EmptyState title="No cloud health signals for this app in the last 24h" hint="a signal appears here when the provider reports a problem on this app" /> : (
    <DataTable<HealthSignal> rows={rows} rowKey={(r) => r.time + r.signal + r.metric + r.resource} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Health signals" columns={[
      { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
      { key: "res", header: "Resource", width: 170, render: (r) => r.resource },
      { key: "sig", header: "Signal", width: 150, render: (r) => r.signal },
      { key: "metric", header: "Metric", width: 150, render: (r) => <span className="ao-mono">{r.metric}</span> },
      { key: "state", header: "State", width: 100, render: (r) => <HealthBadge status={r.state} /> },
      { key: "cur", header: "Current", width: 90, render: (r) => <strong>{r.current}</strong> },
      { key: "base", header: "Baseline", width: 90, render: (r) => <span className="ao-muted">{r.baseline}</span> },
      { key: "src", header: "Cloud", width: 90, render: (r) => r.source.toUpperCase() },
    ]} />)}</div>;
}

function ChangeTable({ rows }: { rows: ChangeEvent[] }) {
  return <div className="ao-panel"><div className="ao-panel-h">Change events <span className="ao-panel-meta">provider audit log · last 24h</span></div>
    {rows.length === 0 ? <EmptyState title="No cloud change events for this app in the last 24h" hint="management-plane changes on this app's resources appear here" /> : (
    <DataTable<ChangeEvent> rows={rows} rowKey={(r) => r.time + r.changeType + r.resource + r.actor} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Change events" columns={[
      { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
      { key: "type", header: "Change", width: 160, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
      { key: "res", header: "Resource", width: 190, render: (r) => <span className="ao-mono">{r.resource}</span> },
      { key: "actor", header: "Actor", width: 180, render: (r) => <span className="ao-mono">{r.actor}</span> },
      { key: "src", header: "Source", width: 160, render: (r) => r.source },
      { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
    ]} />)}</div>;
}

function EvidenceTable({ rows }: { rows: EvidenceRow[] }) {
  return <div className="ao-panel"><div className="ao-panel-h">Evidence <span className="ao-panel-meta">what the engine grounded into this app's RCA + its declared gaps</span></div>
    {rows.length === 0 ? <EmptyState title="No cloud evidence for this app" hint="evidence appears when the correlation engine grounds one of this app's cloud signals into an RCA object" /> : (
    <DataTable<EvidenceRow> rows={rows} rowKey={(r) => `${r.evidenceRef}|${r.rcaGroup}|${r.time}|${r.reason}`} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Evidence" columns={[
      { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
      { key: "cat", header: "Category", width: 110, render: (r) => r.category },
      { key: "sig", header: "Signal", width: 140, render: (r) => r.signalType },
      { key: "reason", header: "Reason", width: 320, render: (r) => <span className="ao-why" title={r.reason}>{r.reason}</span> },
      { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
      { key: "ref", header: "Evidence ref", width: 150, render: (r) => <span className="ao-mono ao-muted">{r.evidenceRef}</span> },
    ]} />)}</div>;
}
