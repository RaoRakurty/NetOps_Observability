// App Observability — App Detail drill-in (#81 P3F).
// The six-part story for one app: Identity → Health → Change → Traffic → Dependencies
// → Underlay → Evidence, with an RCA summary that always shows confidence + evidence.
// Built on the existing tokens/components; mock-fed today.

import { useState } from "react";
import { Segmented } from "../../components/ui";
import { Chip } from "../../components/noc";
import DataTable from "../../components/DataTable";
import type { App } from "./types";
import {
  HealthBadge, ConfidenceBadge, RootDomainBadge, MetricCard, EmptyState,
  fmtBps, ago,
} from "./badges";
import { mockHealth, mockChanges, mockEvidence, mockResources } from "./mock";

type DetailTab = "overview" | "identity" | "health" | "changes" | "traffic" | "dependencies" | "underlay" | "evidence";

export default function AppDetail({ app, onBack }: { app: App; onBack: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  const health = mockHealth.filter((h) => h.app === app.name);
  const changes = mockChanges.filter((c) => c.app === app.name);
  const evidence = mockEvidence.filter((e) => e.app === app.name);
  const resources = mockResources.filter((r) => r.app === app.name || r.app === app.id);

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
          <span>{app.provider.toUpperCase()} · {app.account} · {app.region}</span>
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
            <MetricCard label="Health" value={<HealthBadge status={app.health} />} tone={app.health === "down" ? "bad" : app.health === "degraded" ? "warn" : "good"} />
            <MetricCard label="5xx rate" value={`${app.errorPct}%`} tone={app.errorPct > 5 ? "bad" : app.errorPct > 1 ? "warn" : "good"} />
            <MetricCard label="P95 latency" value={app.p95ms ? `${app.p95ms} ms` : "—"} tone={app.p95ms > 1000 ? "warn" : "good"} />
            <MetricCard label="Traffic" value={fmtBps(app.trafficBps)} tone="accent" />
            <MetricCard label="Unknown traffic" value={`${app.unknownPct}%`} tone={app.unknownPct > 20 ? "warn" : undefined} />
            <MetricCard label="Last change" value={ago(app.lastChange)} sub={app.lastChange ? "deploy" : undefined} />
            <MetricCard label="Impacted seams" value={app.underlayImpacted ? "1" : "0"} tone={app.underlayImpacted ? "warn" : undefined} />
          </div>
          <RcaPanel app={app} />
          <div className="ao-panel">
            <div className="ao-panel-h">Incident timeline</div>
            <ul className="ao-timeline">
              {changes.map((c, i) => <li key={"c" + i}><span className="ao-tl-t">{ago(c.time)}</span><Chip label="change" tone="var(--warn)" /> {c.changeType.replace(/_/g, " ")} on {c.resource}</li>)}
              {health.map((h, i) => <li key={"h" + i}><span className="ao-tl-t">{ago(h.time)}</span><Chip label="health" tone="var(--crit)" /> {h.signal} {h.current} (baseline {h.baseline})</li>)}
              {evidence.filter((e) => e.signalType === "cloud_lb_access").map((e, i) => <li key={"e" + i}><span className="ao-tl-t">{ago(e.time)}</span><Chip label="traffic" tone="var(--accent)" /> {e.reason}</li>)}
              {changes.length + health.length === 0 && <li><EmptyState title="No events in window" /></li>}
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
              <tr><td>Owner / Env</td><td>{app.owner} · {app.env}</td></tr>
              <tr><td>Cloud</td><td>{app.provider.toUpperCase()} · {app.account} · {app.region}</td></tr>
              <tr><td>Resources mapped</td><td>{app.resources}</td></tr>
              <tr><td>Unknown traffic</td><td>{app.unknownPct}%</td></tr>
            </tbody>
          </table>
          <div className="ao-panel-h">Resources</div>
          <DataTable<typeof resources[number]> rows={resources} rowKey={(r) => r.id} height={Math.min(300, 44 + resources.length * 30)} ariaLabel="App resources"
            columns={[
              { key: "name", header: "Resource", width: 200, text: (r) => r.name, render: (r) => <strong>{r.name}</strong> },
              { key: "type", header: "Type", width: 110, render: (r) => r.type },
              { key: "src", header: "Identity source", width: 140, render: (r) => <>{r.source} <ConfidenceBadge level={r.confidence} /></> },
              { key: "health", header: "Health", width: 110, render: (r) => <HealthBadge status={r.health} /> },
            ]} />
        </div>
      )}

      {tab === "health" && <SignalTable kind="health" app={app} />}
      {tab === "changes" && <SignalTable kind="changes" app={app} />}
      {tab === "evidence" && <SignalTable kind="evidence" app={app} />}

      {tab === "traffic" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Traffic</div>
          <div className="ao-cards">
            <MetricCard label="Throughput" value={fmtBps(app.trafficBps)} tone="accent" />
            <MetricCard label="5xx rate" value={`${app.errorPct}%`} tone={app.errorPct > 5 ? "bad" : "good"} />
            <MetricCard label="Unknown" value={`${app.unknownPct}%`} />
          </div>
          <EmptyState title="Per-flow breakdown wires to /api/flows/apps?include_cloud=true" hint="cloud_flow + cloud_lb_access evidence renders here when ingested" />
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
          {app.underlayImpacted
            ? <table className="ao-kv"><tbody>
                <tr><td>Seam</td><td>Direct Connect (us-east-1 ⇄ dc1)</td></tr>
                <tr><td>Underlay evidence</td><td>BGP flap + RTT 12→140ms</td></tr>
                <tr><td>App symptom</td><td>p95 latency {app.p95ms} ms</td></tr>
                <tr><td>Root domain</td><td><RootDomainBadge domain="hybrid_underlay" /> <ConfidenceBadge level="suspected" /></td></tr>
              </tbody></table>
            : <EmptyState title="No underlay impact correlated" hint="app-to-underlay RCA join (P3D) lights this up when a seam degrades under the app" />}
        </div>
      )}
    </div>
  );
}

function RcaPanel({ app }: { app: App }) {
  if (app.rootDomain === "unknown") {
    return <div className="ao-panel ao-rca"><div className="ao-panel-h">RCA</div><EmptyState title="No active RCA — app is healthy or evidence is insufficient" hint="unknown is first-class; we don't guess a root cause" /></div>;
  }
  return (
    <div className="ao-panel ao-rca">
      <div className="ao-panel-h">RCA summary <RootDomainBadge domain={app.rootDomain} /></div>
      <div className="ao-rca-grid">
        <div><div className="ao-rca-l">Likely root domain</div><div className="ao-rca-v"><RootDomainBadge domain={app.rootDomain} /></div></div>
        <div><div className="ao-rca-l">Why</div><div className="ao-rca-v">{rcaWhy(app)}</div></div>
        <div><div className="ao-rca-l">Supporting evidence</div><div className="ao-rca-v ao-good">{rcaSupport(app)}</div></div>
        <div><div className="ao-rca-l">Contradicting</div><div className="ao-rca-v ao-muted">none above floor</div></div>
        <div><div className="ao-rca-l">Next action</div><div className="ao-rca-v">{rcaAction(app)}</div></div>
      </div>
    </div>
  );
}

const rcaWhy = (a: App) => a.rootDomain === "deployment" ? "deploy 7m before 5xx onset, same app" : a.rootDomain === "database_dependency" ? "DB connection pool exhausted; targets unhealthy" : a.rootDomain === "hybrid_underlay" ? "Direct Connect BGP flap coincides with latency rise" : "multi-signal correlation";
const rcaSupport = (a: App) => a.rootDomain === "deployment" ? "cloud_change (confirmed) + cloud_health 5xx (strong)" : a.rootDomain === "database_dependency" ? "elb target_health down + rds connections (strong)" : "underlay BGP/RTT + app latency (suspected)";
const rcaAction = (a: App) => a.rootDomain === "deployment" ? "Review/rollback deploy 7f3a" : a.rootDomain === "database_dependency" ? "Scale DB connections / check pool config" : "Open DX seam ticket; verify on-prem BGP";

function SignalTable({ kind, app }: { kind: "health" | "changes" | "evidence"; app: App }) {
  if (kind === "health") {
    const rows = mockHealth.filter((h) => h.app === app.name);
    return <div className="ao-panel"><div className="ao-panel-h">Health signals</div>
      <DataTable rows={rows} rowKey={(r) => r.time + r.signal} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Health signals" columns={[
        { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
        { key: "res", header: "Resource", width: 150, render: (r) => r.resource },
        { key: "sig", header: "Signal", width: 140, render: (r) => r.signal },
        { key: "state", header: "State", width: 100, render: (r) => <HealthBadge status={r.state} /> },
        { key: "cur", header: "Current", width: 90, render: (r) => <strong>{r.current}</strong> },
        { key: "base", header: "Baseline", width: 90, render: (r) => <span className="ao-muted">{r.baseline}</span> },
        { key: "src", header: "Source", width: 150, render: (r) => r.source },
      ]} /></div>;
  }
  if (kind === "changes") {
    const rows = mockChanges.filter((c) => c.app === app.name);
    return <div className="ao-panel"><div className="ao-panel-h">Change events</div>
      <DataTable rows={rows} rowKey={(r) => r.time + r.changeType} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Change events" columns={[
        { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
        { key: "type", header: "Change", width: 160, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
        { key: "res", header: "Resource", width: 150, render: (r) => r.resource },
        { key: "actor", header: "Actor", width: 150, render: (r) => <span className="ao-mono">{r.actor}</span> },
        { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
      ]} /></div>;
  }
  const rows = mockEvidence.filter((e) => e.app === app.name);
  return <div className="ao-panel"><div className="ao-panel-h">Evidence</div>
    <DataTable rows={rows} rowKey={(r) => r.time + r.signalType} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Evidence" columns={[
      { key: "time", header: "Time", width: 90, render: (r) => ago(r.time) },
      { key: "sig", header: "Signal", width: 140, render: (r) => r.signalType },
      { key: "reason", header: "Reason", width: 280, render: (r) => r.reason },
      { key: "conf", header: "Confidence", width: 110, render: (r) => <ConfidenceBadge level={r.confidence} /> },
      { key: "ref", header: "Evidence ref", width: 150, render: (r) => <span className="ao-mono ao-muted">{r.evidenceRef}</span> },
    ]} /></div>;
}
