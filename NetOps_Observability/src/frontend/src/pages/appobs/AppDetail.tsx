// App Observability — App Detail drill-in (#81 P3F/P3H).
// The six-part story for one app: Identity → Health → Change → Traffic → Dependencies
// → Underlay → Evidence, with an RCA summary that always shows confidence + evidence.
//
// Every panel is LIVE and tenant-scoped: resources from the cloud inventory, health /
// change / evidence from the signals this app's connected cloud account actually
// emitted (/api/cloud/health|changes|evidence). Nothing is sample data; a panel with
// no ingested signal shows its empty state instead.

import { fmtDateTime } from "../../lib/time";
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
import { healthRank, confidenceRank, timeRank } from "./sortRanks";
import { loadResources, loadAppRca, loadHealthSignals, loadChangeEvents, loadEvidence } from "./api";
import { resourceCategory } from "./attribution";
import { isStateEvent, stateLabel, stateReason, cleanVal } from "./timeline";
import { DEFAULT_CLOUD_RANGE, filterByRange, newestIso, rangeWords } from "./range";
import { FeedBar } from "./FeedBar";
import { feedCount } from "./range";
import ResourceMetricsPanel from "./ResourceMetricsPanel";
import SloCard from "./SloCard";
import { lbTraffic, isLbErrorSignal } from "./traffic";
import {
  healthMetricCell, healthCurrentCell, healthBaselineCell, healthReasonCell,
} from "./healthCells";

type DetailTab = "overview" | "identity" | "health" | "metrics" | "changes" | "traffic" | "dependencies" | "underlay" | "evidence";

// a metric with no ingested source renders "—", never a fabricated 0.
const NM = (v: number, fmt: (n: number) => string): ReactNode =>
  v < 0 ? <span className="ao-muted">—</span> : fmt(v);

// ── Data age (owner review: "every panel is empty or stale") ─────────────────
// The cloud hosts behind this lab were torn down ~2h before the review, so the
// service genuinely had no live telemetry. That was not the defect — the defect
// was that the page could not TELL you: a 2h-old "degraded" rendered exactly
// like a live one, and empty panels never said whether they were empty because
// nothing was measured or because nothing had arrived recently.
//
// So any value derived from a signal now carries the age of the signal it came
// from, and any empty panel says which of the two empties it is.
function AsOf({ iso, prefix = "as of" }: { iso: string; prefix?: string }) {
  if (!iso) return null;
  return (
    <span className="ao-asof" title={`Source last reported at ${fmtDateTime(iso)}`}>
      {prefix} {ago(iso)}
    </span>
  );
}

// The honest hint for a panel with nothing in the selected window: distinguishes
// "this source has never reported" from "this source went quiet N ago".
function staleHint(newest: string, minutes: number, what: string): string {
  if (newest) {
    return `Nothing in the ${rangeWords(minutes)} — this service's most recent ${what} landed ${ago(newest)}. Widen the range to see it, or check Data sources if the source has stopped reporting.`;
  }
  return `No ${what} has been ingested for this service. Connect the source in Data sources — nothing is simulated here.`;
}

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
// `loadedAt` stamps only a SUCCESSFUL fetch, so the live cue can never age-reset
// on a failure and make stale data look fresh.
function useAppSignals(app: App) {
  const [health, setHealth] = useState<HealthSignal[]>([]);
  const [changes, setChanges] = useState<ChangeEvent[]>([]);
  const [evidence, setEvidence] = useState<EvidenceRow[]>([]);
  const [loadedAt, setLoadedAt] = useState<number>(() => Date.now());
  const [busy, setBusy] = useState(false);
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    let live = true;
    const key = app.name || app.id;
    if (nonce > 0) setBusy(true);
    Promise.allSettled([loadHealthSignals(key), loadChangeEvents(key), loadEvidence(key)]).then(
      ([h, c, e]) => {
        if (!live) return;
        setHealth(h.status === "fulfilled" ? h.value : []);
        setChanges(c.status === "fulfilled" ? c.value : []);
        setEvidence(e.status === "fulfilled" ? e.value.rows : []);
        setLoadedAt(Date.now());
        setBusy(false);
      },
    );
    return () => { live = false; };
  }, [app.name, app.id, nonce]);
  return { health, changes, evidence, loadedAt, busy, refresh: () => setNonce((n) => n + 1) };
}

export default function AppDetail({ app, onBack }: { app: App; onBack: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  const sig = useAppSignals(app);
  // One window for the whole drill-in, so every panel answers for the same
  // period the user picked (the same control as Investigations).
  const [minutes, setMinutes] = useState<number>(DEFAULT_CLOUD_RANGE.minutes);
  const health = filterByRange(sig.health, minutes);
  const changes = filterByRange(sig.changes, minutes);
  const evidence = filterByRange(sig.evidence, minutes);
  // Freshness anchors — the newest signal of each kind REGARDLESS of range, so
  // an empty window can still say how old the last real reading was.
  const newestHealth = newestIso(sig.health);
  const newestChange = newestIso(sig.changes);
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
          {/* A health verdict without its age is the review's core dishonesty: a
              2h-old "degraded" read as current. State the age next to the badge. */}
          <AsOf iso={newestHealth} />
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
          { value: "health", label: "Health" }, { value: "metrics", label: "Metrics" },
          { value: "changes", label: "Changes" },
          { value: "traffic", label: "Traffic" }, { value: "dependencies", label: "Dependencies" },
          { value: "underlay", label: "Underlay" }, { value: "evidence", label: "Evidence" },
        ]}
      />

      {/* One range + liveness cue for every panel below (owner review #2 + #6). */}
      <FeedBar
        minutes={minutes} onRange={setMinutes}
        count={feedCount(health.length + changes.length, sig.health.length + sig.changes.length, minutes)}
        loadedAt={sig.loadedAt} onRefresh={sig.refresh} busy={sig.busy}
        label={`${app.name} time range`}
      />

      {tab === "overview" && (
        <div className="ao-stack">
          <div className="ao-cards">
            {/* Health is MEASURED from this app's own cloud health signals, and
                every card states the AGE of what it is showing — a value with no
                timestamp cannot be told apart from a live one (owner review #6). */}
            <MetricCard label="Health"
              value={<HealthBadge status={worstHealth(health, app)} />}
              sub={newestHealth ? `as of ${ago(newestHealth)}` : "never reported"}
              tone={worstHealth(health, app) === "down" ? "bad" : worstHealth(health, app) === "degraded" ? "warn" : "good"} />
            <MetricCard label={`Health signals (${rangeWords(minutes).replace("last ", "")})`}
              value={health.length}
              sub={health.length ? `newest ${ago(newestIso(health))}` : newestHealth ? `none in range · last ${ago(newestHealth)}` : "never reported"}
              tone={health.length ? "warn" : "good"} />
            <MetricCard label={`Cloud changes (${rangeWords(minutes).replace("last ", "")})`}
              value={changes.length}
              sub={changes.length ? `newest ${ago(newestIso(changes))}` : newestChange ? `none in range · last ${ago(newestChange)}` : "never reported"} />
            <MetricCard label="P95 latency" value={NM(app.p95ms, (n) => `${n} ms`)} sub="not ingested — needs cloud metrics" />
            <MetricCard label="Traffic" value={NM(app.trafficBps, fmtBps)} sub="not ingested — needs cloud flow logs" tone="accent" />
            <MetricCard label="Last change"
              value={changes.length ? ago(changes[0].time) : newestChange ? ago(newestChange) : <span className="ao-muted">—</span>}
              sub={changes.length ? changes[0].changeType.replace(/_/g, " ")
                : newestChange ? "outside the selected range" : "no change ingested"} />
            <MetricCard label="Impacted seams" value={<span className="ao-muted">—</span>} sub="not ingested — needs seam telemetry" />
          </div>
          <SloCard appName={app.name} />
          <RcaPanel app={app} evidence={evidence} />
          <div className="ao-panel">
            <div className="ao-panel-h">Incident timeline <span className="ao-panel-meta">this app's cloud signals · {rangeWords(minutes)}</span></div>
            <ul className="ao-timeline">
              {changes.map((c, i) => <li key={"c" + i}><span className="ao-tl-t">{ago(c.time)}</span><Chip label="change" tone="var(--warn)" /> {c.changeType.replace(/_/g, " ")} on {c.resource}</li>)}
              {/* A state event has no metric/current/baseline — the old line
                  rendered "resource_health   (baseline )". Say the state + the
                  provider's reason instead. */}
              {health.map((h, i) => (
                <li key={"h" + i}>
                  <span className="ao-tl-t">{ago(h.time)}</span>
                  <Chip label="health" tone="var(--crit)" />{" "}
                  {isStateEvent(h)
                    ? <>{h.signal.replace(/_/g, " ")} · <strong>{stateLabel(h.state)}</strong>
                        {stateReason(h) ? <span className="ao-muted"> · {stateReason(h)}</span>
                          : <span className="ao-muted"> · no reason stated</span>}</>
                    : <>{h.signal.replace(/_/g, " ")} {h.metric} <strong>{h.current}</strong>
                        {cleanVal(h.baseline) && <span className="ao-muted"> vs {h.baseline} baseline</span>}</>}
                </li>
              ))}
              {changes.length + health.length === 0 && (
                <li><EmptyState title={`No cloud events for this app in the ${rangeWords(minutes)}`}
                  hint={staleHint(newestIso([...sig.health, ...sig.changes]), minutes, "cloud signal")} /></li>
              )}
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
              { key: "type", header: "Type", width: 120, sortValue: (r) => r.type, render: (r) => r.type },
              { key: "region", header: "Region", width: 100, sortValue: (r) => r.region, render: (r) => r.region },
              { key: "src", header: "Identity source", width: 130, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <>{r.source} <ConfidenceBadge level={r.confidence} /></> },
              { key: "health", header: "Health", width: 110, sortValue: (r) => healthRank(r.health), render: (r) => <HealthBadge status={r.health} /> },
            ]} />
          )}
        </div>
      )}

      {tab === "metrics" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Cloud metrics
            <span className="ao-panel-meta">provider metric lane · measured values, never simulated</span></div>
          <ResourceMetricsPanel
            targets={resources.map((r) => ({ id: r.id, name: r.name }))}
            subject={app.name} />
        </div>
      )}

      {tab === "health" && <HealthTable rows={health} minutes={minutes} newest={newestHealth} />}
      {tab === "changes" && <ChangeTable rows={changes} minutes={minutes} newest={newestChange} />}
      {tab === "evidence" && <EvidenceTable rows={evidence} minutes={minutes} newest={newestIso(sig.evidence)} />}

      {tab === "traffic" && (
        <TrafficPanel app={app} evidence={evidence} allEvidence={sig.evidence} minutes={minutes} />
      )}

      {tab === "dependencies" && (
        <div className="ao-panel">
          <div className="ao-panel-h">Dependencies</div>
          <EmptyState title="Dependency graph renders on the App Map" hint="Dependencies observed in cloud flows and traces." />
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

// ── Traffic (app-edge HTTP telemetry from the cloud LB plane) ────────────────
// The owner asked for throughput + a 5xx rate. Exactly ONE of those is ingested,
// and this panel is explicit about which:
//   · gateway 5xx COUNT — REAL. Every ELB-side 5xx access-log line becomes a
//     cloud_lb_log signal, so the count over a window is complete.
//   · THROUGHPUT / 5xx RATE — the ALB tailer drops 2xx/3xx/4xx at parse time
//     (cloud_log_parsers.alb_lb_signal returns None for them), so the request
//     volume that would be the rate's denominator is never stored. A "rate" made
//     from 5xx alone is always 100% — a fabricated number. We name the gap and
//     the source that closes it instead of inventing the figure.
// See ./traffic for the derivation.
function TrafficPanel({ app, evidence, allEvidence, minutes }: {
  app: App; evidence: EvidenceRow[]; allEvidence: EvidenceRow[]; minutes: number;
}) {
  const t = lbTraffic(evidence, minutes);
  const everNewest = lbTraffic(allEvidence, Number.MAX_SAFE_INTEGER).newest;
  return (
    <div className="ao-stack">
      <div className="ao-panel">
        <div className="ao-panel-h">Traffic
          <span className="ao-panel-meta">app-edge HTTP · load-balancer access logs · {rangeWords(minutes)}</span></div>
        <div className="ao-cards">
          <MetricCard label="Gateway 5xx"
            value={t.errors}
            sub={t.errors ? `newest ${ago(t.newest)}` : everNewest ? `none in range · last ${ago(everNewest)}` : "none ingested"}
            tone={t.errors ? "bad" : "good"} />
          <MetricCard label="Request throughput"
            value={<span className="ao-muted">—</span>}
            sub="not ingested — access logs are filtered to 5xx faults only" />
          <MetricCard label="5xx rate"
            value={<span className="ao-muted">—</span>}
            sub="needs request volume — not measurable from 5xx alone" />
          <MetricCard label="Reporting load balancers"
            value={t.resources.length || <span className="ao-muted">—</span>}
            sub={t.resources.length ? t.resources.join(", ") : "no LB reported a 5xx in range"} />
        </div>
      </div>

      <div className="ao-panel">
        <div className="ao-panel-h">Gateway 5xx events <span className="ao-panel-meta">every ELB-side 5xx grounded for {app.name}</span></div>
        {t.errors === 0 ? (
          <EmptyState
            title={`No gateway 5xx for this service in the ${rangeWords(minutes)}`}
            hint={everNewest
              ? `The most recent 5xx landed ${ago(everNewest)} — widen the range to see it. A quiet load balancer is a healthy one; this panel only fills when the provider reports an error.`
              : "No load-balancer access logs have been ingested for this service. Connect the LB log source in Data sources — no sample traffic is shown."} />
        ) : (
          <DataTable<EvidenceRow>
            rows={evidence.filter((r) => r.grounded && isLbErrorSignal(r.signalType))}
            rowKey={(r) => `${r.evidenceRef}|${r.time}`}
            height={Math.min(320, 44 + t.errors * 30)} ariaLabel="Gateway 5xx events"
            columns={[
              { key: "time", header: "Time", width: 90, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
              { key: "res", header: "Load balancer", width: 200, sortValue: (r) => r.resource, render: (r) => <span className="ao-mono">{r.resource}</span> },
              { key: "sig", header: "Signal", width: 140, sortValue: (r) => r.signalType, render: (r) => r.signalType },
              { key: "reason", header: "What was observed", width: 320, sortValue: (r) => r.reason, render: (r) => <span className="ao-why" title={r.reason}>{r.reason}</span> },
            ]} />
        )}
      </div>

      {/* The honest gap, stated once rather than as three fake "—" cards. */}
      <div className="ao-panel">
        <div className="ao-panel-h">Not measured</div>
        <p className="ao-set-d">
          Request throughput and a true 5xx <em>rate</em> need total request volume.
          The load-balancer log pipeline keeps only ELB-side 5xx lines (successful
          requests are discarded at parse time), so the denominator is not stored
          and Correlix will not estimate it.
        </p>
        <div className="ao-set-v">Needs: full load-balancer access-log ingestion (all status codes), or provider request-count metrics.</div>
      </div>
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
        <div><div className="ao-rca-l">Observations</div><div className="ao-rca-v">{rca.signalCount}</div></div>
        {/* Observers = distinct observer identities (audit D-P2-12: the old cell
            printed the source PLANES and called them observers). */}
        <div><div className="ao-rca-l">Observers</div><div className="ao-rca-v"
          title={rca.observers.join(", ")}>{rca.observerCount || "—"}</div></div>
        <div><div className="ao-rca-l">Planes</div><div className="ao-rca-v">{rca.planeCount || rca.sources.length || "—"}</div></div>
        <div><div className="ao-rca-l">State</div><div className="ao-rca-v">{rca.state}</div></div>
      </div>
      <a className="ao-rca-link" href={`#/investigate/rca?id=${encodeURIComponent(rca.correlationId)}`}>
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
        {/* Honest about WHICH silence this is: the engine forms objects over its
            own 24h window, so "no investigation" here is not a range artefact. */}
        <EmptyState title="No investigation for this service in the last 24 hours"
          hint="An investigation opens automatically when correlated signals point at this service. None is open — either nothing faulted, or the signals that would ground one have stopped arriving (check Data sources)." />
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
          <div className="ao-muted ao-chain-empty">No cloud signals attached yet.</div>
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
function HealthTable({ rows, minutes, newest }: { rows: HealthSignal[]; minutes: number; newest: string }) {
  return <div className="ao-panel"><div className="ao-panel-h">Health signals <span className="ao-panel-meta">{rangeWords(minutes)} · from the connected cloud account</span></div>
    {rows.length === 0 ? <EmptyState title={`No cloud health signals for this app in the ${rangeWords(minutes)}`} hint={staleHint(newest, minutes, "health signal")} /> : (
    <DataTable<HealthSignal> rows={rows} rowKey={(r) => r.time + r.signal + r.metric + r.resource} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Health signals" columns={[
      { key: "time", header: "Time", width: 90, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
      { key: "res", header: "Resource", width: 170, sortValue: (r) => r.resource, render: (r) => r.resource },
      { key: "sig", header: "Signal", width: 150, sortValue: (r) => r.signal, render: (r) => r.signal },
      // A provider state event carries no metric/value/baseline — the shared
      // cells say what it IS instead (identical rule to the Alerts table).
      { key: "metric", header: "Metric", width: 150, sortValue: (r) => r.metric, render: healthMetricCell },
      { key: "state", header: "State", width: 100, sortValue: (r) => healthRank(r.state), render: (r) => <HealthBadge status={r.state} /> },
      { key: "cur", header: "Current", width: 90, sortValue: (r) => r.current, render: healthCurrentCell },
      { key: "base", header: "Baseline", width: 90, sortValue: (r) => r.baseline, render: healthBaselineCell },
      { key: "reason", header: "Reason", width: 150, sortValue: (r) => stateReason(r), render: healthReasonCell },
      { key: "src", header: "Cloud", width: 90, sortValue: (r) => r.source, render: (r) => r.source.toUpperCase() },
    ]} />)}</div>;
}

function ChangeTable({ rows, minutes, newest }: { rows: ChangeEvent[]; minutes: number; newest: string }) {
  return <div className="ao-panel"><div className="ao-panel-h">Change events <span className="ao-panel-meta">provider audit log · {rangeWords(minutes)}</span></div>
    {rows.length === 0 ? <EmptyState title={`No cloud change events for this app in the ${rangeWords(minutes)}`} hint={staleHint(newest, minutes, "change event")} /> : (
    <DataTable<ChangeEvent> rows={rows} rowKey={(r) => r.time + r.changeType + r.resource + r.actor} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Change events" columns={[
      { key: "time", header: "Time", width: 90, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
      { key: "type", header: "Change", width: 160, sortValue: (r) => r.changeType, render: (r) => <Chip label={r.changeType.replace(/_/g, " ")} tone="var(--warn)" /> },
      { key: "res", header: "Resource", width: 190, sortValue: (r) => r.resource, render: (r) => <span className="ao-mono">{r.resource}</span> },
      { key: "actor", header: "Actor", width: 180, sortValue: (r) => r.actor, render: (r) => <span className="ao-mono">{r.actor}</span> },
      { key: "src", header: "Source", width: 160, sortValue: (r) => r.source, render: (r) => r.source },
      { key: "conf", header: "Confidence", width: 110, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <ConfidenceBadge level={r.confidence} /> },
    ]} />)}</div>;
}

function EvidenceTable({ rows, minutes, newest }: { rows: EvidenceRow[]; minutes: number; newest: string }) {
  return <div className="ao-panel"><div className="ao-panel-h">Evidence <span className="ao-panel-meta">what the engine grounded into this app's RCA + its declared gaps · {rangeWords(minutes)}</span></div>
    {rows.length === 0 ? <EmptyState title={`No cloud evidence for this app in the ${rangeWords(minutes)}`} hint={staleHint(newest, minutes, "grounded finding")} /> : (
    <DataTable<EvidenceRow> rows={rows} rowKey={(r) => `${r.evidenceRef}|${r.rcaGroup}|${r.time}|${r.reason}`} height={Math.min(320, 44 + rows.length * 30)} ariaLabel="Evidence" columns={[
      { key: "time", header: "Time", width: 90, sortValue: (r) => timeRank(r.time), render: (r) => ago(r.time) },
      { key: "cat", header: "Category", width: 110, sortValue: (r) => r.category, render: (r) => r.category },
      { key: "sig", header: "Signal", width: 140, sortValue: (r) => r.signalType, render: (r) => r.signalType },
      { key: "reason", header: "Reason", width: 320, sortValue: (r) => r.reason, render: (r) => <span className="ao-why" title={r.reason}>{r.reason}</span> },
      { key: "conf", header: "Confidence", width: 110, sortValue: (r) => confidenceRank(r.confidence), render: (r) => <ConfidenceBadge level={r.confidence} /> },
      { key: "ref", header: "Evidence ref", width: 150, sortValue: (r) => r.evidenceRef, render: (r) => <span className="ao-mono ao-muted">{r.evidenceRef}</span> },
    ]} />)}</div>;
}
