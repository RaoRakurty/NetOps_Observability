import { useEffect, useState } from "react";
import { api } from "../services/api";
import { Group, Panel, MetricLine, MetricTop, MetricStat, fmtNum } from "../components/board/panels";
import { StatStrip, Stat, StatTone } from "../components/ui";
import InvestigationPage from "./troubleshoot/InvestigationPage";
import { parseInvestigationHash, type TroubleshootSection } from "./troubleshoot/investigationModel";

// Troubleshooting — health of the collection pipeline itself (collectors, SNMP
// reachability, NetFlow ingest, traps). Unlike the device boards, the collector
// self-metrics (collector_*) emit even when every device is unreachable, so this
// board stays useful precisely when the others go dark — it tells you whether
// "no data" is a collector problem or a device problem.

// CountStat — a scalar tile sourced from a non-Prometheus store (ClickHouse
// flows / OpenSearch traps) via an async loader.
function CountStat({ label, loader, fmt = fmtNum, tone }: {
  label: string; loader: () => Promise<number>; fmt?: (n: number) => string; tone?: (n: number) => StatTone;
}) {
  const [v, setV] = useState<number | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => { try { const n = await loader(); if (alive) setV(n); } catch { if (alive) setV(null); } };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return <Stat label={label} value={v == null ? "—" : fmt(v)} tone={v != null && tone ? tone(v) : ""} />;
}

// NetFlow source presence — per flow_type record counts + exporters (ClickHouse).
function FlowSources() {
  const [rows, setRows] = useState<{ flow_type: string; flows: number; exporters: number }[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try { const r = await api.flowsByType(3600); if (alive) { setRows((r?.data as any[]) ?? []); setErr(null); } }
      catch (e) { if (alive) setErr((e as Error).message); }
    };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return (
    <Panel title="NetFlow / IPFIX / sFlow sources (last 1h)">
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <div className="empty">No flow records received in the last hour.</div>
      ) : (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {rows.map((t) => (
            <span key={t.flow_type} className="badge accent-badge" title={`${t.exporters} exporter(s)`}>
              {String(t.flow_type).toUpperCase()}: {fmtNum(t.flows)} flows · {t.exporters} exporters
            </span>
          ))}
        </div>
      )}
    </Panel>
  );
}

const flowsTotal = async () => {
  const r = await api.flowsByType(3600);
  return ((r?.data as any[]) ?? []).reduce((s, t) => s + Number(t.flows || 0), 0);
};
const trapsTotal = async () => {
  const r = await api.searchLogs({ query: "*", signal: "snmptrap", size: 0 });
  return r?.hits?.total?.value ?? 0;
};

// Reachable-vs-configured union for the SNMP collectors (one chart, two series).
const snmpReachQuery = [
  `label_replace(sum(collector_targets_reachable{collector=~"snmp.*"}),"k","reachable","","")`,
  `label_replace(sum(collector_targets{collector=~"snmp.*"}),"k","configured","","")`,
].join(" or ");

// The page carries TWO sections, switched (never stacked) so neither buries the
// other, each reachable as a deep link (#/investigate/troubleshooting?section=…):
//
//  · Investigation (DEFAULT) — the symptom-first operator surface: pick what is
//    wrong, get a verdict header, escalate to TAC from that verdict, then
//    parallel evidence lanes, Iris and a seam-owned handoff. This is the page's
//    reason to exist (Project 4 §A).
//  · Collection pipeline — the old June board (is the PIPELINE or the DEVICE at
//    fault?). Kept reachable for ONE RELEASE while operators migrate; its
//    step-zero insight now lives beside the investigation lanes.
//
// The third section, "Protocol diagnostics", was REMOVED on 2026-09-05
// (docs/design/TAC_ESCALATION_2026-09-05.md §5). Its manual bench — pick a
// protocol, pick an issue, pick a device, press analyze — is replaced by the
// escalation flow that hangs off the verdict, and its issue × command matrix
// became Iris → Knowledge (coverage per vendor dialect). An old deep link to
// it lands on the investigation surface.
export type { TroubleshootSection };

/** Initial section from the hash. Anything unrecognized falls back to the
 *  investigation surface — a deep link never lands on a blank page. */
export function sectionFromHash(hash?: string): TroubleshootSection {
  const h = hash ?? (typeof location !== "undefined" ? location.hash : "");
  return parseInvestigationHash(h).section;
}

export default function Troubleshooting({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  const initial = parseInvestigationHash(typeof location !== "undefined" ? location.hash : "");
  const [section, setSection] = useState<TroubleshootSection>(initial.section);
  return (
    <div className="dm-board">
      {/* Section switch as a toggle-button group (not ARIA tabs: no tabpanel /
          roving-focus wiring, and plain buttons are fully keyboard operable). */}
      <div className="seg-mini" role="group" aria-label="Troubleshooting section">
        <button type="button" aria-pressed={section === "investigate"} className={section === "investigate" ? "on" : ""}
          onClick={() => setSection("investigate")}>Investigation</button>
        <button type="button" aria-pressed={section === "pipeline"} className={section === "pipeline" ? "on" : ""}
          onClick={() => setSection("pipeline")}>Collection pipeline</button>
      </div>

      {section === "investigate" ? (
        <InvestigationPage rangeMinutes={m} initialSymptom={initial.symptom} initialCaseId={initial.caseId} />
      ) : (
      <>
      <p className="mini-meta" style={{ margin: 0 }}>
        This is the legacy collection-pipeline board. It answers one question — is the PIPELINE or the DEVICE at
        fault — and stays reachable for one release; day-to-day troubleshooting now starts on Investigation.
      </p>

      <Group title="Fleet counts" hue="#3B82F6">
        <StatStrip>
          <MetricStat label="Monitored devices" query='max(collector_targets{collector="snmpmetrics"}) or vector(0)' minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
          <MetricStat label="Reachable (SNMP)" query='sum(collector_targets_reachable{collector=~"snmp.*"}) or vector(0)' minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "bad")} />
          <CountStat label="Flows indexed (1h)" loader={flowsTotal} tone={(n) => (n > 0 ? "good" : "warn")} />
          <CountStat label="SNMP traps (1h)" loader={trapsTotal} />
        </StatStrip>
        <p className="mini-meta" style={{ margin: 0 }}>
          When monitored &gt; 0 but reachable = 0, the collector is healthy and the devices are unreachable (creds / ACL / device down) — not a pipeline failure.
        </p>
      </Group>

      <Group title="Collectors" hue="#22C55E">
        <div className="dm-grid">
          <MetricLine title="Reachable targets by collector" query="collector_targets_reachable" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["collector"]} stepped />
          <MetricLine title="Poll duration by collector (ms)" query="collector_poll_duration_ms" minutes={m} fmtY={(n) => `${n.toFixed(0)} ms`} labelKeys={["collector"]} />
          <MetricTop title="Configured targets by collector" query="collector_targets" minutes={m} fmtX={(n) => `${n.toFixed(0)}`} labelKeys={["collector"]} />
          <MetricLine title="Samples emitted per poll" query="collector_samples" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["collector"]} />
        </div>
      </Group>

      <Group title="SNMP reachability" hue="#F59E0B">
        <MetricLine title="SNMP reachable vs configured" query={snmpReachQuery} minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["k"]} stepped />
      </Group>

      <Group title="NetFlow pipeline" hue="#8B5CF6">
        <FlowSources />
        <p className="mini-meta" style={{ margin: 0 }}>
          Flow records are aggregated exporter-side; a difference between exported and indexed counts is expected. Full per-dimension analysis lives in the Flows dashboard.
        </p>
      </Group>

      <Group title="Traps" hue="#EC4899">
        <Panel title="SNMP traps received (1h)">
          <StatStrip>
            <CountStat label="Traps stored" loader={trapsTotal} />
          </StatStrip>
          <p className="mini-meta" style={{ margin: 0 }}>Browse individual traps in Logs → Log Explorer (SNMP traps signal).</p>
        </Panel>
      </Group>
      </>
      )}
    </div>
  );
}
