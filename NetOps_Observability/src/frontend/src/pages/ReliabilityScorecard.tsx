// ReliabilityScorecard — the executive "Operational Recovery Scorecard" for RCA Time
// Intelligence (#84). Decomposes incident time across the fleet: phase percentiles
// (MTTI emphasised — the differentiator), trends, MTBF, repeat rate, top time-loss
// phase, and the chronic offenders that keep failing. Honest: percentile-first (not
// vanity averages), surfaces the scan cap + the internal-stack-included caveat.

import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import {
  api, type ReliabilityRollupResp, type ReliabilityTrendsResp, type ChronicOffender, type ReliabilityQuery,
} from "../services/api";
import { StatStrip, Stat, Segmented, InfoTip } from "../components/ui";

function fmtDur(ms: number): string {
  if (!ms || ms < 0) return "—";
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = s / 60;
  if (m < 60) return `${Math.floor(m)}m ${Math.round(s - Math.floor(m) * 60)}s`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

const DRIVER_LABEL: Record<string, string> = {
  detection: "Detection", correlation: "Correlation & isolation", evidence_missing: "Evidence readiness",
  ownership: "Owner identification", acknowledgement: "Acknowledgement", mitigation: "Mitigation",
  provider_repair: "Provider repair", unknown: "—",
};

const WINDOWS = [
  { value: "604800", label: "7d" },
  { value: "2592000", label: "30d" },
  { value: "7776000", label: "90d" },
];
const OWNERS = ["", "customer", "isp", "cloud_provider", "saas", "carrier"];

export default function ReliabilityScorecard() {
  const [since, setSince] = useState("2592000");
  const [owner, setOwner] = useState("");
  const [rollup, setRollup] = useState<ReliabilityRollupResp | null>(null);
  const [trends, setTrends] = useState<ReliabilityTrendsResp | null>(null);
  const [offenders, setOffenders] = useState<ChronicOffender[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setErr(""); setRollup(null);
    const f: ReliabilityQuery = owner ? { owner } : {};
    const sinceN = Number(since);
    const bucket = sinceN <= 604800 ? 86400 : sinceN <= 2592000 ? 604800 : 1209600; // day / week / fortnight
    Promise.all([
      api.reliabilityRollups(sinceN, f),
      api.reliabilityTrends(sinceN, bucket, f),
      api.reliabilityChronicOffenders(sinceN, 10, f),
    ]).then(([ro, tr, ch]) => {
      if (!alive) return;
      setRollup(ro); setTrends(tr); setOffenders(ch.offenders ?? []);
    }).catch(() => { if (alive) setErr("Reliability data unavailable."); });
    return () => { alive = false; };
  }, [since, owner]);

  const r = rollup?.rollup;
  const metric = (name: string) => r?.metrics?.[name];

  const trendOption = useMemo(() => {
    const buckets = trends?.buckets ?? [];
    const x = buckets.map((b) => b.bucket_start.slice(0, 10));
    const series = (name: string, field: "p50_ms" | "p90_ms") =>
      buckets.map((b) => { const m = b.metrics?.[name]; return m ? Math.round(m[field] / 1000) : null; });
    return {
      grid: { left: 8, right: 12, top: 30, bottom: 22, containLabel: true },
      tooltip: { trigger: "axis", valueFormatter: (v: number) => (v == null ? "—" : `${v}s`) },
      legend: { top: 0, textStyle: { color: "var(--fg-muted)", fontSize: 11 } },
      xAxis: { type: "category", data: x, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
      yAxis: { type: "value", name: "seconds", nameTextStyle: { color: "var(--fg-subtle)", fontSize: 10 }, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
      series: [
        { name: "MTTI p50", type: "line", smooth: true, data: series("tti", "p50_ms"), itemStyle: { color: "#6d5dfc" }, lineStyle: { width: 2 } },
        { name: "MTTI p90", type: "line", smooth: true, data: series("tti", "p90_ms"), itemStyle: { color: "#a99bff" }, lineStyle: { width: 1, type: "dashed" } },
        { name: "MTTR-Recovery p50", type: "line", smooth: true, data: series("ttr_recovery", "p50_ms"), itemStyle: { color: "#30a46c" }, lineStyle: { width: 2 } },
      ],
    };
  }, [trends]);

  return (
    <div className="page rsc">
      <div className="rsc-head">
        <div>
          <h1 className="rsc-title">Operational Recovery Scorecard</h1>
          <p className="rsc-sub">Where incident time is spent across the fleet — percentile-based, not vanity averages.
            <InfoTip label="about"> MTTI (time-to-isolate) is Correlix's differentiator: time until the likely root domain / seam / owner is identified with evidence-backed confidence. </InfoTip>
          </p>
        </div>
        <div className="rsc-filters">
          <Segmented value={since} onChange={setSince} options={WINDOWS} />
          <select className="rsc-select" value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Owner filter">
            {OWNERS.map((o) => <option key={o} value={o}>{o ? o.replace(/_/g, " ") : "all owners"}</option>)}
          </select>
        </div>
      </div>

      {err && <div className="rsc-empty">{err}</div>}

      {r && (
        <>
          <StatStrip>
            <Stat label="Incidents" value={r.incident_count} />
            <Stat label="MTTI p50 · isolate" value={fmtDur(metric("tti")?.p50_ms ?? 0)} tone="accent" />
            <Stat label="MTTI p90" value={fmtDur(metric("tti")?.p90_ms ?? 0)} tone="accent" />
            <Stat label="MTTC p50 · correlate" value={fmtDur(metric("ttc")?.p50_ms ?? 0)} />
            <Stat label="MTTR-Recovery p50" value={fmtDur(metric("ttr_recovery")?.p50_ms ?? 0)} />
            <Stat label="MTTR-Resolution p50" value={fmtDur(metric("ttr_resolution")?.p50_ms ?? 0)} />
            <Stat label="MTBF" value={fmtDur(r.mtbf_ms)} />
            <Stat label="Repeat rate" value={`${Math.round(r.repeat_incident_rate * 100)}%`} tone={r.repeat_incident_rate > 0.3 ? "warn" : ""} />
            <Stat label="Top time-loss phase" value={DRIVER_LABEL[r.top_time_loss_phase] ?? r.top_time_loss_phase} tone="warn" />
          </StatStrip>

          <div className="rsc-grid">
            <div className="rsc-panel rsc-chart">
              <div className="rsc-panel-title">Phase trend (p50/p90 over time)</div>
              {(trends?.buckets?.length ?? 0) > 0
                ? <ReactECharts option={trendOption} style={{ height: 260 }} notMerge lazyUpdate />
                : <div className="rsc-empty">Not enough history in this window.</div>}
            </div>

            <div className="rsc-panel">
              <div className="rsc-panel-title">Chronic offenders — what keeps failing</div>
              {offenders.length === 0 ? (
                <div className="rsc-empty">No recurring objects in this window.</div>
              ) : (
                <table className="rsc-table">
                  <thead><tr><th>#</th><th>Object</th><th className="num">Incidents</th><th className="num">MTBF</th></tr></thead>
                  <tbody>
                    {offenders.map((o, i) => (
                      <tr key={o.group_key}>
                        <td className="rsc-rank">{i + 1}</td>
                        <td className="rsc-obj mono" title={o.group_key}>{o.group_key}</td>
                        <td className="num"><b>{o.incident_count}</b></td>
                        <td className="num mono">{fmtDur(o.mtbf_ms)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Honest caveats — never hide truncation or the internal-stack inclusion. */}
          {(rollup?.capped || rollup?.note) && (
            <div className="rsc-note">
              {rollup?.capped && <span>⚠ Window exceeds the 5,000-incident scan cap — figures reflect the most recent 5,000. </span>}
              {rollup?.note && <span>{rollup.note}.</span>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
