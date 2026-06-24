// ReliabilityScorecard — the enterprise "NOC Recovery Scorecard" for RCA Time
// Intelligence (#84). Answers, for a NOC/operator/exec: how many customer-impacting
// incidents, how fast we ISOLATE the root domain (MTTI — the hero), where the time
// goes, which owner domain owns the pain, which objects keep failing, and what to do
// next. Customer-impacting by default (internal/platform self-monitoring excluded
// unless toggled). Percentile-first; honest about unavailable / workflow-dependent
// metrics; never "Correlix cut MTTR 80%".

import { useEffect, useMemo, useState, type ReactNode } from "react";
import ReactECharts from "echarts-for-react";
import {
  api, type ReliabilityRollupResp, type ChronicOffender, type OwnerDomainStat, type ReliabilityQuery,
} from "../services/api";
import { Segmented, InfoTip } from "../components/ui";
import { fmtDur, delayLabel, recommendedAction, offenderDisplay, DOMAIN_TONE } from "./reliabilityMeta";

const WINDOWS = [{ value: "604800", label: "7d" }, { value: "2592000", label: "30d" }, { value: "7776000", label: "90d" }];
const OWNERS = ["", "isp", "cloud_provider", "saas", "app_team", "netops"];
const OWNER_LABEL: Record<string, string> = { "": "all owners", isp: "ISP", cloud_provider: "Cloud", saas: "SaaS", app_team: "App", netops: "LAN / Network" };

type CardTone = "hero" | "amber" | "good" | "muted" | "";
function Card({ label, sub, value, tone = "", tip, unavailable }: {
  label: string; sub: string; value: ReactNode; tone?: CardTone; tip: string; unavailable?: string;
}) {
  return (
    <div className={`rsc-card rsc-card-${unavailable ? "muted" : tone}`}>
      <div className="rsc-card-label">{label}<InfoTip label="i">{tip}</InfoTip></div>
      <div className="rsc-card-val">{unavailable ? <span className="rsc-card-na">{unavailable}</span> : value}</div>
      <div className="rsc-card-sub">{sub}</div>
    </div>
  );
}

export default function ReliabilityScorecard() {
  const [since, setSince] = useState("2592000");
  const [owner, setOwner] = useState("");
  const [includeInternal, setIncludeInternal] = useState(false);
  const [data, setData] = useState<ReliabilityRollupResp | null>(null);
  const [trend, setTrend] = useState<{ x: string[]; tti50: (number | null)[]; tti90: (number | null)[] } | null>(null);
  const [offenders, setOffenders] = useState<ChronicOffender[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setErr(""); setData(null);
    const f: ReliabilityQuery = { ...(owner ? { owner } : {}), include_internal: includeInternal };
    const sinceN = Number(since);
    const bucket = sinceN <= 604800 ? 86400 : sinceN <= 2592000 ? 604800 : 1209600;
    Promise.all([
      api.reliabilityRollups(sinceN, f),
      api.reliabilityTrends(sinceN, bucket, f),
      api.reliabilityChronicOffenders(sinceN, 10, f),
    ]).then(([ro, tr, ch]) => {
      if (!alive) return;
      setData(ro);
      setTrend({
        x: tr.buckets.map((b) => b.bucket_start.slice(0, 10)),
        tti50: tr.buckets.map((b) => { const m = b.metrics?.tti; return m ? Math.round(m.p50_ms / 1000) : null; }),
        tti90: tr.buckets.map((b) => { const m = b.metrics?.tti; return m ? Math.round(m.p90_ms / 1000) : null; }),
      });
      setOffenders(ch.offenders ?? []);
    }).catch(() => { if (alive) setErr("Reliability data unavailable."); });
    return () => { alive = false; };
  }, [since, owner, includeInternal]);

  const r = data?.rollup;
  const m = (name: string) => r?.metrics?.[name];
  const windowLabel = since === "604800" ? "7-day" : since === "7776000" ? "90-day" : "30-day";
  const topDomain = useMemo(() => {
    const list = (data?.by_owner_domain ?? []).filter((d) => d.domain !== "Internal Platform");
    return list.slice().sort((a, b) => b.incident_count - a.incident_count)[0];
  }, [data]);

  // Lifecycle Time Breakdown (p50/p90 by phase). Detect is per-incident only (excluded
  // from rollups), so the fleet breakdown starts at Correlate.
  const breakdownOption = useMemo(() => {
    const phases = [["ttc", "Correlate"], ["tti", "Isolate"], ["ttr_recovery", "Recover"], ["ttr_resolution", "Resolve"]];
    const p50 = phases.map(([k]) => { const s = m(k); return s ? Math.round(s.p50_ms / 1000) : null; });
    const p90 = phases.map(([k]) => { const s = m(k); return s ? Math.round(s.p90_ms / 1000) : null; });
    return {
      grid: { left: 8, right: 12, top: 30, bottom: 20, containLabel: true },
      tooltip: { trigger: "axis", valueFormatter: (v: number) => (v == null ? "no data" : `${v}s`) },
      legend: { top: 0, textStyle: { color: "var(--fg-muted)", fontSize: 11 } },
      xAxis: { type: "category", data: phases.map(([, l]) => l), axisLabel: { color: "var(--fg-muted)", fontSize: 11 } },
      yAxis: { type: "value", name: "seconds", nameTextStyle: { color: "var(--fg-subtle)", fontSize: 10 }, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
      series: [
        { name: "p50 (normal)", type: "bar", data: p50, itemStyle: { color: "#6d5dfc", borderRadius: [3, 3, 0, 0] } },
        { name: "p90 (long tail)", type: "bar", data: p90, itemStyle: { color: "#c4bbff", borderRadius: [3, 3, 0, 0] } },
      ],
    };
  }, [data]);

  return (
    <div className="page rsc">
      <div className="rsc-head">
        <div>
          <h1 className="rsc-title">NOC Recovery Scorecard</h1>
          <p className="rsc-sub">Where incident time is spent — detection, correlation, isolation, recovery, and repeat failures.
            <InfoTip label="MTTI"> MTTI (Mean Time to Isolate) is Correlix's hero metric: time from the first correlated signal to an evidence-backed root domain, seam, and owner. It is not a universal standard — it's what shrinks the NOC investigation window. </InfoTip>
          </p>
        </div>
        <div className="rsc-filters">
          <Segmented value={since} onChange={setSince} options={WINDOWS} ariaLabel="Window" />
          <select className="rsc-select" value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Owner filter">
            {OWNERS.map((o) => <option key={o} value={o}>{OWNER_LABEL[o]}</option>)}
          </select>
          <label className="rsc-toggle" title="Internal/platform self-monitoring is excluded by default.">
            <input type="checkbox" checked={includeInternal} onChange={(e) => setIncludeInternal(e.target.checked)} />
            Include internal/platform events
          </label>
        </div>
      </div>

      {err && <div className="rsc-empty">{err}</div>}

      {r && (
        <>
          {/* Executive insight strip — data-driven, graceful when values are unavailable. */}
          <div className="rsc-exec">
            <b>{windowLabel} summary:</b> {r.incident_count.toLocaleString()} customer-impacting incident{r.incident_count === 1 ? "" : "s"} analyzed.
            {m("tti") ? <> Median root-domain isolation was <b>{fmtDur(m("tti")!.p50_ms)}</b>; P90 isolation was <b>{fmtDur(m("tti")!.p90_ms)}</b>.</> : " Isolation timing is pending more isolated incidents."}
            {" "}Top delay driver was <b>{delayLabel(r.top_time_loss_phase)}</b>.
            {topDomain && <> <b>{topDomain.domain}</b> drove the most incidents.</>}
            {!m("ttr_recovery") && " Recovery timing is unavailable until recovery evidence is connected."}
          </div>

          {/* Stat cards — hero emphasis on MTTI / P90 / delay / repeat rate. */}
          <div className="rsc-cards">
            <Card label="Customer Incidents" sub="in selected window" value={r.incident_count.toLocaleString()} tip="Customer-impacting incidents in the selected window. Internal/platform self-monitoring is excluded unless explicitly included." />
            <Card label="Median Time to Isolate" sub="MTTI p50" tone="hero" value={fmtDur(m("tti")?.p50_ms)} unavailable={m("tti") ? undefined : "Not enough isolated incidents"} tip="Median time to evidence-backed root domain, seam, or owner isolation." />
            <Card label="P90 Isolation Time" sub="MTTI p90" tone="hero" value={fmtDur(m("tti")?.p90_ms)} unavailable={m("tti") ? undefined : "Not enough isolated incidents"} tip="90% of incidents were isolated within this time. This exposes long-tail NOC pain." />
            <Card label="Median Time to Correlate" sub="MTTC p50" value={fmtDur(m("ttc")?.p50_ms)} tip="Median time from first signal to grouping related signals into one correlated incident." />
            <Card label="Median Time to Recover Service" sub="Recovery p50" value={fmtDur(m("ttr_recovery")?.p50_ms)} unavailable={m("ttr_recovery") ? undefined : "No recovery evidence"} tip="Median time until service health recovered. Requires a recovery signal or workflow evidence." />
            <Card label="Median Time to Close Ticket" sub="Resolution p50" value={fmtDur(m("ttr_resolution")?.p50_ms)} unavailable={m("ttr_resolution") ? undefined : "Workflow required"} tip="Median time until ticket/workflow closure. Requires ServiceNow, Jira, PagerDuty, or operator workflow timestamps." />
            <Card label="Time Between Repeat Failures" sub="MTBF" value={fmtDur(r.mtbf_ms)} unavailable={r.mtbf_ms > 0 ? undefined : "No repeats yet"} tip="Average time between repeat failures for the same object or pattern." />
            <Card label="Recurring Incident Rate" sub="Repeat rate" tone={r.repeat_incident_rate > 0.3 ? "amber" : "hero"} value={`${Math.round(r.repeat_incident_rate * 100)}%`} tip="Percentage of incidents matching a recurring object, signature, or failure pattern." />
            <Card label="Top Delay Driver" sub="Top time-loss phase" tone="amber" value={delayLabel(r.top_time_loss_phase)} tip="The lifecycle phase causing the most accumulated operational delay." />
          </div>

          {/* Owner Domain Breakdown — is this ours, the provider's, the cloud's, the app team's? */}
          <div className="rsc-panel">
            <div className="rsc-panel-title">Owner Domain Breakdown — who owns the pain</div>
            <table className="rsc-table">
              <thead><tr><th>Owner Domain</th><th className="num">Incidents</th><th className="num">MTTI p90</th><th className="num">Recovery p90</th><th className="num">Recurring</th><th>Top Delay Driver</th></tr></thead>
              <tbody>
                {(data!.by_owner_domain ?? []).map((b: OwnerDomainStat) => (
                  <tr key={b.domain} className={owner && OWNER_LABEL[owner] !== b.domain ? "rsc-row-dim" : ""}>
                    <td><span className={`rsc-dom rsc-dom-${DOMAIN_TONE[b.domain] ?? "unknown"}`}>{b.domain}</span></td>
                    <td className="num"><b>{b.incident_count}</b></td>
                    <td className="num mono">{fmtDur(b.mtti_p90_ms)}</td>
                    <td className="num mono">{b.recovery_p90_ms ? fmtDur(b.recovery_p90_ms) : <span className="rsc-na-sm">no signal</span>}</td>
                    <td className="num">{Math.round(b.repeat_incident_rate * 100)}%</td>
                    <td>{delayLabel(b.top_delay_driver)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {owner === "isp" && <div className="rsc-hint">Provider-owned incidents are useful for carrier escalation and SLA / vendor review.</div>}
          </div>

          <div className="rsc-grid">
            <div className="rsc-panel rsc-chart">
              <div className="rsc-panel-title">Lifecycle Time Breakdown — where did the time go (p50 vs p90)</div>
              {m("tti") || m("ttc")
                ? <ReactECharts option={breakdownOption} style={{ height: 240 }} notMerge lazyUpdate />
                : <div className="rsc-empty">Not enough isolated incidents in this window. Expand to 90d, or include more incidents.</div>}
            </div>

            <div className="rsc-panel">
              <div className="rsc-panel-title">Chronic Offenders — what keeps failing</div>
              {offenders.length === 0 ? (
                <div className="rsc-empty">No recurring objects in this window.</div>
              ) : (
                <table className="rsc-table rsc-offenders">
                  <thead><tr><th>#</th><th>Object</th><th>Owner</th><th className="num">Incidents</th><th className="num">MTBF</th><th>Recommended Action</th></tr></thead>
                  <tbody>
                    {offenders.map((o, i) => {
                      const disp = offenderDisplay(o.group_key);
                      return (
                        <tr key={o.group_key}>
                          <td className="rsc-rank">{i + 1}</td>
                          <td><div className="rsc-obj-name">{disp.display}</div><div className="rsc-obj-raw mono" title={disp.secondary}>{disp.secondary}</div></td>
                          <td><span className={`rsc-dom rsc-dom-${DOMAIN_TONE[o.owner_domain] ?? "unknown"}`}>{o.owner_domain}</span></td>
                          <td className="num"><b>{o.incident_count}</b></td>
                          <td className="num mono">{fmtDur(o.mtbf_ms)}</td>
                          <td className="rsc-action">{recommendedAction(o.owner_domain)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* MTTI trend — clearer, with an honest empty state. */}
          <div className="rsc-panel rsc-chart">
            <div className="rsc-panel-title">Isolation trend — MTTI p50 / p90 over time</div>
            {(trend?.x.length ?? 0) > 1 ? (
              <ReactECharts style={{ height: 200 }} notMerge lazyUpdate option={{
                grid: { left: 8, right: 12, top: 28, bottom: 22, containLabel: true },
                tooltip: { trigger: "axis", valueFormatter: (v: number) => (v == null ? "—" : `${v}s`) },
                legend: { top: 0, textStyle: { color: "var(--fg-muted)", fontSize: 11 } },
                xAxis: { type: "category", data: trend!.x, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
                yAxis: { type: "value", name: "seconds", nameTextStyle: { color: "var(--fg-subtle)", fontSize: 10 }, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
                series: [
                  { name: "MTTI p50", type: "line", smooth: true, data: trend!.tti50, itemStyle: { color: "#6d5dfc" }, lineStyle: { width: 2 } },
                  { name: "MTTI p90", type: "line", smooth: true, data: trend!.tti90, itemStyle: { color: "#a99bff" }, lineStyle: { width: 1, type: "dashed" } },
                ],
              }} />
            ) : <div className="rsc-empty">Not enough historical buckets to show a trend. Expand to 90d or ingest more incidents.</div>}
          </div>

          {/* Honest, enterprise-worded footnote (info, not a warning). */}
          <div className="rsc-note">
            Showing {includeInternal ? "all events including internal/platform self-monitoring" : "customer-impacting incidents only"}.
            {!includeInternal && " Internal/platform events can be included explicitly."}
            {data!.capped && ` Large windows use the most recent ${data!.scan_cap.toLocaleString()} incidents.`}
            {" "}This dashboard separates the investigation clock from the repair clock: how fast incidents were detected, correlated, and isolated — then where recovery or resolution is waiting on owner action, provider repair, or workflow evidence.
          </div>
        </>
      )}
    </div>
  );
}
