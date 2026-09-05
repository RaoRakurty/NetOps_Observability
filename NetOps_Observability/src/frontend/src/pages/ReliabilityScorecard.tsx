// ReliabilityScorecard — the enterprise "NOC Recovery Scorecard" for RCA Time
// Intelligence (#84). Answers, for a NOC manager: where is incident time lost, which
// owner domain owns the pain, what evidence is missing, what keeps recurring, and what
// to fix next. Customer-impacting by default; percentile-first; honest about
// unavailable / workflow-dependent metrics — never a fabricated MTTR, never "0 ms".

import { useEffect, useMemo, useState, type ReactNode } from "react";
import ReactECharts from "../components/EChart";
import {
  api, type ReliabilityRollupResp, type ChronicOffender, type OwnerDomainStat, type ReliabilityQuery,
  type IncidentTimeMetricRow,
} from "../services/api";
import { Segmented, InfoTip } from "../components/ui";
import RcaFeedbackTile from "../components/rca/RcaFeedbackTile";
import { chartBase, axisStyle, paletteColor } from "../theme/charts";
import { operatorError } from "../lib/errors";
import {
  fmtDur, delayLabel, recommendedAction, offenderDisplay, DOMAIN_TONE,
  deriveCoverage, recoveryReadiness, COVERAGE_LABEL, COVERAGE_TONE, type CoverageState,
} from "./reliabilityMeta";
import { buildTimeMetricsSeries, METRIC_TTD, METRIC_TTR_RECOVERY } from "./timeMetricsSeries";

const WINDOWS = [{ value: "604800", label: "7d" }, { value: "2592000", label: "30d" }, { value: "7776000", label: "90d" }];
const OWNERS = ["", "isp", "cloud_provider", "saas", "app_team", "netops"];
const OWNER_LABEL: Record<string, string> = { "": "all owners", isp: "ISP", cloud_provider: "Cloud", saas: "SaaS", app_team: "App", netops: "LAN / Network" };

// Bucket width for the selected window — one definition, shared by the server-side
// /reliability/trends read and the client-side phase-snapshot trend, so the two
// charts on this page always carry the same x axis.
function bucketFor(sinceSeconds: number): number {
  return sinceSeconds <= 604800 ? 86400 : sinceSeconds <= 2592000 ? 604800 : 1209600;
}

// The persisted phase-metric snapshots are read newest-first; the endpoint's own
// default is 500 and anything outside 1..cap is refused, so the ask is explicit.
const TIME_METRIC_LIMIT = 500;
// MTTD and MTTR, in the metric names timeintel persists.
const TREND_PHASES = [METRIC_TTD, METRIC_TTR_RECOVERY] as const;

const plural = (n: number, word: string): string => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

type CardTone = "hero" | "amber" | "good" | "muted" | "";
// A card with an explicit unavailable state: the value reads a reason ("Not measured")
// and the subtext explains WHY ("Recovery evidence not connected") in a muted style.
function Card({ label, sub, value, tone = "", tip, unavailable, unavailableSub }: {
  label: string; sub: string; value: ReactNode; tone?: CardTone; tip: string;
  unavailable?: string; unavailableSub?: string;
}) {
  const muted = !!unavailable;
  return (
    <div className={`rsc-card rsc-card-${muted ? "muted" : tone}`}>
      <div className="rsc-card-label">{label}<InfoTip label="i">{tip}</InfoTip></div>
      <div className="rsc-card-val">{muted ? <span className="rsc-card-na">{unavailable}</span> : value}</div>
      <div className="rsc-card-sub">{muted ? (unavailableSub ?? sub) : sub}</div>
    </div>
  );
}

function CoverageChip({ label, state }: { label: string; state: CoverageState }) {
  return (
    <span className="rsc-cov">
      <span className="rsc-cov-label">{label}</span>
      <span className={`rsc-cov-state rsc-cov-${COVERAGE_TONE[state]}`}>{COVERAGE_LABEL[state]}</span>
    </span>
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
  // Persisted phase-metric snapshots — their own state, their own fetch, their own
  // failure. A dead snapshot read must leave the rest of the scorecard standing.
  const [snapshots, setSnapshots] = useState<IncidentTimeMetricRow[] | null>(null);
  const [snapErr, setSnapErr] = useState("");

  useEffect(() => {
    let alive = true;
    setErr(""); setData(null);
    const f: ReliabilityQuery = { ...(owner ? { owner } : {}), include_internal: includeInternal };
    const sinceN = Number(since);
    const bucket = bucketFor(sinceN);
    Promise.all([
      api.reliabilityRollups(sinceN, f),
      api.reliabilityTrends(sinceN, bucket, f),
      api.reliabilityChronicOffenders(sinceN, 10, f),
    ]).then(([ro, tr, ch]) => {
      if (!alive) return;
      setData(ro);
      setTrend({
        x: tr.buckets.map((b) => b.bucket_start.slice(0, 10)),
        tti50: tr.buckets.map((b) => { const mm = b.metrics?.tti; return mm ? Math.round(mm.p50_ms / 1000) : null; }),
        tti90: tr.buckets.map((b) => { const mm = b.metrics?.tti; return mm ? Math.round(mm.p90_ms / 1000) : null; }),
      });
      setOffenders(ch.offenders ?? []);
    }).catch(() => { if (alive) setErr("Reliability data unavailable."); });
    return () => { alive = false; };
  }, [since, owner, includeInternal]);

  // The snapshot series is read once (the route carries no window/owner selector);
  // the window, owner and internal filters are applied to the rows below, using the
  // same controls and the same defaults as the rollup reads above.
  useEffect(() => {
    let alive = true;
    setSnapErr(""); setSnapshots(null);
    api.reliabilityTimeMetrics(TIME_METRIC_LIMIT)
      .then((res) => { if (alive) setSnapshots(res.snapshots ?? []); })
      .catch((e) => { if (alive) setSnapErr(operatorError(e, "Recorded phase timings could not be loaded.")); });
    return () => { alive = false; };
  }, []);

  const r = data?.rollup;
  const m = (name: string) => r?.metrics?.[name];
  const has = (name: string) => { const s = m(name); return !!s && s.p50_ms > 0; };
  const windowLabel = since === "604800" ? "7-day" : since === "7776000" ? "90-day" : "30-day";
  const topDomain = useMemo(() => {
    const list = (data?.by_owner_domain ?? []).filter((d) => d.domain !== "Internal Platform");
    return list.slice().sort((a, b) => b.incident_count - a.incident_count)[0];
  }, [data]);

  // Evidence coverage + Recovery Readiness — both data-driven.
  const coverage = useMemo(() => deriveCoverage({
    ttc: has("ttc"), tti: has("tti"), recovery: has("ttr_recovery"), ticketing: has("ttr_resolution"),
  }), [data]);
  const readiness = useMemo(() => r ? recoveryReadiness({
    repeatRate: r.repeat_incident_rate, topDelay: r.top_time_loss_phase, coverage,
    mttiP90Ms: m("tti")?.p90_ms, offenderCount: offenders.length,
  }) : null, [r, coverage, offenders]);

  const recoveryMissing = coverage.recovery !== "connected";
  const ticketingMissing = coverage.ticketing !== "connected";

  // Lifecycle Time Breakdown (p50/p90 by phase). Detect is per-incident only; the fleet
  // breakdown starts at Correlate. Missing phases render as gaps (not zero bars).
  const breakdownOption = useMemo(() => {
    const phases = [["ttc", "Correlate"], ["tti", "Isolate"], ["ttr_recovery", "Recover"], ["ttr_resolution", "Resolve"]];
    const p50 = phases.map(([k]) => { const s = m(k); return s && s.p50_ms > 0 ? Math.round(s.p50_ms / 1000) : null; });
    const p90 = phases.map(([k]) => { const s = m(k); return s && s.p90_ms > 0 ? Math.round(s.p90_ms / 1000) : null; });
    return {
      grid: { left: 8, right: 12, top: 30, bottom: 20, containLabel: true },
      tooltip: { trigger: "axis", valueFormatter: (v: number) => (v == null ? "not measured" : `${v}s`) },
      legend: { top: 0, textStyle: { color: "var(--fg-muted)", fontSize: 11 } },
      xAxis: { type: "category", data: phases.map(([, l]) => l), axisLabel: { color: "var(--fg-muted)", fontSize: 11 } },
      yAxis: { type: "value", name: "seconds", nameTextStyle: { color: "var(--fg-subtle)", fontSize: 10 }, axisLabel: { color: "var(--fg-muted)", fontSize: 10 } },
      series: [
        { name: "p50 (normal)", type: "bar", data: p50, itemStyle: { color: "#6d5dfc", borderRadius: [3, 3, 0, 0] } },
        { name: "p90 (long tail)", type: "bar", data: p90, itemStyle: { color: "#c4bbff", borderRadius: [3, 3, 0, 0] } },
      ],
    };
  }, [data]);

  // ── Detection & repair trend, from the PERSISTED phase-metric snapshots ──────
  // Same window, same bucket width, same owner and internal-event filters as the
  // rollups above. The central statistic is the MEDIAN (nearest-rank p50, the
  // method the rollup percentiles use), so a point here agrees with the p50 cards.
  const phaseTrend = useMemo(() => buildTimeMetricsSeries({
    snapshots, metrics: TREND_PHASES, windowSeconds: Number(since),
    bucketSeconds: bucketFor(Number(since)), now: Date.now(), includeInternal, owner,
  }), [snapshots, since, includeInternal, owner]);

  const phaseTrendMeasured = phaseTrend.series.some((s) => s.points.some((p) => p !== null));
  const blockerPhrase = phaseTrend.blockers.slice(0, 2)
    .map((b) => `${plural(b.count, "phase")} ${b.text}`).join(" and ");

  const phaseTrendOption = useMemo(() => ({
    ...chartBase,
    grid: { left: 8, right: 12, top: 30, bottom: 20, containLabel: true },
    tooltip: { ...chartBase.tooltip, trigger: "axis", valueFormatter: (v: number | null) => (v == null ? "not measured" : `${v}s`) },
    legend: { ...chartBase.legend, top: 0 },
    xAxis: { type: "category", data: phaseTrend.buckets.map((b) => b.label), ...axisStyle },
    yAxis: { type: "value", name: "seconds (median)", ...axisStyle },
    series: phaseTrend.series.map((s, i) => ({
      name: s.label,
      type: "line",
      smooth: true,
      // A bucket with nothing complete to measure is a GAP, never a joined line:
      // connecting across it would draw a measurement that was never taken.
      connectNulls: false,
      data: s.points.map((p) => (p == null ? null : Math.round(p / 1000))),
      lineStyle: { width: 2, color: paletteColor(i) },
      itemStyle: { color: paletteColor(i) },
    })),
  }), [phaseTrend]);

  return (
    <div className="page rsc">
      <div className="rsc-head">
        <div>
          <div className="rsc-title-row">
            <h1 className="rsc-title">NOC Recovery Scorecard</h1>
            {readiness && (
              <span className={`rsc-readiness rsc-rd-${readiness.state.replace(/\s/g, "").toLowerCase()}`}
                title={`Recovery Readiness ${readiness.score}/100 — a deterministic score from repeat rate, evidence coverage, long-tail isolation, and chronic offenders.`}>
                <span className="rsc-rd-state">Recovery Readiness: {readiness.state}</span>
                <span className="rsc-rd-score">{readiness.score}/100</span>
                <span className="rsc-rd-drag">Primary drag: {readiness.drag}</span>
              </span>
            )}
          </div>
          <p className="rsc-sub">Where incident time is spent — detection, correlation, isolation, recovery, and repeat failures.
            <InfoTip label="MTTI"> MTTI (Mean/Median Time To Isolate) is Correlix's hero metric: time from incident detection to an evidence-backed root domain, seam, and owner. Not a universal standard — it's what shrinks the NOC investigation window. </InfoTip>
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
          {/* Executive insight strip — operational, explicit about missing recovery/ITSM. */}
          <div className="rsc-exec">
            <b>{windowLabel} summary:</b> {r.incident_count.toLocaleString()} customer-impacting incident{r.incident_count === 1 ? "" : "s"} analyzed.
            {has("tti") ? <> Median root-domain isolation was <b>{fmtDur(m("tti")!.p50_ms)}</b>; P90 was <b>{fmtDur(m("tti")!.p90_ms)}</b>.</> : " Isolation timing is pending more isolated incidents."}
            {" "}The largest time-loss driver was <b>{delayLabel(r.top_time_loss_phase)}</b>{topDomain && <>, mostly in <b>{topDomain.domain}</b>-owned incidents</>}.
            {(recoveryMissing || ticketingMissing) && " Recovery and ticket-closure timing are not yet measured because recovery/ITSM evidence is not connected."}
          </div>

          {/* Evidence Coverage strip — explains the unavailable recovery/closure metrics. */}
          <div className="rsc-coverage">
            <span className="rsc-cov-head">Evidence coverage</span>
            <CoverageChip label="Correlation" state={coverage.correlation} />
            <CoverageChip label="Isolation" state={coverage.isolation} />
            <CoverageChip label="Recovery" state={coverage.recovery} />
            <CoverageChip label="ITSM / closure" state={coverage.ticketing} />
          </div>

          {/* Stat cards — hero on MTTI / P90 / delay / repeat; muted on unavailable. */}
          <div className="rsc-cards">
            <Card label="Customer-impacting incidents" sub="in selected window" value={r.incident_count.toLocaleString()} tip="Customer-impacting incidents in the selected window. Internal/platform self-monitoring is excluded unless explicitly included." />
            <Card label="Median root-domain isolation time" sub="MTTI p50" tone="hero" value={fmtDur(m("tti")?.p50_ms)} unavailable={has("tti") ? undefined : "Insufficient evidence"} unavailableSub="Not enough isolated incidents" tip="Median Time To Isolate — time from detection to evidence-backed root-domain/seam/owner isolation. P50 = median (normal case)." />
            <Card label="P90 root-domain isolation time" sub="MTTI p90" tone="hero" value={fmtDur(m("tti")?.p90_ms)} unavailable={has("tti") ? undefined : "Insufficient evidence"} unavailableSub="Not enough isolated incidents" tip="P90 = long-tail isolation; 90% of incidents were isolated faster than this. Exposes the NOC pain that medians hide." />
            <Card label="Median correlation time" sub="MTTC p50" value={fmtDur(m("ttc")?.p50_ms)} unavailable={has("ttc") ? undefined : "Insufficient evidence"} tip="Median Time To Correlate — time to group related signals into one incident. In the current engine correlation and isolation are grounded together, so MTTC tracks closely with isolation." />
            <Card label="Median recovery time" sub="Recovery p50" value={fmtDur(m("ttr_recovery")?.p50_ms)} unavailable={recoveryMissing ? "Not measured" : undefined} unavailableSub="Recovery evidence not connected" tip="Median time until service health recovered. Where no ITSM recovery signal is linked, recovery is engine-inferred — the incident window closed with no further symptoms — and is shown as an approximation, not a measurement. Unavailable only when the window carries neither." />
            <Card label="Median ticket closure time" sub="Resolution p50" value={fmtDur(m("ttr_resolution")?.p50_ms)} unavailable={ticketingMissing ? "Not available" : undefined} unavailableSub="ITSM workflow required" tip="Median time until ticket/workflow closure. Requires ServiceNow, Jira, PagerDuty, or operator workflow timestamps." />
            <Card label="Repeat failure interval" sub="MTBF" value={fmtDur(r.mtbf_ms)} unavailable={r.mtbf_ms > 0 ? undefined : "No repeats yet"} tip="Mean Time Between Failures — average time between repeat incidents for the same object or domain." />
            <Card label="Repeat-affected incidents" sub="Repeat rate" tone={r.repeat_incident_rate > 0.3 ? "amber" : "hero"} value={`${Math.round(r.repeat_incident_rate * 100)}%`} tip="Percentage of incidents associated with an object, path, device, or domain that has failed more than once in this window." />
            <Card label="Top time-loss driver" sub="lifecycle phase" tone="amber" value={delayLabel(r.top_time_loss_phase)} tip="The lifecycle phase causing the most accumulated operational delay across the window." />
          </div>

          {/* Owner Domain Breakdown — where the pain lands. */}
          <div className="rsc-panel">
            <div className="rsc-panel-title">Owner Domain Breakdown — where the pain lands</div>
            <table className="rsc-table">
              <thead><tr><th>Owner domain</th><th className="num">Incidents</th><th className="num">MTTI p90</th><th className="num">Recovery p90</th><th className="num">Repeat</th><th>Top time-loss driver</th></tr></thead>
              <tbody>
                {(data!.by_owner_domain ?? []).map((b: OwnerDomainStat) => (
                  <tr key={b.domain} className={owner && OWNER_LABEL[owner] !== b.domain ? "rsc-row-dim" : ""}>
                    <td><span className={`rsc-dom rsc-dom-${DOMAIN_TONE[b.domain] ?? "unknown"}`}>{b.domain}</span></td>
                    <td className="num"><b>{b.incident_count}</b></td>
                    <td className="num mono">{b.mtti_p90_ms > 0 ? fmtDur(b.mtti_p90_ms) : <span className="rsc-na-sm">No valid sample</span>}</td>
                    <td className="num mono">{b.recovery_p90_ms > 0 ? fmtDur(b.recovery_p90_ms) : <span className="rsc-na-sm">No recovery signal</span>}</td>
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
              <div className="rsc-panel-title">Lifecycle Time Breakdown — where incident time is spent (p50 vs p90)</div>
              {has("tti") || has("ttc")
                ? <>
                    <ReactECharts option={breakdownOption} style={{ height: 240 }} notMerge lazyUpdate />
                    {(recoveryMissing || ticketingMissing) && (
                      <div className="rsc-chart-note">Recovery and ticket-closure timing are unavailable until recovery / ITSM evidence is connected.</div>
                    )}
                  </>
                : <div className="rsc-empty">Not enough isolated incidents in this window. Expand to 90d, or include more incidents.</div>}
            </div>

            <div className="rsc-panel">
              <div className="rsc-panel-title">Recurring Failure Sources — what keeps coming back</div>
              {offenders.length === 0 ? (
                <div className="rsc-empty">No recurring objects in this window.</div>
              ) : (
                <table className="rsc-table rsc-offenders">
                  <thead><tr><th>#</th><th>Object</th><th>Owner</th><th className="num">Incidents</th><th className="num">MTBF</th><th>Recommended action</th></tr></thead>
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
                          <td className="rsc-action">{recommendedAction(o.owner_domain, o.group_key)}</td>
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
                tooltip: { trigger: "axis", valueFormatter: (v: number) => (v == null ? "not measured" : `${v}s`) },
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

      {/* Detection & repair trend — the tenant's RECORDED phase-metric snapshots
          (one per incident, freshest calculation kept). Deliberately outside the
          rollup block: it owns its own read, so neither panel can blank the other.
          An unmeasured bucket is a gap with a stated reason, never a zero. */}
      <div className="rsc-panel rsc-chart">
        <div className="rsc-panel-title">Detection and repair trend — MTTD and MTTR over time (median)</div>
        {snapErr ? (
          <div className="rsc-empty">{snapErr}</div>
        ) : snapshots === null ? (
          <div className="rsc-empty">Loading recorded phase timings…</div>
        ) : phaseTrend.incidentCount === 0 ? (
          <div className="rsc-empty">Nothing recorded in this window yet — phase timings appear once incidents are analyzed.</div>
        ) : !phaseTrendMeasured ? (
          <div className="rsc-empty">
            Not measured in this window: none of the {plural(phaseTrend.incidentCount, "incident")} completed
            a detection or recovery phase{blockerPhrase ? ` — ${blockerPhrase}` : ""}.
          </div>
        ) : (
          <>
            <ReactECharts option={phaseTrendOption} style={{ height: 220 }} notMerge lazyUpdate />
            <div className="rsc-chart-note">
              {phaseTrend.incompleteIncidents === 0
                ? `All ${plural(phaseTrend.incidentCount, "incident")} in this window carry a complete detection and recovery lifecycle.`
                : `${phaseTrend.incompleteIncidents.toLocaleString()} of ${plural(phaseTrend.incidentCount, "incident")} in this window have an incomplete lifecycle${blockerPhrase ? ` — ${blockerPhrase}` : ""}. A break in a line is a period with nothing complete to measure.`}
              {snapshots.length >= TIME_METRIC_LIMIT && ` Based on the ${TIME_METRIC_LIMIT.toLocaleString()} most recent recorded snapshots.`}
            </div>
          </>
        )}
      </div>

      {/* Engine quality (Project 2 P7) — the operator verdict loop. Its own fixed
          30-day window (it measures the engine, not the selected incident
          window) and its own fetch, so a reliability outage never hides it. */}
      <RcaFeedbackTile />
    </div>
  );
}
