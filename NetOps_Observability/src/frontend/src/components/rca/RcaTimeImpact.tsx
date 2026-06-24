// RcaTimeImpact — the "Time Impact" card for the RCA detail window (RCA Time
// Intelligence / Incident Time Decomposition). Shows exactly WHERE this incident's
// time was spent: detection, correlation, root/seam ISOLATION (the differentiator),
// owner identification, evidence readiness, acknowledgement, mitigation, recovery,
// resolution — plus the single "time-loss driver".
//
// Honesty bar (owner): NOT a vanity MTTR number, NEVER "Correlix cut MTTR 80%".
// Inferred/ITSM timestamps are labelled; a phase with no data reads "—" with the
// missing event named — never a fabricated zero. Wording is precise, not marketing
// ("Correlix isolated the likely DIA seam in 1m 24s", not "AI reduced MTTR").

import { useEffect, useState } from "react";
import { api, type TimeIntel, type TimeMetric, type TimeIntelLifecycleRow } from "../../services/api";

// Friendly label per metric; `star` marks MTTI = time-to-isolate (the differentiator).
const METRIC_ROWS: { name: TimeMetric["metric_name"]; label: string; star?: boolean }[] = [
  { name: "ttd", label: "Detected in" },
  { name: "ttc", label: "Correlated in" },
  { name: "tti", label: "Root / seam isolated in", star: true },
  { name: "tte", label: "Evidence ready in" },
  { name: "tta", label: "Acknowledged in" },
  { name: "ttm", label: "Mitigated in" },
  { name: "ttr_recovery", label: "Recovered in" },
  { name: "ttr_resolution", label: "Resolution time" },
];

// Lifecycle stages, in order, for the horizontal timeline.
const LIFECYCLE_STAGES: { key: string; label: string }[] = [
  { key: "impact_started", label: "Impact" },
  { key: "first_signal", label: "First signal" },
  { key: "detected", label: "Detected" },
  { key: "correlation_completed", label: "Correlated" },
  { key: "rca_candidate_generated", label: "RCA candidate" },
  { key: "root_domain_identified", label: "Root isolated" },
  { key: "owner_identified", label: "Owner" },
  { key: "evidence_ready", label: "Evidence" },
  { key: "ticket_created", label: "Ticket" },
  { key: "acknowledged", label: "Acked" },
  { key: "mitigated", label: "Mitigated" },
  { key: "recovered", label: "Recovered" },
  { key: "closed", label: "Closed" },
];

function fmtDur(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s - m * 60);
  if (m < 60) return rem ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m - h * 60}m`;
}

const DRIVER_LABEL: Record<TimeIntel["time_loss_driver"], string> = {
  detection: "Detection", correlation: "Correlation & isolation", evidence_missing: "Evidence readiness",
  ownership: "Owner identification", acknowledgement: "Acknowledgement", mitigation: "Mitigation",
  provider_repair: "Provider repair", unknown: "Unknown",
};

/** Source chip — flags an inferred/ITSM/etc. timestamp so it never reads as ground truth. */
function SourceChip({ src }: { src: TimeMetric }) {
  if (!src.complete) return null;
  if (src.is_inferred) return <span className="ti-src ti-src-inferred" title="At least one endpoint was inferred (e.g. impact onset from the earliest customer-impacting signal)">inferred</span>;
  return null;
}

function MetricRow({ m, label, star }: { m?: TimeMetric; label: string; star?: boolean }) {
  return (
    <div className={`ti-row${star ? " ti-row-star" : ""}`}>
      <span className="ti-row-label">{star && <span className="ti-star" aria-hidden="true">★</span>}{label}</span>
      {m && m.complete ? (
        <span className="ti-row-val">
          {fmtDur(m.duration_ms)}
          {m.confidence < 1 && <span className="ti-conf" title="Confidence">{` ·${Math.round(m.confidence * 100)}%`}</span>}
          {m && <SourceChip src={m} />}
        </span>
      ) : (
        <span className="ti-row-val ti-row-na" title={m?.missing_event ? `Awaiting ${m.missing_event.replace(/_/g, " ")}` : "No data"}>
          — {m?.missing_event ? <span className="ti-missing">awaiting {m.missing_event.replace(/_/g, " ")}</span> : null}
        </span>
      )}
    </div>
  );
}

export default function RcaTimeImpact({ correlationId }: { correlationId: string }) {
  const [data, setData] = useState<TimeIntel | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    let alive = true;
    setData(null); setErr("");
    if (!correlationId) return;
    api.correlationTimeMetrics(correlationId)
      .then((d) => { if (alive) setData(d); })
      .catch(() => { if (alive) setErr("unavailable"); });
    return () => { alive = false; };
  }, [correlationId]);

  if (err) return <div className="ti-card ti-empty">Time Impact unavailable.</div>;
  if (!data) return <div className="ti-card ti-empty">Loading time impact…</div>;

  const byName = new Map(data.metrics.map((m) => [m.metric_name, m]));
  const stageAt = new Map(data.lifecycle.map((l) => [l.event_type, l]));

  return (
    <div className="ti-card">
      <div className="ti-head">
        <span className="ti-title">Time Impact</span>
        <span className="ti-sub">Incident time decomposition</span>
      </div>

      {/* Time-loss driver — the precise, non-marketing headline. */}
      <div className={`ti-driver ti-driver-${data.time_loss_driver}`}>
        <span className="ti-driver-tag">Time-loss driver</span>
        <span className="ti-driver-name">{DRIVER_LABEL[data.time_loss_driver]}</span>
        <span className="ti-driver-expl">{data.time_loss_explanation}</span>
      </div>

      {/* Phase rows. */}
      <div className="ti-rows">
        {METRIC_ROWS.map((r) => <MetricRow key={r.name} m={byName.get(r.name)} label={r.label} star={r.star} />)}
      </div>

      {/* Lifecycle timeline — reached stages light up; pending stay muted. */}
      <div className="ti-timeline" aria-label="Incident lifecycle">
        {LIFECYCLE_STAGES.map((st) => {
          const row: TimeIntelLifecycleRow | undefined = stageAt.get(st.key);
          const reached = !!row;
          return (
            <div key={st.key} className={`ti-stage${reached ? " on" : ""}`}
              title={reached ? `${st.label} · ${new Date(row!.at).toLocaleString()}${row!.timestamp_source !== "observed" ? ` (${row!.timestamp_source})` : ""}` : `${st.label} — not reached`}>
              <span className="ti-dot" aria-hidden="true" />
              <span className="ti-stage-label">{st.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
