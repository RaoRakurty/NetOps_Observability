// RcaTimeImpact — the "Time Impact" card for the RCA detail window (RCA Time
// Intelligence). It breaks one incident's clock apart and shows WHERE the time went:
// detection → correlation → root/seam ISOLATION (MTTI, the hero) → owner → evidence
// → ticket → ack → mitigate → recover → close, plus the CURRENT BOTTLENECK.
//
// Phase-consistent: the bottleneck is the earliest INCOMPLETE phase (backend walk),
// so it never says "provider repair pending" while evidence/ticket are still open.
// Honesty: inferred timestamps are chipped; ITSM/recovery phases with no workflow
// read "Workflow required" / natural pending text — never a bare dash, never fabricated.

import { useEffect, useState } from "react";
import { api, type TimeIntel, type Bottleneck, type TimeIntelLifecycleRow } from "../../services/api";

// ── phase rows (spec order). Each maps to a backend lifecycle event_type. ──
type PhaseKey =
  | "detected" | "correlated" | "root_isolated" | "owner_assigned" | "evidence_bundle_ready"
  | "ticket_created" | "acknowledged" | "mitigated" | "service_recovered" | "ticket_closed";
const PHASES: { key: PhaseKey; event: string; label: string; pending: string; star?: boolean; workflow?: boolean }[] = [
  { key: "detected", event: "detected", label: "Detected", pending: "Awaiting detection" },
  { key: "correlated", event: "correlation_completed", label: "Correlated", pending: "Awaiting correlation" },
  { key: "root_isolated", event: "root_domain_identified", label: "Root / seam isolated", pending: "Awaiting root isolation", star: true },
  { key: "owner_assigned", event: "owner_identified", label: "Owner assigned", pending: "Awaiting owner assignment" },
  { key: "evidence_bundle_ready", event: "evidence_ready", label: "Evidence bundle ready", pending: "Awaiting evidence bundle" },
  { key: "ticket_created", event: "ticket_created", label: "Ticket created", pending: "Awaiting ticket creation", workflow: true },
  { key: "acknowledged", event: "acknowledged", label: "Acknowledged", pending: "Awaiting acknowledgement", workflow: true },
  { key: "mitigated", event: "mitigated", label: "Mitigated", pending: "Awaiting mitigation", workflow: true },
  { key: "service_recovered", event: "recovered", label: "Service recovered", pending: "Awaiting recovery signal", workflow: true },
  { key: "ticket_closed", event: "closed", label: "Ticket closed", pending: "Awaiting ticket closure", workflow: true },
];

// the lifecycle phase each current-bottleneck value points at (for "current" highlight)
const BOTTLENECK_PHASE: Partial<Record<Bottleneck, PhaseKey>> = {
  root_isolation: "root_isolated", owner_assignment: "owner_assigned", evidence_bundle: "evidence_bundle_ready",
  ticket_creation: "ticket_created", workflow_not_connected: "ticket_created", acknowledgement: "acknowledged",
  provider_repair: "mitigated", mitigation: "mitigated", recovery: "service_recovered", closure: "ticket_closed",
};
const BOTTLENECK_LABEL: Record<Bottleneck, string> = {
  resolved: "Resolved", detection: "Detection pending", correlation: "Correlation pending",
  root_isolation: "Root domain isolation pending", owner_assignment: "Owner assignment pending",
  evidence_bundle: "Evidence bundle pending", ticket_creation: "Ticket creation pending",
  acknowledgement: "Provider acknowledgement pending", provider_repair: "Provider repair pending",
  mitigation: "Mitigation pending", recovery: "Recovery validation pending", closure: "Ticket closure pending",
  workflow_not_connected: "Workflow not connected", unknown: "—",
};
// banner tone: amber = operator-controllable delay; slate = external/workflow; green = resolved.
const BOTTLENECK_TONE: Record<Bottleneck, "amber" | "slate" | "good"> = {
  resolved: "good", detection: "amber", correlation: "amber", root_isolation: "amber",
  owner_assignment: "amber", evidence_bundle: "amber", ticket_creation: "amber", acknowledgement: "slate",
  provider_repair: "slate", mitigation: "amber", recovery: "amber", closure: "slate",
  workflow_not_connected: "slate", unknown: "slate",
};

const STAGE_TIPS: Record<string, string> = {
  impact: "Incident impact onset. May be inferred if no direct impact signal exists.",
  first_signal: "First observable signal associated with this incident.",
  detected: "Incident detected by Correlix.",
  correlated: "Related signals grouped into one incident.",
  root_isolated: "Likely root domain/seam isolated with evidence.",
  owner: "Responsible owner domain assigned.",
  evidence: "Evidence package ready for workflow/escalation.",
  ticket: "ITSM/provider ticket created.",
  acknowledged: "Owner/provider acknowledged the ticket.",
  mitigated: "Mitigation action recorded.",
  recovered: "Service recovery signal observed.",
  ticket_closed: "Ticket/workflow closed.",
};
// bottom timeline (consistent terminology with the rows)
const TIMELINE: { key: string; label: string; tip: string }[] = [
  { key: "impact", label: "Impact", tip: STAGE_TIPS.impact },
  { key: "first_signal", label: "First signal", tip: STAGE_TIPS.first_signal },
  { key: "detected", label: "Detected", tip: STAGE_TIPS.detected },
  { key: "correlation_completed", label: "Correlated", tip: STAGE_TIPS.correlated },
  { key: "root_domain_identified", label: "Root isolated", tip: STAGE_TIPS.root_isolated },
  { key: "owner_identified", label: "Owner", tip: STAGE_TIPS.owner },
  { key: "evidence_ready", label: "Evidence bundle", tip: STAGE_TIPS.evidence },
  { key: "ticket_created", label: "Ticket", tip: STAGE_TIPS.ticket },
  { key: "acknowledged", label: "Acknowledged", tip: STAGE_TIPS.acknowledged },
  { key: "mitigated", label: "Mitigated", tip: STAGE_TIPS.mitigated },
  { key: "recovered", label: "Service recovered", tip: STAGE_TIPS.recovered },
  { key: "closed", label: "Ticket closed", tip: STAGE_TIPS.ticket_closed },
];

function fmtElapsed(ms: number): string {
  if (ms < 1000) return `${Math.max(0, ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s - m * 60);
  if (m < 60) return rem ? `${m}m ${String(rem).padStart(2, "0")}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m - h * 60}m`;
}

export default function RcaTimeImpact({ correlationId }: { correlationId: string }) {
  const [d, setD] = useState<TimeIntel | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setD(null); setErr("");
    if (!correlationId) return;
    api.correlationTimeMetrics(correlationId)
      .then((r) => { if (alive) setD(r); })
      .catch(() => { if (alive) setErr("unavailable"); });
    return () => { alive = false; };
  }, [correlationId]);

  if (err) return <div className="ti-card ti-empty">Time Impact unavailable.</div>;
  if (!d) return <div className="ti-card ti-empty">Loading time impact…</div>;

  const at = new Map<string, TimeIntelLifecycleRow>(d.lifecycle.map((l) => [l.event_type, l]));
  // Impact onset anchor: impact_started if present, else first_signal (inferred).
  const impact = at.get("impact_started") ?? at.get("first_signal");
  const impactInferred = !at.get("impact_started");
  const impactMs = impact ? Date.parse(impact.at) : NaN;
  const currentPhase = BOTTLENECK_PHASE[d.current_bottleneck];
  const tone = BOTTLENECK_TONE[d.current_bottleneck];

  // Identical-timestamp honesty: the engine grounds correlation+isolation+owner+
  // evidence in ONE persist, so those elapsed times legitimately coincide.
  const groundedSameUpdate = ["correlation_completed", "root_domain_identified", "owner_identified"]
    .map((e) => at.get(e)?.at).filter(Boolean);
  const sameUpdate = groundedSameUpdate.length >= 2 && new Set(groundedSameUpdate).size === 1;

  return (
    <div className="ti-card">
      <div className="ti-head">
        <span className="ti-title">Time Impact</span>
        <span className="ti-sub">Incident time decomposition</span>
      </div>

      {/* CURRENT BOTTLENECK — phase-consistent, precise, non-marketing. */}
      <div className={`ti-driver ti-tone-${tone}`}>
        <span className="ti-driver-tag">Current bottleneck</span>
        <span className="ti-driver-name">{BOTTLENECK_LABEL[d.current_bottleneck]}</span>
        <span className="ti-driver-expl">{d.bottleneck_message}</span>
      </div>

      <div className="ti-basis" title="Impact onset may be inferred from the first observable signal and correlation window. Inferred timestamps are marked explicitly.">
        Elapsed from {impactInferred ? "inferred " : ""}impact onset
      </div>

      <div className="ti-rows">
        {PHASES.map((p) => {
          const ev = at.get(p.event);
          const isCurrent = currentPhase === p.key;
          const elapsed = ev && !Number.isNaN(impactMs) ? Date.parse(ev.at) - impactMs : null;
          return (
            <div key={p.key} className={`ti-row${p.star ? " ti-row-star" : ""}${isCurrent ? " ti-row-current" : ""}`}>
              <span className="ti-row-label">
                {p.star && <span className="ti-star" aria-hidden="true">★</span>}{p.label}
                {/* Root-isolated context: owner + evidence confidence (the MTTI proof). */}
                {p.star && ev && (d.owner_label || d.confidence_label) && (
                  <span className="ti-row-ctx">{[d.owner_label && `${d.owner_label}-owned`, d.confidence_label].filter(Boolean).join(" · ")}</span>
                )}
              </span>
              {ev ? (
                <span className="ti-row-val" title={sameUpdate && ["correlated", "root_isolated", "owner_assigned"].includes(p.key) ? "Correlation, isolation and owner assignment were completed by the same evidence update." : undefined}>
                  {elapsed != null ? fmtElapsed(elapsed) : "—"}
                  {ev.timestamp_source === "inferred" && <span className="ti-src ti-src-inferred" title="Derived (e.g. impact onset from the first observable signal).">Inferred</span>}
                </span>
              ) : (
                <span className={`ti-row-val ti-row-na${isCurrent ? " ti-na-current" : ""}`}>
                  {p.workflow && !d.workflow_connected
                    ? <span className="ti-src-muted" title="Requires ServiceNow, Jira, PagerDuty, or operator workflow evidence.">Workflow required</span>
                    : <span className="ti-pending">{p.pending}</span>}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Lifecycle timeline — consistent labels; current bottleneck stage = amber. */}
      <div className="ti-timeline" aria-label="Incident lifecycle">
        {TIMELINE.map((st) => {
          const reached = !!at.get(st.key) || (st.key === "impact" && !!impact);
          const isCurrentStage = currentPhase && BOTTLENECK_PHASE[d.current_bottleneck] &&
            PHASES.find((p) => p.key === currentPhase)?.event === st.key;
          const row = at.get(st.key);
          const cls = reached ? "on" : isCurrentStage ? "current" : "";
          return (
            <div key={st.key} className={`ti-stage ${cls}${st.key === "root_domain_identified" ? " ti-stage-hero" : ""}`}
              title={`${st.label} — ${st.tip}${row ? ` · ${new Date(row.at).toLocaleString()}${row.timestamp_source !== "observed" ? ` (${row.timestamp_source})` : ""}` : reached ? "" : " · not reached"}`}>
              <span className="ti-dot" aria-hidden="true" />
              <span className="ti-stage-label">{st.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
