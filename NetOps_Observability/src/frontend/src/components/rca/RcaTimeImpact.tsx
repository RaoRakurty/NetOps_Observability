// RcaTimeImpact — the "Time Impact" card for the RCA detail window (RCA Time
// Intelligence). It breaks one incident's clock apart in two zones: what Correlix has
// PROVEN/inferred (detect → correlate → root/seam ISOLATION (MTTI, the hero) → owner →
// evidence) and the WORKFLOW & RECOVERY lifecycle that requires ITSM/recovery evidence.
//
// State model: each phase is observed | inferred | completed | not_measured | pending |
// current. A "measurement gap" (workflow not connected) is NOT a bottleneck — Correlix
// finished RCA; the downstream steps just aren't observable yet, so they read
// "Not measured", never "Workflow required" (which would imply the NOC failed).

import { fmtDateTime } from "../../lib/time";
import { useEffect, useState } from "react";
import { api, type TimeIntel, type Bottleneck, type TimeIntelLifecycleRow } from "../../services/api";

type PhaseKey =
  | "detected" | "correlated" | "root_isolated" | "owner_assigned" | "evidence_bundle_ready"
  | "ticket_created" | "acknowledged" | "mitigated" | "service_recovered" | "ticket_closed";
type PhaseStatus = "observed" | "inferred" | "current" | "not_measured" | "pending";

type Phase = { key: PhaseKey; event: string; label: string; pending: string; star?: boolean; workflow?: boolean };
// RCA-evidence zone (proven/inferred by Correlix) + Workflow & recovery zone (needs evidence).
const RCA_ZONE: Phase[] = [
  { key: "detected", event: "detected", label: "Detected", pending: "Awaiting detection" },
  { key: "correlated", event: "correlation_completed", label: "Correlated", pending: "Awaiting correlation" },
  { key: "root_isolated", event: "root_domain_identified", label: "Root / seam isolated", pending: "Awaiting root isolation", star: true },
  { key: "owner_assigned", event: "owner_identified", label: "Owner assigned", pending: "Awaiting owner assignment" },
  { key: "evidence_bundle_ready", event: "evidence_ready", label: "Evidence bundle ready", pending: "Awaiting evidence bundle" },
];
const WF_ZONE: Phase[] = [
  { key: "ticket_created", event: "ticket_created", label: "Ticket created", pending: "Awaiting ticket creation", workflow: true },
  { key: "acknowledged", event: "acknowledged", label: "Acknowledged", pending: "Awaiting acknowledgement", workflow: true },
  { key: "mitigated", event: "mitigated", label: "Mitigated", pending: "Awaiting mitigation", workflow: true },
  { key: "service_recovered", event: "recovered", label: "Service recovered", pending: "Awaiting recovery signal", workflow: true },
  { key: "ticket_closed", event: "ticket_closed", label: "Ticket closed", pending: "Awaiting ticket closure", workflow: true },
];

const BOTTLENECK_PHASE: Partial<Record<Bottleneck, PhaseKey>> = {
  root_isolation: "root_isolated", owner_assignment: "owner_assigned", evidence_bundle: "evidence_bundle_ready",
  ticket_creation: "ticket_created", acknowledgement: "acknowledged",
  provider_repair: "mitigated", mitigation: "mitigated", recovery: "service_recovered", closure: "ticket_closed",
};
// Real bottleneck labels (only used when there's a measured delay, not a measurement gap).
const BOTTLENECK_LABEL: Record<Bottleneck, string> = {
  resolved: "Resolved", detection: "Detection pending", correlation: "Correlation pending",
  root_isolation: "Root domain isolation pending", owner_assignment: "Owner assignment pending",
  evidence_bundle: "Evidence bundle pending", ticket_creation: "Ticket creation delayed",
  acknowledgement: "Acknowledgement delayed", provider_repair: "Provider repair pending",
  mitigation: "Mitigation delayed", recovery: "Recovery delayed", closure: "Ticket closure delayed",
  workflow_not_connected: "ITSM / recovery workflow not connected", unknown: "—",
};

const STAGE_TIPS: Record<string, string> = {
  impact: "Incident impact onset. May be inferred from the earliest customer-impacting signal.",
  first_signal: "First observable signal associated with this incident.",
  detected: "Incident detected by Correlix.", correlated: "Related signals grouped into one incident.",
  root_isolated: "Likely root domain/seam isolated with evidence.", owner: "Responsible owner domain assigned.",
  evidence: "Evidence package ready for workflow/escalation.", ticket: "ITSM/provider ticket created.",
  acknowledged: "Owner/provider acknowledged the ticket.", mitigated: "Mitigation action recorded.",
  recovered: "Service recovery signal observed.", ticket_closed: "Ticket/workflow closed.",
};
const TIMELINE: { key: string; label: string; tip: string; hero?: boolean }[] = [
  { key: "impact", label: "Impact", tip: STAGE_TIPS.impact },
  { key: "first_signal", label: "First signal", tip: STAGE_TIPS.first_signal },
  { key: "detected", label: "Detected", tip: STAGE_TIPS.detected },
  { key: "correlation_completed", label: "Correlated", tip: STAGE_TIPS.correlated },
  { key: "root_domain_identified", label: "Isolated", tip: STAGE_TIPS.root_isolated, hero: true },
  { key: "owner_identified", label: "Owner", tip: STAGE_TIPS.owner },
  { key: "evidence_ready", label: "Evidence", tip: STAGE_TIPS.evidence },
  { key: "ticket_created", label: "Ticket", tip: STAGE_TIPS.ticket },
  { key: "acknowledged", label: "Ack", tip: STAGE_TIPS.acknowledged },
  { key: "mitigated", label: "Mitigated", tip: STAGE_TIPS.mitigated },
  { key: "recovered", label: "Recovered", tip: STAGE_TIPS.recovered },
  { key: "closed", label: "Closed", tip: STAGE_TIPS.ticket_closed },
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
const confidenceWord = (tier: string) => tier === "confirmed" ? "Confirmed" : tier === "suspected" ? "Suspected" : "Inferred";
// Grounded seam type → operator display (the WHERE of the fault).
const SEAM_LABEL: Record<string, string> = {
  DIA: "DIA", SDWAN: "SD-WAN", "SD-WAN": "SD-WAN", VPN: "VPN", DX: "Direct Connect",
  EXPRESSROUTE: "ExpressRoute", INTERCONNECT: "Interconnect", CLOUD_BACKBONE: "Cloud backbone",
  LAN: "LAN", WAN: "WAN", DC: "Data center", CLOUD: "Cloud",
};
const seamLabel = (t?: string) => (t ? (SEAM_LABEL[t.toUpperCase()] ?? t) : "");

export default function RcaTimeImpact({ correlationId }: { correlationId: string }) {
  const [d, setD] = useState<TimeIntel | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setD(null); setErr("");
    if (!correlationId) return;
    api.correlationTimeMetrics(correlationId).then((r) => { if (alive) setD(r); }).catch(() => { if (alive) setErr("unavailable"); });
    return () => { alive = false; };
  }, [correlationId]);

  if (err) return <div className="ti-card ti-empty" role="status">Time Impact unavailable.</div>;
  if (!d) return <div className="ti-card ti-empty" role="status">Loading time impact…</div>;

  const at = new Map<string, TimeIntelLifecycleRow>(d.lifecycle.map((l) => [l.event_type, l]));
  const impact = at.get("impact_started") ?? at.get("first_signal");
  const impactInferred = !at.get("impact_started");
  const impactMs = impact ? Date.parse(impact.at) : NaN;

  // A "measurement gap" = the downstream workflow is not OBSERVABLE (not connected),
  // NOT a process bottleneck. Only call it a bottleneck for a real RCA/measured delay.
  const measurementGap = d.current_bottleneck === "workflow_not_connected";
  const currentPhase = measurementGap ? undefined : BOTTLENECK_PHASE[d.current_bottleneck];
  const elapsedTo = (ev: string): number | null => {
    const r = at.get(ev); return r && !Number.isNaN(impactMs) ? Date.parse(r.at) - impactMs : null;
  };
  const isoMs = elapsedTo("root_domain_identified");

  // Data-driven outcome line.
  const outcome = (() => {
    if (isoMs == null) return "RCA is correlating evidence toward root-domain isolation.";
    const isoStr = fmtElapsed(isoMs);
    const recMs = elapsedTo("recovered"), closeMs = elapsedTo("closed");
    if (recMs != null || closeMs != null) {
      const parts = [`RCA isolated the root domain in ${isoStr}.`];
      if (recMs != null) parts.push(`Service recovery completed in ${fmtElapsed(recMs)}.`);
      if (closeMs != null) parts.push(`Ticket closed in ${fmtElapsed(closeMs)}.`);
      return parts.join(" ");
    }
    return `RCA completed through root-domain isolation in ${isoStr}. Recovery and ticket-closure timing are not measured because workflow evidence is not connected.`;
  })();

  function Row({ p }: { p: Phase }) {
    const ev = at.get(p.event);
    const isCurrent = currentPhase === p.key;
    const elapsed = ev && !Number.isNaN(impactMs) ? Date.parse(ev.at) - impactMs : null;
    const status: PhaseStatus = ev ? (ev.timestamp_source === "inferred" ? "inferred" : "observed")
      : p.workflow && !d!.workflow_connected ? "not_measured" : isCurrent ? "current" : "pending";
    return (
      <div className={`ti-row${p.star ? " ti-row-star" : ""}${status === "current" ? " ti-row-current" : ""}${status === "not_measured" ? " ti-row-nm" : ""}`}>
        <span className="ti-row-label">
          {p.star && <span className="ti-star" aria-hidden="true">★</span>}{p.label}
          {p.star && ev && <span className="ti-row-ctx">{[
            d!.seam_type && `Seam: ${seamLabel(d!.seam_type)}`,
            d!.owner_label && `Owner: ${d!.owner_label}`,
            `${confidenceWord(d!.verdict_tier)} · evidence bundle ready`,
          ].filter(Boolean).join(" · ")}</span>}
          {p.key === "owner_assigned" && ev && (
            <span className="ti-row-ctx" title="Owner was inferred from root-domain, seam ownership, and supporting evidence. No external workflow assignment observed.">
              {ev.timestamp_source === "inferred" ? "Inferred · Source: Correlix RCA" : "Assigned · Source: workflow"}
            </span>
          )}
        </span>
        {ev ? (
          <span className="ti-row-val">{elapsed != null ? fmtElapsed(elapsed) : "—"}
            {ev.timestamp_source === "inferred" && <span className="ti-src ti-src-inferred" title="Derived (e.g. impact onset from the first observable signal).">Inferred</span>}</span>
        ) : status === "not_measured" ? (
          <span className="ti-row-val ti-row-na"><span className="ti-src-muted" title="ITSM / recovery workflow evidence not connected.">Not measured</span></span>
        ) : (
          <span className={`ti-row-val ti-row-na${isCurrent ? " ti-na-current" : ""}`}><span className="ti-pending">{p.pending}</span></span>
        )}
      </div>
    );
  }

  return (
    <div className="ti-card">
      <div className="ti-head">
        <span className="ti-title">Time Impact</span>
        <span className="ti-sub">Incident time decomposition</span>
      </div>

      {/* Data-driven outcome line — separates the investigation clock from the repair clock. */}
      <div className="ti-outcome">{outcome}</div>

      {/* Current measurement gap (workflow unobservable) vs real bottleneck (measured delay). */}
      <div className={`ti-driver ${measurementGap ? "ti-tone-slate" : d.current_bottleneck === "resolved" ? "ti-tone-good" : "ti-tone-amber"}`}>
        <span className="ti-driver-tag">{measurementGap ? "Current measurement gap" : "Current bottleneck"}</span>
        <span className="ti-driver-name">{BOTTLENECK_LABEL[d.current_bottleneck]}</span>
        <span className="ti-driver-expl">
          {measurementGap
            ? "RCA evidence is ready. Ticket creation, acknowledgement, mitigation, service recovery and closure timing require ServiceNow, Jira, PagerDuty, or Correlix operator workflow evidence."
            : d.bottleneck_message}
        </span>
      </div>

      <div className="ti-basis" title="Elapsed time is measured from the earliest observed or inferred customer-impacting signal in this RCA group.">
        Elapsed from first impact signal{impactInferred && <span className="ti-onset-badge">Inferred onset</span>}
      </div>

      {/* Zone 1 — RCA evidence timeline (proven/inferred by Correlix). */}
      <div className="ti-zone-label">RCA evidence timeline</div>
      <div className="ti-rows">{RCA_ZONE.map((p) => <Row key={p.key} p={p} />)}</div>

      {/* Zone 2 — workflow & recovery lifecycle (requires ITSM/recovery evidence). */}
      <div className="ti-zone-label ti-zone-wf">Workflow &amp; recovery timeline</div>
      <div className="ti-rows">{WF_ZONE.map((p) => <Row key={p.key} p={p} />)}</div>

      {/* Operational CTA when the workflow is unmeasured (not salesy). */}
      {measurementGap && (
        <div className="ti-cta">Connect ITSM or enable Correlix operator workflow to measure recovery and closure timing.</div>
      )}

      {/* Milestone rail: green observed · purple isolation · gray-hollow not measured. */}
      <div className="ti-timeline" aria-label="Incident lifecycle">
        {TIMELINE.map((st) => {
          const row = at.get(st.key);
          const reached = !!row || (st.key === "impact" && !!impact);
          const wfStage = ["ticket_created", "acknowledged", "mitigated", "recovered", "closed"].includes(st.key);
          const notMeasured = !reached && wfStage && !d.workflow_connected;
          const cls = reached ? "on" : notMeasured ? "nm" : "";
          return (
            <div key={st.key} className={`ti-stage ${cls}${st.hero ? " ti-stage-hero" : ""}`}
              title={`${st.label} — ${st.tip}${row ? ` · ${fmtDateTime(row.at)}${row.timestamp_source !== "observed" ? ` (${row.timestamp_source})` : ""}` : notMeasured ? " · not measured (workflow not connected)" : reached ? "" : " · not reached"}`}>
              <span className="ti-dot" aria-hidden="true" />
              <span className="ti-stage-label">
                {st.label}
                {/* State is color-coded on the dot (1.4.1) and detailed only in
                    the title tooltip (1.4.13) — mirror it as SR-readable text. */}
                <span className="sr-only">
                  {row ? ` — ${fmtDateTime(row.at)}` : notMeasured ? " — not measured" : reached ? "" : " — not reached"}
                </span>
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
