// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ExperienceIncidentView.tsx — one experience incident.
//
// The owner's Phase F information architecture, in this exact order:
//
//   HEADER → IMPACT → EXPERIENCE PATH → TIMELINE → HYPOTHESES → CHANGES →
//   EVIDENCE → ACTION → VERIFY
//
// The order is the argument. Impact says who is hurt, the path says where, the
// timeline says when, the hypotheses say what is suspected, the changes say
// what we did to ourselves, the evidence says why any of that is believed, the
// action says what to do and the verification says whether it worked. Moving
// ACTION above EVIDENCE would let an operator act on a claim they have not seen
// the grounds for, which is the whole failure mode this layout is against.
//
// Four reads, one per resource the server publishes: the packet, its evidence,
// its timeline and its path reference. The path is a REFERENCE — the ordered
// spine belongs to the service path graph and is never reconstructed here from
// the evidence, because a path assembled out of what happened to be measured is
// a drawing, not an observation.

import { useState } from "react";

import { api } from "../../services/api";
import type {
  DemCohort, DemEvidenceItem, DemHypothesis, DemIncidentEvidenceResponse,
  DemIncidentPathResponse, DemIncidentResponse, DemIncidentTimelineResponse, DemWindow,
} from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { ownerLabel, seamTypeLabel } from "../../components/rca/labels";
import { AiInvestigatorPanel } from "./ai";
import { SeamRibbon } from "./ribbon";
import { TimelineScrubber, buildEntries } from "./scrubber";
import {
  ConfidenceChip, Loading, LoadError, Money, NotMeasured, Panel, ProvenanceChip,
  SeverityChip, fmtDuration, pct, reasonText,
} from "./honest";
import { useDemRead } from "./state";
import AskIris from "../../components/AskIris";

type EvidenceFilter = "all" | "supporting" | "contradicting" | "missing";

const FILTERS: { key: EvidenceFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "supporting", label: "Supporting" },
  { key: "contradicting", label: "Contradicting" },
  { key: "missing", label: "Missing" },
];

export default function ExperienceIncidentView({ id, window: win, onBack }: {
  id: string;
  window: DemWindow;
  onBack: () => void;
}) {
  const packet = useDemRead<DemIncidentResponse>(() => api.demIncident(id, win), [id, win]);
  const evidence = useDemRead<DemIncidentEvidenceResponse>(
    () => api.demIncidentEvidence(id, win), [id, win]);
  const timeline = useDemRead<DemIncidentTimelineResponse>(
    () => api.demIncidentTimeline(id, win), [id, win]);
  const path = useDemRead<DemIncidentPathResponse>(() => api.demIncidentPath(id, win), [id, win]);
  const [filter, setFilter] = useState<EvidenceFilter>("all");
  // Promotion (tracker 255): the one WRITE on this screen. A derived incident
  // has no owner and no lifecycle until an operator says it is real; the button
  // is the act, and the reload is what makes the linkage appear where the
  // header already reports it.
  const [promoting, setPromoting] = useState(false);
  const [promoteError, setPromoteError] = useState("");

  if (packet.status === "loading") return <Loading what="the incident" />;
  if (packet.status === "error" || !packet.data) {
    return (
      <div className="dx-section">
        <div className="dx-actions">
          <button type="button" className="btn" onClick={onBack}>Back to incidents</button>
        </div>
        <LoadError what="The incident" error={packet.error} onRetry={packet.reload} />
      </div>
    );
  }

  const inc = packet.data.incident;
  const leading = inc.hypotheses?.find((h) => h.id === inc.leading_hypothesis_id);
  const layer = layerForCause(leading?.cause_class);

  return (
    <div className="dx-section">
      <div className="dx-actions">
        <button type="button" className="btn" onClick={onBack}>Back to incidents</button>
      </div>

      {/* ── HEADER ── */}
      <Panel title={inc.title} label="Incident header"
        actions={
          <>
            {!inc.promoted && packet.data.can_promote && (
              <button type="button" className="btn" disabled={promoting}
                title="Raise this as a platform incident with the experience evidence class"
                onClick={() => {
                  setPromoting(true);
                  setPromoteError("");
                  api.demPromoteIncident(id, win)
                    .then(() => packet.reload())
                    .catch((e: unknown) => setPromoteError(e instanceof Error ? e.message : String(e)))
                    .finally(() => setPromoting(false));
                }}>
                {promoting ? "Promoting…" : "Promote"}
              </button>
            )}
            <SeverityChip severity={inc.severity} />
          </>
        }>
        <div className="dx-cards">
          <div className="dx-card" role="group" aria-label="Status">
            <span className="dx-card-label">Status</span>
            <span className="dx-card-value" style={{ fontSize: "var(--fs-md)" }}>{inc.status}</span>
            <span className="dx-cap">
              {promoteError
                ? promoteError
                : inc.promoted
                  ? `Promoted incident ${inc.incident_id}`
                  : "Not promoted to a durable incident record"}
            </span>
          </div>
          <div className="dx-card" role="group" aria-label="Started">
            <span className="dx-card-label">Started</span>
            <span className="dx-card-value" style={{ fontSize: "var(--fs-md)" }}>
              {fmtDateTime(inc.first_impact_at)}
            </span>
            <span className="dx-cap">detected {fmtDateTime(inc.detected_at)}</span>
          </div>
          <div className="dx-card" role="group" aria-label="Impacted users">
            <span className="dx-card-label">Impacted users</span>
            {inc.impact.users === undefined
              ? <NotMeasured reason="not_configured"
                  detail="Nothing counts affected people for this incident. That is not the same as nobody being affected." />
              : <span className="dx-card-value">{inc.impact.users}</span>}
          </div>
          <div className="dx-card" role="group" aria-label="Business impact">
            <span className="dx-card-label">Business impact</span>
            <span className="dx-card-value" style={{ fontSize: "var(--fs-md)" }}>
              <Money value={inc.impact.business_value_lost} currency={inc.impact.currency} />
            </span>
          </div>
          <div className="dx-card" role="group" aria-label="Leading hypothesis and confidence">
            <span className="dx-card-label">Leading hypothesis</span>
            <span className="dx-cap">
              {leading?.explanation || "No cause has enough evidence yet."}
            </span>
            <ConfidenceChip confidence={inc.confidence} tier={inc.verdict_tier}
              factors={leading?.confidence_factors} gateReasons={leading?.gate_reasons} />
          </div>
          <div className="dx-card" role="group" aria-label="Owner">
            <span className="dx-card-label">Owner</span>
            <span className="dx-card-value" style={{ fontSize: "var(--fs-md)" }}>
              {inc.owner ? (ownerLabel(inc.owner) || inc.owner) : "Not determined"}
            </span>
            <span className="dx-cap">
              {inc.seam ? `${seamTypeLabel(inc.seam) || inc.seam} handoff` : "No owning handoff identified"}
            </span>
          </div>
        </div>
      </Panel>

      {/* ── IMPACT ── */}
      <Panel title="Impact" label="Incident impact">
        <div className="dx-src-grid">
          <ImpactStat label="Journey success" value={inc.impact.journey_success_pct}
            before={inc.impact.journey_success_before} unit="%" />
          <ImpactStat label="Error rate" value={inc.impact.error_pct} unit="%" />
          <ImpactStat label="p95 response" value={inc.impact.p95_ms} unit="ms" />
          <ImpactStat label="Sessions" value={inc.impact.sessions} />
          <ImpactStat label="Transactions" value={inc.impact.transactions} />
        </div>
        {inc.impact.not_measured && inc.impact.not_measured.length > 0 && (
          <p className="dx-note">
            Not measured for this incident: <b>{inc.impact.not_measured.join(", ")}</b>. These are
            absent measurements, not zeroes.
          </p>
        )}
        <div className="dx-src-grid">
          <section className="dx-src" aria-label="Affected population">
            <h3 className="dx-h3">Affected</h3>
            <CohortList cohorts={inc.impact.affected_cohorts}
              empty="No affected population could be described." />
            <p className="dx-cap">
              {[
                inc.affected_apps?.length ? `${inc.affected_apps.join(", ")}` : "",
                inc.affected_sites?.length ? `sites: ${inc.affected_sites.join(", ")}` : "",
              ].filter(Boolean).join(" · ")}
            </p>
          </section>
          <section className="dx-src" aria-label="Unaffected population">
            <h3 className="dx-h3">Unaffected</h3>
            <CohortList cohorts={inc.impact.unaffected_cohorts}
              empty="No unaffected population could be described, so nothing here rules a change out." />
          </section>
        </div>
      </Panel>

      {/* ── EXPERIENCE PATH ── */}
      <Panel title="Experience path" label="Experience path">
        <SeamRibbon layer={layer} seam={inc.seam} owner={inc.owner ? ownerLabel(inc.owner) || inc.owner : ""}
          cause={leading?.explanation} label="Seam ribbon" />
        <PathReference res={path.data} status={path.status} error={path.error} onRetry={path.reload} />
      </Panel>

      {/* ── TIMELINE ── */}
      <Panel title="Timeline" label="Incident timeline">
        {timeline.status === "loading" && <Loading what="the timeline" />}
        {timeline.status === "error" && (
          <LoadError what="The timeline" error={timeline.error} onRetry={timeline.reload} />
        )}
        {timeline.status === "ready" && timeline.data && (
          <TimelineScrubber
            entries={buildEntries(timeline.data.timeline, timeline.data.changes)}
            start={inc.window?.start} end={inc.window?.end} />
        )}
      </Panel>

      {/* ── HYPOTHESES ── */}
      <Panel title="Hypotheses" label="Incident hypotheses">
        {(inc.hypotheses ?? []).length === 0 ? (
          <p className="dx-note">
            No cause proposed.<AskIris topic="dem.no-cause-proposed" label="no proposed cause" />
          </p>
        ) : (
          <div className="dx-section">
            {inc.hypotheses.map((h) => (
              <HypothesisCard key={h.id} h={h} leading={h.id === inc.leading_hypothesis_id} />
            ))}
          </div>
        )}
      </Panel>

      {/* ── CHANGES ── */}
      <Panel title="Changes" label="Changes ranked against this incident">
        {(inc.changes ?? []).length === 0 ? (
          <p className="dx-note">
            No change bears on this incident.<AskIris topic="dem.unwired-producers" label="an empty change list" />
          </p>
        ) : (
          <div className="dx-scroll">
            <table className="dx-table">
              <thead>
                <tr>
                  <th scope="col">Relevance</th><th scope="col">When</th>
                  <th scope="col">Change</th><th scope="col">Why it is ranked here</th>
                </tr>
              </thead>
              <tbody>
                {inc.changes!.map((c) => (
                  <tr key={c.change.id}>
                    <td className="dx-mono">{(c.score * 100).toFixed(0)}%</td>
                    <td className="dx-mono">{fmtDateTime(c.change.provenance?.event_at)}</td>
                    <td>
                      <b>{c.change.summary}</b>
                      <div className="dx-cap">{c.change.type.replace(/_/g, " ").toLowerCase()} · {c.change.object}</div>
                    </td>
                    <td>
                      <ul className="dx-conf-factors">
                        {c.reasons.map((r, i) => <li key={i}>{r}</li>)}
                      </ul>
                      {!c.precedes_impact && (
                        <span className="dx-chip">after first impact — cannot be a cause</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* ── EVIDENCE ── */}
      <Panel title="Evidence" label="Incident evidence"
        actions={
          <div className="dx-ev-filters" role="group" aria-label="Evidence filter">
            {FILTERS.map((f) => (
              <button key={f.key} type="button"
                className={`dx-tab${filter === f.key ? " is-active" : ""}`}
                aria-pressed={filter === f.key}
                onClick={() => setFilter(f.key)}>{f.label}</button>
            ))}
          </div>
        }>
        {evidence.status === "loading" && <Loading what="the evidence" />}
        {evidence.status === "error" && (
          <LoadError what="The evidence" error={evidence.error} onRetry={evidence.reload} />
        )}
        {evidence.status === "ready" && evidence.data && (
          <EvidenceList data={evidence.data} filter={filter} />
        )}
      </Panel>

      {/* ── ACTION ── */}
      <Panel title="Action" label="Recommended actions">
        {(inc.recommended_actions ?? []).length === 0 ? (
          <p className="dx-note">
            Nothing recommended.<AskIris topic="dem.no-action-recommended" label="no recommended action" />
          </p>
        ) : (
          <div className="dx-section">
            {inc.recommended_actions!.map((a) => (
              <article className="dx-hyp" key={a.id}>
                <div className="dx-hyp-head">
                  <h3 className="dx-h3">{a.summary}</h3>
                  <span className="dx-chip">proposed by {a.proposed_by}</span>
                </div>
                <p className="dx-note">Expected outcome: {a.expected_outcome}</p>
                <p className="dx-cap">
                  Risk {a.risk} · {a.reversible ? "reversible" : "NOT reversible"}
                  {a.rollback_plan ? ` · rollback: ${a.rollback_plan}` : ""}
                </p>
                <p className="dx-cap">
                  Approval {a.approval_state} · execution {a.execution_state}
                </p>
                <p className="dx-note">
                  How it would be verified: {a.verification_plan
                    || "no verification plan — recovery could only be guessed at"}
                </p>
              </article>
            ))}
          </div>
        )}
      </Panel>

      {/* ── VERIFY ── */}
      <Panel title="Verify" label="Recovery verification">
        <p className={inc.verification?.recovered ? "dx-note" : "dx-error"} role="note">
          <b>
            {!inc.verification?.attempted
              ? "Not verified yet."
              : inc.verification.recovered
                ? "Recovered — the evidence agrees."
                : "Not recovered."}
          </b>
          {" "}{inc.verification?.detail}
        </p>
        <p className="dx-cap">
          Action done is not recovery.<AskIris topic="dem.action-vs-recovery" label="verified recovery" />
        </p>
        {(inc.verification?.checks ?? []).length > 0 && (
          <div className="dx-scroll">
            <table className="dx-table">
              <thead>
                <tr>
                  <th scope="col">Check</th><th scope="col">Source</th>
                  <th scope="col">Result</th><th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {inc.verification.checks!.map((c) => (
                  <tr key={c.name}>
                    <td>{c.name}</td>
                    <td>{c.source}</td>
                    <td>
                      {!c.measured
                        ? <NotMeasured compact detail={c.detail} />
                        : c.passed ? "passed" : "failed"}
                    </td>
                    <td className="dx-cap">{c.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <AiInvestigatorPanel availability={packet.data.ai_investigator} subject={inc.title} />
      {!packet.data.evidence_packet_available && (
        <p className="dx-cap">
          No briefing<AskIris topic="dem.briefing-data-class" label="an unavailable briefing" />
        </p>
      )}
      <p className="dx-cap">
        Window {fmtDateTime(inc.window?.start)} → {fmtDateTime(inc.window?.end)}
        {inc.first_impact_at ? ` · running for ${fmtDuration((Date.now() - Date.parse(inc.first_impact_at)) / 1000)}` : ""}
      </p>
    </div>
  );
}

// ── pieces ──────────────────────────────────────────────────────────────────

function ImpactStat({ label, value, before, unit }: {
  label: string; value?: number; before?: number; unit?: string;
}) {
  return (
    <section className="dx-src" aria-label={label}>
      <h3 className="dx-h3">{label}</h3>
      {value === undefined ? (
        <NotMeasured reason="no_samples"
          detail={`Nothing produced ${label.toLowerCase()} for this incident.`} />
      ) : (
        <>
          <span className="dx-mono" style={{ fontSize: "var(--fs-md)" }}>
            {unit === "%" ? pct(value) : `${value.toFixed(unit === "ms" ? 0 : 2)}${unit ?? ""}`}
          </span>
          {before !== undefined && (
            <span className="dx-cap">before the incident: {unit === "%" ? pct(before) : before.toFixed(0)}</span>
          )}
        </>
      )}
    </section>
  );
}

function CohortList({ cohorts, empty }: { cohorts?: DemCohort[]; empty: string }) {
  if (!cohorts || cohorts.length === 0) return <p className="dx-cap">{empty}</p>;
  return (
    <ul className="dx-conf-factors">
      {cohorts.map((c, i) => (
        <li key={i}>
          {Object.entries(c as Record<string, string | undefined>)
            .filter(([, v]) => v)
            .map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`)
            .join(" · ") || "an unlabelled population"}
        </li>
      ))}
    </ul>
  );
}

function PathReference({ res, status, error, onRetry }: {
  res: DemIncidentPathResponse | null;
  status: "loading" | "ready" | "error";
  error: string;
  onRetry: () => void;
}) {
  if (status === "loading") return <Loading what="the path reference" />;
  if (status === "error" || !res) {
    return <LoadError what="The path reference" error={error} onRetry={onRetry} />;
  }
  if (res.measured === false || !res.path_observation_id) {
    // Rendered VERBATIM. The server's sentence is the product here: it says the
    // difference between "no path" and "a clean path", which no icon can.
    return <p className="dx-note" role="note">{res.reason}</p>;
  }
  return (
    <p className="dx-note">
      Path observation <span className="dx-mono">{res.path_observation_id}</span>.
      {" "}{res.note}
    </p>
  );
}

function HypothesisCard({ h, leading }: { h: DemHypothesis; leading: boolean }) {
  return (
    <article className={`dx-hyp${leading ? " dx-hyp--leading" : ""}`}
      aria-label={`Hypothesis: ${h.explanation}`}>
      <div className="dx-hyp-head">
        <h3 className="dx-h3">{h.explanation}</h3>
        <span className={`dx-hyp-state dx-hyp-state--${h.state}`}>{h.state.toLowerCase()}</span>
      </div>
      <p className="dx-cap">
        {h.cause_class.replace(/_/g, " ")}
        {h.cause_entity ? ` · ${h.cause_entity}` : " · no concrete entity named"}
        {h.owner ? ` · ${ownerLabel(h.owner) || h.owner}` : " · owner not determined"}
        {h.blast_radius ? ` · ${h.blast_radius}` : ""}
        {leading ? " · leading" : ""}
      </p>
      <ConfidenceChip confidence={h.confidence} tier={h.verdict_tier}
        factors={h.confidence_factors} gateReasons={h.gate_reasons} />
      <p className="dx-cap">
        {h.independence?.independent_pair?.length
          ? `Two independent observations agree (${h.independence.independent_pair.join(" + ")}).`
          : "No two independent observations agree yet."}
        {" "}
        {h.independence?.modalities?.length
          ? `Kinds of instrument: ${h.independence.modalities.join(", ")}.`
          : ""}
      </p>
      {(h.missing_evidence ?? []).length > 0 && (
        <ul className="dx-gate" aria-label="Missing evidence for this hypothesis">
          {h.missing_evidence!.map((m, i) => (
            <li key={i}>
              {m.source}: {m.detail || reasonText(m.reason)}
              {m.required ? " — its absence blocks confirmation" : ""}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function EvidenceList({ data, filter }: {
  data: DemIncidentEvidenceResponse; filter: EvidenceFilter;
}) {
  const items = data.evidence ?? [];
  const missing = data.missing_evidence ?? [];

  if (filter === "missing") {
    if (missing.length === 0) {
      return (
        <p className="dx-note">
          Nothing recorded as missing.<AskIris topic="dem.nothing-missing" label="nothing recorded as missing" />
        </p>
      );
    }
    return (
      <ul className="dx-ev">
        {missing.map((m, i) => (
          <li className="dx-ev-item dx-ev-item--neutral" key={i}>
            <span className="dx-ev-summary">{m.source}</span>
            <span className="dx-ev-meta">
              <span>{m.independence_group || "kind of instrument not recorded"}</span>
              <span>{m.required ? "required for confirmation" : "not required"}</span>
            </span>
            <span className="dx-nm-why">{m.detail || reasonText(m.reason)}</span>
          </li>
        ))}
      </ul>
    );
  }

  const shown = items.filter((e) =>
    filter === "all" ? true
      : filter === "supporting" ? e.stance === "supports"
        : e.stance === "contradicts");

  if (shown.length === 0) {
    return (
      <p className="dx-note">
        No observation of this kind.
        {missing.length > 0 && ` ${missing.length} source(s) not reporting.`}
      </p>
    );
  }
  return (
    <ul className="dx-ev">
      {shown.map((e) => <EvidenceRow key={e.id} e={e} />)}
    </ul>
  );
}

function EvidenceRow({ e }: { e: DemEvidenceItem }) {
  const observation = e.provenance?.observation ?? "unknown";
  const inferred = observation !== "observed";
  return (
    <li className={`dx-ev-item dx-ev-item--${e.stance}${inferred ? " dx-ev-item--inferred" : ""}`}>
      <div className="dx-ev-head">
        <ProvenanceChip observation={observation} />
        <span className="dx-chip">{e.stance}</span>
        {e.decisive && <span className="dx-chip">decisive</span>}
        <span className="dx-ev-summary">{e.summary}</span>
      </div>
      {e.detail && <span className="dx-nm-detail">{e.detail}</span>}
      <div className="dx-ev-meta">
        <span>{e.kind}</span>
        {e.entity && <span>{e.entity_kind || "entity"}: {e.entity}</span>}
        <span>kind of instrument: {e.independence_group}</span>
        <span>observer: {e.observer || "not recorded"}</span>
        <span>reliability {(e.reliability * 100).toFixed(0)}%</span>
        {e.value !== undefined && (
          <span className="dx-mono">
            {e.value}{e.unit ?? ""}
            {e.baseline !== undefined ? ` vs baseline ${e.baseline}${e.unit ?? ""}` : ""}
          </span>
        )}
        <span>{e.provenance?.source}</span>
      </div>
    </li>
  );
}

/** hypothesis cause class → the ribbon layer, mirroring experience.LayerFor.
 *  The list summary carries `likely_layer` already; the packet carries the
 *  cause class, so the mapping is repeated here rather than guessed. */
function layerForCause(cause?: string): string | undefined {
  switch (cause) {
    case "client_endpoint": return "device";
    case "lan_access": return "LAN";
    case "wan_overlay": return "WAN";
    case "last_mile": case "transit_degradation": case "routing_change": return "ISP";
    case "dns_resolution": return "DNS";
    case "tls_termination": case "cloud_edge": case "cloud_policy": return "cloud edge";
    case "application_regression": case "dependency_failure": case "capacity_saturation":
      return "application";
    case "config_change": return "network";
    case "synthetic_artifact": return "measurement";
    default: return undefined;
  }
}
