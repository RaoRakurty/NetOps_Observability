// InvestigationPage — the symptom-first Troubleshooting surface (Project 4 §A).
//
// The shape, straight from the design of record:
//   symptom entry ("What's wrong?")  →  verdict header  →  parallel evidence
//   lanes  →  IRIS co-pilot  →  seam-owned handoff.
//
// POSITIONING (research §c). RCA is what Correlix CONCLUDED; this page is where
// the operator DRIVES and the platform does the legwork. So the two entry points
// are equal citizens: pick one of the nine canonical NOC workflows, or pick an
// open correlation case. Picking a case shows the SAME six-question RCA header
// the RCA workspace shows for that object (RcaCaseHeader — one definition, not a
// second verdict vocabulary). Picking only a symptom shows an HONEST header:
// there is no correlated verdict, we are bisecting, and the ladder says which
// layers actually have evidence behind them.
//
// REUSE, not re-implementation: buildRcaCase + RcaCaseHeader (verdict), the
// already-deployed lane APIs, the ticket + report endpoints (handoff), the Iris
// ask endpoint (co-pilot).
//
// ESCALATION (2026-09-05, docs/design/TAC_ESCALATION_2026-09-05.md §5). The
// manual protocol-diagnostics bench — pick a protocol, pick an issue, pick a
// device, press analyze — is GONE from this page. Its knowledge moved to Iris →
// Knowledge (coverage per vendor), and its work moved into TacEscalationPanel,
// which hangs directly off the verdict: one "Escalate to TAC" button, then
// class → plan → collect → bundle → case. An escalation is anchored to a
// correlated incident, so the panel renders only when a case is open.

import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import "./investigation.css";
import {
  api,
  RcaNotPromotedError,
  type CorrObject,
  type CorrTimeline,
  type Seam,
  type SeamOwnerEntry,
  type TicketStatus,
} from "../../services/api";
import { ShellContext } from "../../context/shell";
import RcaCaseHeader from "../../components/rca/RcaCaseHeader";
import { buildRcaCase, type RcaCase } from "../../components/rca/rcaCase";
import { friendlyProblemId } from "../../components/rca/labels";
import { exportRcaPdf } from "../../components/rca/rcaExport";
import TacEscalationPanel from "./TacEscalationPanel";
import IrisLane from "./IrisLane";
import { LANE_COMPONENT, type LaneScope } from "./InvestigationLanes";
import { operatorError } from "../../lib/errors";
import { ESCALATION_NEEDS_CASE } from "./tacModel";
import {
  SYMPTOMS,
  bisectingHeadline,
  buildLadder,
  lanesForSymptom,
  symptomById,
  type LaneId,
  type LaneState,
  type SymptomId,
} from "./investigationModel";

/** parseJSON — a remote JSON blob is untrusted input; a bad blob is "absent". */
function parseJSON<T>(raw: string | undefined, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(raw) as T; } catch { return fallback; }
}

/** The first affected device on a case — the scope handed to the lanes. */
export function caseDevice(obj: CorrObject | null): string {
  if (!obj) return "";
  const aff = parseJSON<{ devices?: unknown }>(obj.affected, {});
  const list = Array.isArray(aff.devices) ? aff.devices : [];
  const first = list.find((d) => typeof d === "string" && d.trim() !== "");
  return typeof first === "string" ? first : "";
}

export default function InvestigationPage({ rangeMinutes = 60, initialSymptom = null, initialCaseId = "" }: {
  rangeMinutes?: number;
  initialSymptom?: SymptomId | null;
  initialCaseId?: string;
}) {
  // The shell is optional here on purpose: the page renders (and is tested)
  // outside the app shell, and useShell() would throw. Absent shell = no
  // "Open Iris" control, never a crash.
  const shell = useContext(ShellContext);

  const [symptom, setSymptom] = useState<SymptomId | null>(initialSymptom);
  const [caseId, setCaseId] = useState<string>(initialCaseId);
  const [filter, setFilter] = useState("");

  // Open correlation cases (the active-problem entry point).
  const [cases, setCases] = useState<CorrObject[]>([]);
  const [casesErr, setCasesErr] = useState<string>("");

  // The chosen case, mapped through the SAME adapter the RCA workspace uses.
  const [obj, setObj] = useState<CorrObject | null>(null);
  const [timeline, setTimeline] = useState<CorrTimeline | null>(null);
  const [caseErr, setCaseErr] = useState<string>("");
  const [seams, setSeams] = useState<Record<string, Seam>>({});
  const [seamOwners, setSeamOwners] = useState<Record<string, SeamOwnerEntry>>({});
  const [ticket, setTicket] = useState<TicketStatus | null>(null);
  const [handoffNote, setHandoffNote] = useState("");

  // Lane states feed the ladder — a rung is "answered" only when a lane says so.
  const [laneStates, setLaneStates] = useState<Partial<Record<LaneId, LaneState>>>({});
  const reportLane = useCallback((id: LaneId, state: LaneState) => {
    setLaneStates((s) => (s[id] === state ? s : { ...s, [id]: state }));
  }, []);

  useEffect(() => {
    let alive = true;
    api.correlations(25, 86400, "open")
      .then((r) => { if (alive) { setCases(r?.data ?? []); setCasesErr(""); } })
      .catch((e: unknown) => { if (alive) setCasesErr(operatorError(e, "Open investigations could not be loaded.")); });
    api.seams("active")
      .then((list) => { if (!alive) return; const m: Record<string, Seam> = {}; (list ?? []).forEach((s) => { m[s.seam_id] = s; }); setSeams(m); })
      .catch(() => { /* seam inventory optional — class labels still render */ });
    api.getSeamOwners()
      .then((r) => { if (alive) setSeamOwners(r?.seam_owners ?? {}); })
      .catch(() => { /* registry optional */ });
    return () => { alive = false; };
  }, []);

  // Load the chosen case. Everything is best-effort except the object itself:
  // a missing timeline means no verdict header, not a broken page.
  useEffect(() => {
    let alive = true;
    setObj(null); setTimeline(null); setTicket(null); setCaseErr(""); setLaneStates({});
    if (!caseId) return;
    // The case read is the one fetch that is NOT best-effort: if it fails the
    // page says so verbatim instead of spinning on "Loading…" forever (§10 —
    // no silent failure, and never a reassuring blank).
    const fail = (e: unknown) => { if (alive) setCaseErr((prev) => prev || operatorError(e, "This investigation could not be loaded.")); };
    api.correlationDetail(caseId).then((r) => { if (alive) setObj(r.object); }).catch(fail);
    api.correlationTimeline(caseId).then((t) => { if (alive) setTimeline(t); }).catch(fail);
    api.correlationTickets(caseId).then((t) => { if (alive) setTicket(t?.status ?? null); }).catch(() => { /* ticketing optional */ });
    return () => { alive = false; };
  }, [caseId]);

  // The matched signature's playbook — the same derivation the RCA inspector uses.
  const { recommendedSteps, recommendedOwner } = useMemo(() => {
    const hyp = parseJSON<{ ranking?: { hypotheses?: { id?: string; verdict?: { first_steps?: string[]; owner?: string } }[] } }>(obj?.hypotheses, {});
    const list = hyp.ranking?.hypotheses ?? [];
    const top = list.find((h) => h.id === obj?.top_hypothesis)
      ?? (obj && obj.top_hypothesis !== "undetermined" ? list[0] : undefined);
    return { recommendedSteps: top?.verdict?.first_steps ?? [], recommendedOwner: top?.verdict?.owner ?? "" };
  }, [obj]);

  const rcaCase: RcaCase | null = useMemo(() => {
    if (!obj || !timeline) return null;
    return buildRcaCase(timeline, obj, seams, recommendedOwner, recommendedSteps, seamOwners);
  }, [obj, timeline, seams, recommendedOwner, recommendedSteps, seamOwners]);

  const sym = symptomById(symptom);
  // A case opens every lane (the engine did not pre-narrow the evidence); a
  // symptom opens the lanes its workflow needs.
  const lanes = caseId ? lanesForSymptom(null) : lanesForSymptom(symptom);
  const ladder = buildLadder(lanes, laneStates);
  const scope: LaneScope = useMemo(
    () => ({ device: caseDevice(obj), minutes: rangeMinutes, caseId: caseId || undefined }),
    [obj, rangeMinutes, caseId],
  );
  const started = Boolean(symptom || caseId);
  const head = bisectingHeadline(sym);

  const visibleSymptoms = SYMPTOMS.filter((s) => {
    const q = filter.trim().toLowerCase();
    return !q || s.label.toLowerCase().includes(q) || s.hint.toLowerCase().includes(q);
  });
  const visibleCases = cases.filter((c) => {
    const q = filter.trim().toLowerCase();
    return !q || (c.top_hypothesis || "").toLowerCase().includes(q) || c.correlation_id.toLowerCase().includes(q);
  });

  const createTicket = async () => {
    if (!caseId) return;
    setHandoffNote("");
    try {
      const r = await api.correlationTicketCreate(caseId);
      setHandoffNote(`Ticket request enqueued to ${r?.system || "the configured ticket system"}.`);
      // The create is asynchronous server-side; re-read the authoritative state
      // rather than claiming a ticket number the backend has not issued yet.
      try { setTicket((await api.correlationTickets(caseId))?.status ?? null); } catch { /* status read is best-effort */ }
    } catch (e) {
      setHandoffNote(`Could not create a ticket: ${(e as Error).message}`);
    }
  };

  const exportPdf = async () => {
    if (!caseId || !rcaCase) return;
    setHandoffNote("");
    try {
      await api.downloadRcaReport(caseId, friendlyProblemId(caseId));
    } catch (e) {
      // An un-promoted candidate is a POLICY state, not a failure: say so
      // instead of silently printing a document the platform refused.
      if (e instanceof RcaNotPromotedError) {
        setHandoffNote(`${e.message} Promote it from the RCA workspace to export a document.`);
        return;
      }
      if (!exportRcaPdf(rcaCase, caseId)) setHandoffNote("Could not generate the incident report.");
    }
  };

  return (
    <div className="ts-inv">
      {/* ── 1. Symptom entry ───────────────────────────────────────────── */}
      <section className="ts-entry card" aria-labelledby="ts-entry-h">
        <h2 id="ts-entry-h" className="ts-entry-h">What&apos;s wrong?</h2>
        <label className="ts-search">
          <span className="sr-only">Search symptoms and open cases</span>
          <input
            type="search"
            value={filter}
            placeholder="Describe it, or search the open cases…"
            aria-label="Search symptoms and open cases"
            onChange={(e) => setFilter(e.target.value)}
          />
        </label>

        <div className="ts-picker">
          <div className="ts-pickcol">
            <h3 className="ts-pickh" id="ts-symptom-h">Symptom</h3>
            <ul className="ts-symptoms" aria-labelledby="ts-symptom-h">
              {visibleSymptoms.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    className={`ts-symptom${symptom === s.id && !caseId ? " on" : ""}`}
                    aria-pressed={symptom === s.id && !caseId}
                    onClick={() => { setSymptom(s.id); setCaseId(""); }}
                  >
                    <span className="ts-symptom-l">{s.label}</span>
                    <span className="ts-symptom-h">{s.hint}</span>
                  </button>
                </li>
              ))}
              {visibleSymptoms.length === 0 && <li className="empty">No symptom matches that.</li>}
            </ul>
          </div>

          <div className="ts-pickcol">
            <h3 className="ts-pickh" id="ts-case-h">Open correlation case</h3>
            {casesErr ? (
              <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{casesErr}</div>
            ) : visibleCases.length === 0 ? (
              <div className="empty" role="status">No open correlation case right now.</div>
            ) : (
              <ul className="ts-cases" aria-labelledby="ts-case-h">
                {visibleCases.slice(0, 10).map((c) => (
                  <li key={c.correlation_id}>
                    <button
                      type="button"
                      className={`ts-case${caseId === c.correlation_id ? " on" : ""}`}
                      aria-pressed={caseId === c.correlation_id}
                      onClick={() => { setCaseId(c.correlation_id); setSymptom(null); }}
                    >
                      <span className="ts-case-id">{friendlyProblemId(c.correlation_id)}</span>
                      <span className="ts-case-v">{c.verdict_tier}</span>
                      <span className="ts-case-h">{c.top_hypothesis}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      {!started && (
        <p className="empty" role="status">{head.sub}</p>
      )}

      {/* ── 2. Verdict header ──────────────────────────────────────────── */}
      {started && (
        caseId ? (
          rcaCase ? (
            // The SAME header the RCA workspace renders for this object.
            <div className="rca-ws ts-verdict" data-testid="ts-rca-header">
              <RcaCaseHeader data={rcaCase} />
            </div>
          ) : caseErr ? (
            <div className="empty" role="alert" data-testid="ts-case-error" style={{ color: "var(--bad)" }}>{caseErr}</div>
          ) : (
            <div className="empty" role="status" data-testid="ts-case-loading">Loading the correlated verdict…</div>
          )
        ) : (
          <section className="ts-bisect card" aria-labelledby="ts-bisect-h" data-testid="ts-bisect-header">
            <h2 id="ts-bisect-h" className="ts-bisect-h">{head.title}</h2>
            <p className="ts-bisect-sub">{head.sub}</p>
            {sym && <p className="mini-meta">{sym.hint}</p>}
            <ol className="ts-ladder" aria-label="Layer ladder">
              {ladder.map((r) => (
                <li key={r.id} className={`ts-rung ${r.state}`} data-rung={r.id} data-state={r.state}>
                  <span className="ts-rung-l">{r.label}</span>
                  <span className="ts-rung-n">{r.note}</span>
                </li>
              ))}
            </ol>
          </section>
        )
      )}

      {/* ── 2b. Escalate to TAC ────────────────────────────────────────── */}
      {started && (
        caseId ? (
          <TacEscalationPanel incidentId={caseId} />
        ) : (
          <p className="mini-meta ts-escalate-note" role="status">{ESCALATION_NEEDS_CASE}</p>
        )
      )}

      {/* ── 3. Parallel evidence lanes ─────────────────────────────────── */}
      {started && (
        <div className="ts-lanes dm-grid" data-testid="ts-lanes">
          {lanes.map((id) => {
            const Lane = LANE_COMPONENT[id];
            return (
              <Lane
                key={id}
                scope={scope}
                report={reportLane}
              />
            );
          })}

          {/* ── 4. IRIS co-pilot lane ─────────────────────────────────── */}
          <IrisLane
            caseId={caseId || undefined}
            symptomLabel={sym?.label}
            onOpenDrawer={shell ? () => shell.setCopilotOpen(true) : undefined}
          />
        </div>
      )}

      {/* ── 5. Seam-owned handoff ──────────────────────────────────────── */}
      {started && (
        <section className="ts-handoff card" aria-labelledby="ts-handoff-h" data-testid="ts-handoff">
          <h2 id="ts-handoff-h" className="ts-handoff-h">Handoff</h2>
          {rcaCase?.ownershipLabel ? (
            <p className="ts-owner">Owner: <b>{rcaCase.ownershipLabel}</b></p>
          ) : (
            <p className="empty" role="status">
              No seam owner is attributed yet — an owner is named only once the evidence attributes the fault to a seam.
            </p>
          )}
          <div className="ts-handoff-actions">
            <button type="button" className="btn-accent" onClick={createTicket} disabled={!caseId}>
              {ticket?.ticket_number ? `Ticket ${ticket.ticket_number}` : "Create ticket"}
            </button>
            <button type="button" className="chip-btn" onClick={exportPdf} disabled={!caseId || !rcaCase}>
              Export PDF
            </button>
          </div>
          {!caseId && (
            <p className="mini-meta">
              Ticketing and the exported report are attached to a correlation case — pick one to hand this off.
            </p>
          )}
          {handoffNote && <p className="mini-meta" role="status">{handoffNote}</p>}
        </section>
      )}
    </div>
  );
}
