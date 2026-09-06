// InvestigationPage — the symptom-first Troubleshooting surface (Project 4 §A).
//
// THE GOAL OF THIS PAGE, in the order an operator works it (owner, 2026-09-06:
// "not sure how to use this page … what's the goal"):
//
//   Step 1  What's wrong?          — one picker: the problem, or an open case
//   Step 2  Where is it breaking?  — four layers, plain status per layer
//   Step 3  Evidence               — one card per place we looked
//   Step 4  Answer & next action   — the cause (or honestly none) + the handoff
//
// The page used to render every one of those at once, in engine vocabulary,
// with no order of operations — which is why it read as a wall. Nothing was
// removed to fix that: every API call, every lane, IRIS, the TAC escalation and
// both handoff actions are still here. What changed is SEQUENCE (four numbered
// steps), VOCABULARY (a NOC admin's words, not the engine's) and DENSITY (raw
// material moved behind per-card "Details", quiet lanes behind one toggle).
//
// POSITIONING (research §c). RCA is what Correlix CONCLUDED; this page is where
// the operator DRIVES and the platform does the legwork. So the two entry points
// are equal citizens — two tabs of ONE control: pick one of the nine canonical
// NOC workflows, or pick an open correlation case. Picking a case shows the SAME
// six-question RCA header the RCA workspace shows for that object (RcaCaseHeader
// — one definition, not a second verdict vocabulary), now behind step 4's
// "Full RCA detail" disclosure so the plain answer leads. Picking only a symptom
// shows an HONEST answer: no cause is established, and the ladder says which
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
// which is now one of step 4's actions: an escalation is anchored to a
// correlated incident, so it opens only when a case is open.

import { useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
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
import { friendlyProblemId, signatureNocTitle } from "../../components/rca/labels";
import { exportRcaPdf } from "../../components/rca/rcaExport";
import TacEscalationPanel from "./TacEscalationPanel";
import IrisLane from "./IrisLane";
import { LANE_COMPONENT, type LaneScope } from "./InvestigationLanes";
import { operatorError } from "../../lib/errors";
import { ESCALATION_NEEDS_CASE } from "./tacModel";
import {
  HOW_IT_WORKS,
  SYMPTOMS,
  bisectingHeadline,
  buildPlainLadder,
  laneIsQuiet,
  lanesForSymptom,
  plainAnswer,
  plainOwner,
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

/** The engine's verdict tier, in the words the picker shows an operator. */
export function tierLabel(tier: string): string {
  switch ((tier || "").trim()) {
    case "confirmed": return "Cause confirmed";
    case "suspected": return "Likely cause";
    case "recovered": return "Recovered";
    default: return "Cause not known yet";
  }
}

/** Step — the numbered section every part of this page is rendered inside, so
 *  the order of operations is visible rather than implied by stacking. */
function Step({ n, id, title, sub, children, testid }: {
  n: number; id: string; title: string; sub: string; children: ReactNode; testid?: string;
}) {
  const hid = `ts-step-${id}-h`;
  return (
    <section className="ts-step card" aria-labelledby={hid} data-step={n} data-testid={testid}>
      <header className="ts-step-head">
        <span className="ts-step-n" aria-hidden="true">{n}</span>
        <div className="ts-step-headings">
          <h2 id={hid} className="ts-step-h">{title}</h2>
          <p className="ts-step-sub">{sub}</p>
        </div>
      </header>
      {children}
    </section>
  );
}

export default function InvestigationPage({ rangeMinutes = 60, initialSymptom = null, initialCaseId = "" }: {
  rangeMinutes?: number;
  initialSymptom?: SymptomId | null;
  initialCaseId?: string;
}) {
  // The shell is optional here on purpose: the page renders (and is tested)
  // outside the app shell, and useShell() would throw. Absent shell = no
  // "Open Iris" control and no "Correlate" jump, never a crash.
  const shell = useContext(ShellContext);

  const [symptom, setSymptom] = useState<SymptomId | null>(initialSymptom);
  const [caseId, setCaseId] = useState<string>(initialCaseId);
  // Step 1 is ONE control with two tabs — a symptom and an open case are equal
  // ways in, not two competing columns the operator has to compare.
  const [entry, setEntry] = useState<"symptom" | "case">(initialCaseId ? "case" : "symptom");
  const [filter, setFilter] = useState("");
  // Step 3: the quiet lanes (nothing seen, or nothing feeding us) are collapsed
  // behind ONE toggle. They are never dropped — "we cannot see this" is a fact.
  const [quietOpen, setQuietOpen] = useState(false);
  // Step 4: the TAC escalation opens on demand rather than sitting open.
  const [escalateOpen, setEscalateOpen] = useState(false);
  const [rcaDetail, setRcaDetail] = useState(false);

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
    setEscalateOpen(false); setRcaDetail(false);
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
  const ladder = buildPlainLadder(lanes, laneStates);
  const scope: LaneScope = useMemo(
    () => ({ device: caseDevice(obj), minutes: rangeMinutes, caseId: caseId || undefined }),
    [obj, rangeMinutes, caseId],
  );
  const started = Boolean(symptom || caseId);
  const head = bisectingHeadline(sym);
  const answer = plainAnswer(rcaCase);
  const quietLanes = lanes.filter((id) => laneIsQuiet(laneStates[id] ?? "loading"));

  const visibleSymptoms = SYMPTOMS.filter((s) => {
    const q = filter.trim().toLowerCase();
    return !q || s.label.toLowerCase().includes(q) || s.hint.toLowerCase().includes(q);
  });
  const visibleCases = cases.filter((c) => {
    const q = filter.trim().toLowerCase();
    return !q
      || signatureNocTitle(c.top_hypothesis || "").toLowerCase().includes(q)
      || (c.top_hypothesis || "").toLowerCase().includes(q)
      || c.correlation_id.toLowerCase().includes(q);
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
      {/* ── How this page works ────────────────────────────────────────── */}
      <section className="ts-how card" aria-labelledby="ts-how-h">
        <h2 id="ts-how-h" className="ts-how-h">How this page works</h2>
        <ol className="ts-how-list">
          {HOW_IT_WORKS.map((line, i) => (
            <li key={i}><span className="ts-how-n" aria-hidden="true">{i + 1}</span><span>{line}</span></li>
          ))}
        </ol>
      </section>

      {/* ── Step 1 · What's wrong? ─────────────────────────────────────── */}
      <Step
        n={1} id="what" title="What's wrong?"
        sub="Pick the problem you are seeing, or an open case. You can change it at any time."
        testid="ts-step-1"
      >
        <div className="seg-mini ts-entry-tabs" role="group" aria-label="How to start">
          <button
            type="button" aria-pressed={entry === "symptom"} className={entry === "symptom" ? "on" : ""}
            onClick={() => setEntry("symptom")}
          >Describe the problem</button>
          <button
            type="button" aria-pressed={entry === "case"} className={entry === "case" ? "on" : ""}
            onClick={() => setEntry("case")}
          >{`Open cases (${cases.length})`}</button>
        </div>

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

        {entry === "symptom" ? (
          <ul className="ts-symptoms" aria-label="Symptom">
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
        ) : casesErr ? (
          <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{casesErr}</div>
        ) : visibleCases.length === 0 ? (
          <div className="empty" role="status">No open correlation case right now.</div>
        ) : (
          <ul className="ts-cases" aria-label="Open cases">
            {visibleCases.slice(0, 10).map((c) => (
              <li key={c.correlation_id}>
                <button
                  type="button"
                  className={`ts-case${caseId === c.correlation_id ? " on" : ""}`}
                  aria-pressed={caseId === c.correlation_id}
                  onClick={() => { setCaseId(c.correlation_id); setSymptom(null); }}
                >
                  <span className="ts-case-l">{signatureNocTitle(c.top_hypothesis || "")}</span>
                  <span className="ts-case-h">
                    <span className="ts-case-id">{friendlyProblemId(c.correlation_id)}</span>
                    {" · "}{tierLabel(c.verdict_tier)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}

        {started && (
          <p className="ts-picked" role="status">
            Investigating: <b>{caseId ? `${friendlyProblemId(caseId)} — ${signatureNocTitle(obj?.top_hypothesis || "")}` : head.title}</b>
          </p>
        )}
      </Step>

      {!started && (
        <p className="empty" role="status">{head.sub}</p>
      )}

      {/* ── Step 2 · Where is it breaking? ─────────────────────────────── */}
      {started && (
        <Step
          n={2} id="where" title="Where is it breaking?"
          sub="We check the network layer by layer, from the wire up. This is what we have so far."
          testid="ts-step-2"
        >
          {caseId ? (
            caseErr ? (
              <p className="ts-bad" role="alert" data-testid="ts-case-error">{caseErr}</p>
            ) : !rcaCase ? (
              <p className="empty" role="status" data-testid="ts-case-loading">Reading this case…</p>
            ) : null
          ) : (
            <p className="ts-bisect-sub" data-testid="ts-bisect-header">
              <b>{head.title}</b> — {head.sub}
            </p>
          )}
          <ol className="ts-rungs" aria-label="Where it is breaking">
            {ladder.map((r, i) => (
              <li key={r.id} className={`ts-rung ${r.state}`} data-rung={r.id} data-state={r.state}>
                <span className="ts-rung-n" aria-hidden="true">{i + 1}</span>
                <span className="ts-rung-l">{r.label}</span>
                <span className="ts-rung-s">{r.status}</span>
                <span className="ts-rung-note">{r.note}</span>
              </li>
            ))}
          </ol>
          {sym && <p className="ts-step-foot">{sym.hint}</p>}
        </Step>
      )}

      {/* ── Step 3 · Evidence ──────────────────────────────────────────── */}
      {started && (
        <Step
          n={3} id="evidence" title="Evidence"
          sub="One card per place we looked. Cards with something to report are open; the quiet ones are tucked away."
          testid="ts-step-3"
        >
          <div className="ts-lanes dm-grid" data-testid="ts-lanes">
            {/* Every lane is MOUNTED whatever its state — that is what makes it
                able to say it is quiet. A quiet lane is hidden, never skipped,
                so no API call and no honest "we cannot see this" is lost. */}
            {lanes.map((id) => {
              const Lane = LANE_COMPONENT[id];
              const quiet = laneIsQuiet(laneStates[id] ?? "loading");
              return (
                <div key={id} className="ts-lane-slot" hidden={quiet && !quietOpen} data-quiet={quiet ? "yes" : "no"}>
                  <Lane scope={scope} report={reportLane} />
                </div>
              );
            })}
          </div>
          {quietLanes.length > 0 && (
            <button
              type="button" className="chip-btn ts-quiet-toggle"
              aria-expanded={quietOpen} data-testid="ts-quiet-toggle"
              onClick={() => setQuietOpen((q) => !q)}
            >
              {quietOpen
                ? `Hide ${quietLanes.length} quiet ${quietLanes.length === 1 ? "lane" : "lanes"}`
                : `Show ${quietLanes.length} quiet ${quietLanes.length === 1 ? "lane" : "lanes"}`}
            </button>
          )}
        </Step>
      )}

      {/* ── Step 4 · Answer & next action ──────────────────────────────── */}
      {started && (
        <Step
          n={4} id="answer" title="Answer & next action"
          sub="What we think is wrong, who owns it, and the one thing to do next."
          testid="ts-step-4"
        >
          <div className="ts-answer" data-answer={answer.state} data-testid="ts-answer">
            <p className="ts-answer-h">{answer.headline}</p>
            {answer.detail && <p className="ts-answer-d">{answer.detail}</p>}
            <p className="ts-answer-o">Who owns this: <b>{plainOwner(rcaCase?.ownershipLabel)}</b></p>
          </div>

          <div className="ts-actions" data-testid="ts-handoff">
            <button type="button" className="btn-accent" onClick={createTicket} disabled={!caseId}>
              {ticket?.ticket_number ? `Ticket ${ticket.ticket_number}` : "Open ticket"}
            </button>
            <button
              type="button" className="chip-btn" disabled={!caseId}
              aria-expanded={escalateOpen} onClick={() => setEscalateOpen((o) => !o)}
            >
              {escalateOpen ? "Close TAC escalation" : "Escalate to TAC"}
            </button>
            <button
              type="button" className="chip-btn" disabled={!caseId || !shell}
              onClick={() => shell?.navigate(`investigate/rca?id=${encodeURIComponent(caseId)}`)}
            >
              Correlate
            </button>
            <button type="button" className="chip-btn" onClick={exportPdf} disabled={!caseId || !rcaCase}>
              Download report
            </button>
          </div>
          {!caseId && (
            <p className="ts-step-foot">
              A ticket, an escalation and the report all hang off a correlated case. {ESCALATION_NEEDS_CASE}
            </p>
          )}
          {handoffNote && <p className="ts-step-foot" role="status">{handoffNote}</p>}

          {/* Iris is the assistant INSIDE the answer, not an eighth lane. */}
          <IrisLane
            caseId={caseId || undefined}
            symptomLabel={sym?.label}
            onOpenDrawer={shell ? () => shell.setCopilotOpen(true) : undefined}
          />

          {escalateOpen && caseId && <TacEscalationPanel incidentId={caseId} />}

          {/* The engine's own six-question header — the same component the RCA
              workspace renders, kept verbatim but behind a disclosure so the
              plain answer above leads and the engine detail is a click away. */}
          {rcaCase && (
            <div className="ts-disclose">
              <button
                type="button" className="tsl-disclose" aria-expanded={rcaDetail}
                onClick={() => setRcaDetail((d) => !d)}
              >
                {rcaDetail ? "Hide the full RCA detail" : "Full RCA detail"}
              </button>
              {rcaDetail && (
                <div className="rca-ws" data-testid="ts-rca-header">
                  <RcaCaseHeader data={rcaCase} />
                </div>
              )}
            </div>
          )}
        </Step>
      )}
    </div>
  );
}
