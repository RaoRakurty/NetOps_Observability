// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationPage — the Troubleshooting surface, in THREE blocks.
//
// OWNER, 2026-09-06: "Troubleshooting page is still confusing. After picking up
// the problem, it asks where is it breaking. It shows layer where prob and
// green. Next it shows evidence and then gives options to escalate to TAC.
// There are two sections which look similar, one place we can describe the
// problem but cannot do anything its just fixed page and then cases where we
// can escalate or open ticket. Can we simplify these pages, Instead of show so
// many details, simplify these pages and make it intuitive."
//
// So the page is now:
//
//   1. What's wrong?   — ONE list. The open cases as plain rows, and one box to
//                        describe a problem that is not listed. Describing it
//                        CREATES a record (POST /api/incidents, source `manual`,
//                        the same seam an alert-born incident uses), so from
//                        that moment it is a case like any other. There is no
//                        second "describe but do nothing" surface any more.
//   2. The answer      — one card: what it is, WHERE it breaks, WHO it affects,
//                        SINCE when, how sure we are, and the three actions.
//   3. The evidence    — ONE disclosure, collapsed. The lanes live inside it.
//
// WHAT LEFT. The "How this page works" intro (now one Ask Iris on the block
// heading), the four numbered step badges, the layer-ladder progress list, the
// symptom picker and its two tabs, the quiet-lane toggle, the per-lane "Details"
// buttons, and the second "Full RCA detail" disclosure inside the first.
//
// WHAT DID NOT LEAVE. Every lane still MOUNTS and still runs its API — that is
// what earns the answer card's "Breaking at" line, and it is why the evidence
// disclosure hides its body rather than unmounting it. A quiet lane collapses to
// one honest line instead of disappearing. The engine's own RCA header, IRIS and
// the TAC escalation are all still here, inside the block they belong to.

import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import "./investigation.css";
import {
  api,
  type CorrObject,
  type CorrTimeline,
  type Incident,
  type Seam,
  type SeamOwnerEntry,
  type TicketStatus,
} from "../../services/api";
import { ShellContext } from "../../context/shell";
import AskIris from "../../components/AskIris";
import RcaCaseHeader from "../../components/rca/RcaCaseHeader";
import { buildRcaCase, type RcaCase } from "../../components/rca/rcaCase";
import TacEscalationPanel from "./TacEscalationPanel";
import IrisLane from "./IrisLane";
import { LANE_COMPONENT, type LaneScope } from "./InvestigationLanes";
import { operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";
import {
  ALL_LANES,
  MAX_SYMPTOM_CHARS,
  affectsLine,
  breakingAt,
  confidenceChip,
  describedTitle,
  laneIsQuiet,
  pickRows,
  plainAnswer,
  plainOwner,
  quietLaneLine,
  type LaneId,
  type LaneState,
  type PickKind,
  type PickRow,
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

/** What the operator picked. `kind` decides which reads the answer card can make. */
export interface Picked { kind: PickKind; id: string }

export default function InvestigationPage({ rangeMinutes = 60, initialCaseId = "" }: {
  rangeMinutes?: number;
  initialCaseId?: string;
}) {
  // The shell is optional here on purpose: the page renders (and is tested)
  // outside the app shell, and useShell() would throw. Absent shell = no
  // "Open Iris" control, never a crash.
  const shell = useContext(ShellContext);

  const [picked, setPicked] = useState<Picked | null>(
    initialCaseId ? { kind: "correlation", id: initialCaseId } : null,
  );
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [irisOpen, setIrisOpen] = useState(false);
  const [escalateOpen, setEscalateOpen] = useState(false);

  // Block 1 — every open case, however it was opened.
  const [cases, setCases] = useState<CorrObject[]>([]);
  const [mine, setMine] = useState<Incident[]>([]);
  const [casesErr, setCasesErr] = useState<string>("");

  // The describe box.
  const [symptomText, setSymptomText] = useState("");
  const [starting, setStarting] = useState(false);
  const [startErr, setStartErr] = useState("");

  // The chosen correlation case, mapped through the SAME adapter the RCA
  // workspace uses — one verdict vocabulary, never a second one.
  const [obj, setObj] = useState<CorrObject | null>(null);
  const [timeline, setTimeline] = useState<CorrTimeline | null>(null);
  const [caseErr, setCaseErr] = useState<string>("");
  const [seams, setSeams] = useState<Record<string, Seam>>({});
  const [seamOwners, setSeamOwners] = useState<Record<string, SeamOwnerEntry>>({});
  const [ticket, setTicket] = useState<TicketStatus | null>(null);
  const [handoffNote, setHandoffNote] = useState("");

  // Lane states feed the answer card's ONE layer line. A lane earns a layer by
  // returning rows — never by being on screen.
  const [laneStates, setLaneStates] = useState<Partial<Record<LaneId, LaneState>>>({});
  const reportLane = useCallback((id: LaneId, state: LaneState) => {
    setLaneStates((s) => (s[id] === state ? s : { ...s, [id]: state }));
  }, []);

  useEffect(() => {
    let alive = true;
    api.correlations(25, 86400, "open")
      .then((r) => { if (alive) { setCases(r?.data ?? []); setCasesErr(""); } })
      .catch((e: unknown) => { if (alive) setCasesErr(operatorError(e, "Open cases could not be loaded.")); });
    // The operator's own described investigations. Best-effort: a deployment
    // with no incident store still lists its correlated cases.
    api.listIncidents({ limit: 25 })
      .then((list) => { if (alive) setMine(list ?? []); })
      .catch(() => { /* no incident store on this backend — nothing to add */ });
    api.seams("active")
      .then((list) => { if (!alive) return; const m: Record<string, Seam> = {}; (list ?? []).forEach((s) => { m[s.seam_id] = s; }); setSeams(m); })
      .catch(() => { /* seam inventory optional — class labels still render */ });
    api.getSeamOwners()
      .then((r) => { if (alive) setSeamOwners(r?.seam_owners ?? {}); })
      .catch(() => { /* registry optional */ });
    return () => { alive = false; };
  }, []);

  const corrId = picked?.kind === "correlation" ? picked.id : "";

  // Load the chosen correlation case. Everything is best-effort except the
  // object itself: a missing timeline means no engine header, not a broken page.
  useEffect(() => {
    let alive = true;
    setObj(null); setTimeline(null); setTicket(null); setCaseErr(""); setLaneStates({});
    setEscalateOpen(false); setIrisOpen(false); setHandoffNote("");
    if (!corrId) return;
    // The case read is the one fetch that is NOT best-effort: if it fails the
    // page says so verbatim instead of spinning on "Loading…" forever (§10 —
    // no silent failure, and never a reassuring blank).
    const fail = (e: unknown) => { if (alive) setCaseErr((prev) => prev || operatorError(e, "This case could not be loaded.")); };
    api.correlationDetail(corrId).then((r) => { if (alive) setObj(r.object); }).catch(fail);
    api.correlationTimeline(corrId).then((t) => { if (alive) setTimeline(t); }).catch(fail);
    api.correlationTickets(corrId).then((t) => { if (alive) setTicket(t?.status ?? null); }).catch(() => { /* ticketing optional */ });
    return () => { alive = false; };
  }, [corrId]);

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

  const rows: PickRow[] = useMemo(() => pickRows(cases, mine), [cases, mine]);
  const row = rows.find((r) => r.id === picked?.id) ?? null;
  const scope: LaneScope = useMemo(
    () => ({ device: caseDevice(obj), minutes: rangeMinutes, caseId: picked?.id }),
    [obj, rangeMinutes, picked?.id],
  );
  const answer = plainAnswer(rcaCase);
  // Onset comes from the picked row when the case is in the list, and from the
  // object itself when it is not (a deep link can name a case older than the
  // list window). "Not stated" only when neither source carries one.
  const since = row?.since || obj?.window_start || obj?.created_at || "";
  const quiet = ALL_LANES.filter((id) => laneIsQuiet(laneStates[id] ?? "loading"));

  const start = async () => {
    const title = describedTitle(symptomText);
    if (!title || starting) return;
    setStarting(true); setStartErr("");
    try {
      const r = await api.createIncident({ title });
      const inc = r?.incident;
      if (!inc?.id) throw new Error("The investigation was not returned.");
      // It is a case like any other from here: put it at the top of the same
      // list and select it, so the next press acts on it.
      setMine((m) => [inc, ...m.filter((i) => i.id !== inc.id)]);
      setPicked({ kind: "investigation", id: inc.id });
      setSymptomText("");
    } catch (e) {
      setStartErr(operatorError(e, "The investigation could not be opened."));
    } finally {
      setStarting(false);
    }
  };

  const createTicket = async () => {
    if (!corrId) return;
    setHandoffNote("");
    try {
      const r = await api.correlationTicketCreate(corrId);
      setHandoffNote(`Ticket request enqueued to ${r?.system || "the configured ticket system"}.`);
      // The create is asynchronous server-side; re-read the authoritative state
      // rather than claiming a ticket number the backend has not issued yet.
      try { setTicket((await api.correlationTickets(corrId))?.status ?? null); } catch { /* status read is best-effort */ }
    } catch (e) {
      setHandoffNote(`Could not create a ticket: ${(e as Error).message}`);
    }
  };

  return (
    <div className="ts-inv">
      {/* ── 1 · What's wrong? ──────────────────────────────────────────────── */}
      <section className="ts-block card" aria-labelledby="ts-what-h" data-testid="ts-pick">
        <h2 id="ts-what-h" className="ts-block-h">
          What&apos;s wrong?
          <AskIris topic="investigate.how" label="What's wrong?" />
        </h2>

        {casesErr ? (
          <p className="ts-bad" role="alert">{casesErr}</p>
        ) : rows.length === 0 ? (
          <p className="empty" role="status">No open case right now.</p>
        ) : (
          <ul className="ts-cases" aria-label="Open cases">
            {rows.slice(0, 12).map((r) => (
              <li key={`${r.kind}-${r.id}`}>
                <button
                  type="button"
                  className={`ts-case${picked?.id === r.id ? " on" : ""}`}
                  aria-pressed={picked?.id === r.id}
                  data-kind={r.kind}
                  onClick={() => setPicked({ kind: r.kind, id: r.id })}
                >
                  <span className="ts-case-l">{r.title}</span>
                  <span className="ts-case-f fact-line">
                    {r.affects}{r.since ? ` · ${fmtDateTime(r.since)}` : ""}
                  </span>
                  <span className="ts-case-chip badge">{r.chip}</span>
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="ts-describe">
          <label className="ts-describe-l" htmlFor="ts-describe-in">Not listed? Describe it</label>
          <div className="ts-describe-row">
            <input
              id="ts-describe-in"
              type="text"
              value={symptomText}
              maxLength={MAX_SYMPTOM_CHARS}
              placeholder="Branch users cannot reach the CRM"
              onChange={(e) => setSymptomText(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void start(); } }}
            />
            <button
              type="button" className="btn-accent"
              disabled={describedTitle(symptomText) === "" || starting}
              aria-busy={starting}
              onClick={() => { void start(); }}
            >
              {starting ? "Opening…" : "Start investigation"}
            </button>
          </div>
          {startErr && <p className="ts-bad" role="alert">{startErr}</p>}
        </div>
      </section>

      {/* ── 2 · The answer ─────────────────────────────────────────────────── */}
      {picked && (
        <section className="ts-block card" aria-label="The answer" data-testid="ts-answer-block">
          {caseErr ? (
            <p className="ts-bad" role="alert" data-testid="ts-case-error">{caseErr}</p>
          ) : corrId && !rcaCase ? (
            <p className="empty" role="status" data-testid="ts-case-loading">Reading this case…</p>
          ) : null}

          <div className="ts-answer" data-answer={answer.state} data-testid="ts-answer">
            <p className="ts-answer-h">{answer.headline}</p>
            <p className="ts-answer-f fact-line">Breaking at: <b>{breakingAt(laneStates)}</b></p>
            <p className="ts-answer-f fact-line">
              Affects: <b>{corrId ? affectsLine(obj?.affected) : affectsLine("")}</b>
            </p>
            <p className="ts-answer-f fact-line">
              Since: <b>{since ? fmtDateTime(since) : "Not stated"}</b>
            </p>
            <p className="ts-answer-f fact-line">Owner: <b>{plainOwner(rcaCase?.ownershipLabel)}</b></p>
            <span className="ts-answer-chip badge" data-testid="ts-confidence">
              {corrId ? confidenceChip(obj?.top_confidence) : confidenceChip(0)}
            </span>
          </div>

          <div className="ts-actions" data-testid="ts-actions">
            <button
              type="button" className="btn-accent"
              aria-expanded={irisOpen} onClick={() => setIrisOpen((o) => !o)}
            >
              {irisOpen ? "Close Iris" : "Ask Iris"}
            </button>
            <button type="button" className="chip-btn" onClick={createTicket} disabled={!corrId}>
              {ticket?.ticket_number ? `Ticket ${ticket.ticket_number}` : "Open ticket"}
            </button>
            <button
              type="button" className="chip-btn"
              aria-expanded={escalateOpen} onClick={() => setEscalateOpen((o) => !o)}
            >
              {escalateOpen ? "Close TAC escalation" : "Escalate to TAC"}
            </button>
          </div>
          {!corrId && <p className="ts-answer-f fact-line">A ticket needs a correlated case.</p>}
          {handoffNote && <p className="ts-answer-f fact-line" role="status">{handoffNote}</p>}

          {irisOpen && (
            <IrisLane
              caseId={corrId || undefined}
              symptomLabel={row?.title}
              auto
              onOpenDrawer={shell ? () => shell.setCopilotOpen(true) : undefined}
            />
          )}
          {escalateOpen && <TacEscalationPanel incidentId={picked.id} />}
        </section>
      )}

      {/* ── 3 · The evidence ───────────────────────────────────────────────── */}
      {picked && (
        <section className="ts-block card" aria-labelledby="ts-ev-h" data-testid="ts-evidence">
          <h2 id="ts-ev-h" className="ts-block-h">The evidence</h2>
          <button
            type="button" className="ts-ev-toggle tsl-disclose"
            aria-expanded={evidenceOpen} aria-controls="ts-ev-body"
            onClick={() => setEvidenceOpen((o) => !o)}
          >
            {evidenceOpen ? "Hide the evidence" : "Show the evidence"}
          </button>

          {/* HIDDEN, never unmounted: the lanes are what earn "Breaking at", so
              collapsing the disclosure must not stop them looking. */}
          <div id="ts-ev-body" className="ts-ev-body" hidden={!evidenceOpen}>
            <div className="ts-lanes dm-grid" data-testid="ts-lanes">
              {ALL_LANES.map((id) => {
                const Lane = LANE_COMPONENT[id];
                const isQuiet = laneIsQuiet(laneStates[id] ?? "loading");
                return (
                  <div key={id} className="ts-lane-slot" hidden={isQuiet} data-quiet={isQuiet ? "yes" : "no"}>
                    <Lane scope={scope} report={reportLane} />
                  </div>
                );
              })}
            </div>

            {/* A quiet lane is never dropped — "we looked and saw nothing" and
                "nothing feeds us this" are both facts an operator can reach. */}
            {quiet.length > 0 && (
              <ul className="ts-quiet" aria-label="Quiet lanes" data-testid="ts-quiet">
                {quiet.map((id) => (
                  <li key={id} className="fact-line">{quietLaneLine(id, laneStates[id] ?? "loading")}</li>
                ))}
              </ul>
            )}

            {/* The engine's own six-question header — the SAME component the RCA
                workspace renders, kept verbatim, inside this one disclosure. */}
            {rcaCase && (
              <div className="rca-ws" data-testid="ts-rca-header">
                <RcaCaseHeader data={rcaCase} />
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
