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
//   1. Start troubleshooting — ONE block, two cards: the open cases as plain
//                        rows, and one box to describe a problem that is not
//                        listed (owner, 2026-11-23: the old heading "What's
//                        wrong?" was renamed, the type lightened to the
//                        theme's 500 weight, and each block and action given an
//                        icon from components/Icon.tsx). Describing it
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
  type RcaPathAttribution,
  type Seam,
  type SeamOwnerEntry,
  type TacCaseLink,
  type TicketStatus,
} from "../../services/api";
import { ShellContext } from "../../context/shell";
import AskIris from "../../components/AskIris";
import Icon from "../../components/Icon";
import RcaCaseHeader from "../../components/rca/RcaCaseHeader";
import RcaPathCausality from "../../components/rca/RcaPathCausality";
import { readTopologyContext, type TopologyContext } from "../../components/rca/topologyContext";
import { buildRcaCase, type RcaCase } from "../../components/rca/rcaCase";
import { isContextStory } from "../../components/rca/rcaPhrases";
import TacEscalationPanel from "./TacEscalationPanel";
import TacCaseChip from "../../components/tac/TacCaseChip";
import { caseLinkFromIncident } from "./tacModel";
import IrisLane from "./IrisLane";
import { useAIEntitlements } from "../../lib/aiEntitlements";
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

/**
 * The block's icon badge — decorative only (the heading beside it is the
 * accessible name). Deliberately NOT numbered: the owner retired the numbered
 * step badges on 2026-09-06 ("so many details … make it intuitive"), and the
 * icon carries the block's meaning without bringing them back.
 */
function BlockMark({ icon }: { icon: string }) {
  return (
    <span className="ts-mark" aria-hidden="true">
      <Icon name={icon} size={18} />
    </span>
  );
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
  // N-A7: "Ask Iris" only for a caller holding ai.chat. Cosmetic — the
  // server refuses /api/ai/ask without it.
  const aiEnt = useAIEntitlements();
  const [escalateOpen, setEscalateOpen] = useState(false);
  // The vendor case this incident carries. It arrives one of two ways: the
  // escalation panel reports the case it just opened, or — after a reload — the
  // incident record itself carries what MarkSync wrote. Either way the chip
  // renders the SAME sentence, from the same mirror of Go's StatusLine.
  const [tacCase, setTacCase] = useState<TacCaseLink | null>(null);

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
  // The case's measured path (the same report JSON the RCA workspace reads).
  // Best-effort: absent, RcaPathCausality falls back to the timeline's spine.
  const [pathAttr, setPathAttr] = useState<RcaPathAttribution | null>(null);
  const [topoCtx, setTopoCtx] = useState<TopologyContext | null>(null);
  const [handoffNote, setHandoffNote] = useState("");

  // Lane states feed the answer card's ONE layer line. A lane earns a layer by
  // returning rows — never by being on screen.
  const [laneStates, setLaneStates] = useState<Partial<Record<LaneId, LaneState>>>({});
  const reportLane = useCallback((id: LaneId, state: LaneState) => {
    setLaneStates((s) => (s[id] === state ? s : { ...s, [id]: state }));
  }, []);

  useEffect(() => {
    let alive = true;
    // Read boundary (2026-11-25): each answer is shape-checked before it is
    // stored. `x ?? []` caught only null — an object where a list belongs
    // reached `.map`/`.filter` and sent the page to its error screen. An
    // unreadable CASE list is said to be unreadable (never shown as "no open
    // cases", which would be a false all-clear); the optional reads degrade
    // to nothing.
    api.correlations(25, 86400, "open")
      .then((r) => {
        if (!alive) return;
        const data = (r as { data?: unknown } | null | undefined)?.data;
        if (Array.isArray(data)) { setCases(data as CorrObject[]); setCasesErr(""); }
        else setCasesErr("Open cases could not be read.");
      })
      .catch((e: unknown) => { if (alive) setCasesErr(operatorError(e, "Open cases could not be loaded.")); });
    // The operator's own described investigations. Best-effort: a deployment
    // with no incident store still lists its correlated cases.
    api.listIncidents({ limit: 25 })
      .then((list) => { if (alive) setMine(Array.isArray(list) ? list : []); })
      .catch(() => { /* no incident store on this backend — nothing to add */ });
    api.seams("active")
      .then((list) => {
        if (!alive) return;
        const m: Record<string, Seam> = {};
        (Array.isArray(list) ? list : []).forEach((s) => { if (s && typeof s === "object" && s.seam_id) m[s.seam_id] = s; });
        setSeams(m);
      })
      .catch(() => { /* seam inventory optional — class labels still render */ });
    api.getSeamOwners()
      .then((r) => {
        const owners = (r as { seam_owners?: unknown } | null | undefined)?.seam_owners;
        if (alive) setSeamOwners(owners && typeof owners === "object" && !Array.isArray(owners) ? owners as typeof seamOwners : {});
      })
      .catch(() => { /* registry optional */ });
    return () => { alive = false; };
  }, []);

  const corrId = picked?.kind === "correlation" ? picked.id : "";
  // The reset below is keyed on the PICKED INVESTIGATION, not on corrId. A
  // described investigation has no correlation id, so keying on corrId left
  // every described case sharing one key of "": switching between two of them
  // kept the previous case's TAC chip and Iris answer on screen, and the chip's
  // Refresh then posted against the NEW incident's id.
  const pickedKey = picked ? `${picked.kind}:${picked.id}` : "";

  // Load the chosen correlation case. Everything is best-effort except the
  // object itself: a missing timeline means no engine header, not a broken page.
  useEffect(() => {
    let alive = true;
    setObj(null); setTimeline(null); setTicket(null); setCaseErr(""); setLaneStates({});
    setPathAttr(null); setTopoCtx(null);
    setEscalateOpen(false); setIrisOpen(false); setHandoffNote(""); setTacCase(null);
    if (!corrId) return;
    // The case read is the one fetch that is NOT best-effort: if it fails the
    // page says so verbatim instead of spinning on "Loading…" forever (§10 —
    // no silent failure, and never a reassuring blank).
    const fail = (e: unknown) => { if (alive) setCaseErr((prev) => prev || operatorError(e, "This case could not be loaded.")); };
    api.correlationDetail(corrId).then((r) => { if (alive) setObj(r.object); }).catch(fail);
    // The timeline is NOT fatal — the comment above has always said so. Sharing
    // the object read's handler painted "This case could not be loaded." above a
    // fully populated answer card whenever only the timeline read failed.
    api.correlationTimeline(corrId).then((t) => { if (alive) setTimeline(t); })
      .catch(() => { /* no engine header, not a broken page */ });
    api.correlationTickets(corrId).then((t) => { if (alive) setTicket(t?.status ?? null); }).catch(() => { /* ticketing optional */ });
    // Wrapped so a backend (or a test double) without the report read is a
    // missing path panel, never a thrown render.
    Promise.resolve().then(() => api.rcaReportJson(corrId))
      .then((r) => { if (alive) { setPathAttr(r?.path_attribution ?? null); setTopoCtx(readTopologyContext(r)); } })
      .catch(() => { /* report JSON is best-effort; the path falls back to the timeline */ });
    return () => { alive = false; };
  }, [pickedKey, corrId]);

  // The matched signature's playbook — the same derivation the RCA inspector uses.
  const { recommendedSteps, recommendedOwner } = useMemo(() => {
    const hyp = parseJSON<{ ranking?: { hypotheses?: { id?: string; context_story?: boolean; verdict?: { first_steps?: string[]; owner?: string } }[] } }>(obj?.hypotheses, {});
    // Owner D1: a background story never assigns the fix or sets first steps.
    const list = (hyp.ranking?.hypotheses ?? []).filter((h) => !isContextStory(h.id, h.context_story));
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
  // What the incident RECORD knows about a vendor case, for a picked
  // investigation that was escalated in an earlier session. A ticket that did
  // not come from a TAC connector maps to null — the ITSM projection files its
  // own through the same fields, and painting one as a vendor case would be a
  // claim nobody made.
  const recordedCase = useMemo(() => {
    const inc = mine.find((i) => i.id === picked?.id);
    return inc ? caseLinkFromIncident(inc) : null;
  }, [mine, picked?.id]);
  const shownCase = tacCase ?? recordedCase;
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
      {/* ── 1 · Start troubleshooting ─────────────────────────────────────── */}
      <section className="ts-block ts-group" style={{ ["--g" as string]: "var(--mod-network)" } as React.CSSProperties} aria-labelledby="ts-what-h" data-testid="ts-pick">
        <div className="ts-group-head">
          <BlockMark icon="tool" />
          <h2 id="ts-what-h" className="ts-block-h">
            Start troubleshooting
            <AskIris topic="investigate.how" label="Start troubleshooting" />
          </h2>
        </div>
        <p className="ts-lede">Pick an open case, or describe a problem that is not listed.</p>

        <div className="ts-start">
          <div className="ts-card" data-testid="ts-open-cases">
            <div className="ts-card-top">
              <h3 className="ts-card-h">
                <Icon name="alert-triangle" size={18} className="ts-card-ic" />
                Open cases
              </h3>
              {rows.length > 0 && <span className="ts-count badge" aria-label={`${rows.length} open`}>{rows.length}</span>}
            </div>
            {casesErr ? (
              <p className="ts-bad" role="alert">{casesErr}</p>
            ) : rows.length === 0 ? (
              <p className="empty ts-empty" role="status">
                <Icon name="check" size={18} className="ts-empty-ic" />
                No open case right now.
              </p>
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
                      <span className="ts-case-ic" aria-hidden="true">
                        <Icon name={r.kind === "investigation" ? "edit" : "activity"} size={16} />
                      </span>
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
          </div>

          <div className="ts-card ts-describe" data-testid="ts-describe">
            <h3 className="ts-card-h">
              <Icon name="edit" size={18} className="ts-card-ic" />
              Describe a problem
            </h3>
            <label className="ts-describe-l" htmlFor="ts-describe-in">What are users or devices experiencing?</label>
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
              type="button" className="btn-accent ts-start-btn"
              disabled={describedTitle(symptomText) === "" || starting}
              aria-busy={starting}
              onClick={() => { void start(); }}
            >
              <Icon name="search" size={16} />
              {starting ? "Opening…" : "Start investigation"}
            </button>
            {startErr && <p className="ts-bad" role="alert">{startErr}</p>}
          </div>
        </div>
      </section>

      {/* ── 2 · The answer ─────────────────────────────────────────────────── */}
      {picked && (
        <section className="ts-block ts-group" style={{ ["--g" as string]: "var(--accent)" } as React.CSSProperties} aria-label="The answer" data-testid="ts-answer-block">
          <div className="ts-group-head">
            <BlockMark icon="target" />
            <h2 className="ts-block-h">The answer</h2>
          </div>
          {caseErr ? (
            <p className="ts-bad" role="alert" data-testid="ts-case-error">{caseErr}</p>
          ) : corrId && !rcaCase ? (
            <p className="empty" role="status" data-testid="ts-case-loading">Reading this case…</p>
          ) : null}

          <div className="ts-answer" data-answer={answer.state} data-testid="ts-answer">
            <p className="ts-answer-h">{answer.headline}</p>
            {/* The layer is named only when the anomaly lanes asked about THIS
                case's device. A case that names none reads the whole fleet, and
                a fleet-wide row is somebody's fault but not provably this
                one's, so the line stays Unknown and the lane says why. */}
            {/* Four facts as a stat grid (Paths redesign P1). The text keeps
                its "Label: value" reading order for screen readers and tests. */}
            <dl className="ts-facts" data-testid="ts-facts">
              <div className="ts-fact"><dt>Breaking at:</dt> <dd>{breakingAt(laneStates, Boolean(scope.device))}</dd></div>
              <div className="ts-fact"><dt>Affects:</dt> <dd>{corrId ? affectsLine(obj?.affected) : affectsLine("")}</dd></div>
              <div className="ts-fact"><dt>Since:</dt> <dd>{since ? fmtDateTime(since) : "Not stated"}</dd></div>
              <div className="ts-fact"><dt>Owner:</dt> <dd>{plainOwner(rcaCase?.ownershipLabel)}</dd></div>
            </dl>
            <span className="ts-answer-chip badge" data-testid="ts-confidence">
              {corrId ? confidenceChip(obj?.top_confidence) : confidenceChip(0)}
            </span>
          </div>

          <div className="ts-actions" data-testid="ts-actions">
            {aiEnt.has("ai.chat") && (
              <button
                type="button" className="btn-accent"
                aria-expanded={irisOpen} onClick={() => setIrisOpen((o) => !o)}
              >
                <Icon name="copilot" size={16} />
                {irisOpen ? "Close Iris" : "Ask Iris"}
              </button>
            )}
            <button type="button" className="chip-btn" onClick={createTicket} disabled={!corrId}>
              <Icon name="ticket" size={16} />
              {ticket?.ticket_number ? `Ticket ${ticket.ticket_number}` : "Open ticket"}
            </button>
            <button
              type="button" className="chip-btn"
              aria-expanded={escalateOpen} onClick={() => setEscalateOpen((o) => !o)}
            >
              <Icon name="support" size={16} />
              {escalateOpen ? "Close TAC escalation" : "Escalate to TAC"}
            </button>
          </div>
          {shownCase && (
            <p className="ts-answer-f fact-line" data-testid="ts-tac-case">
              <TacCaseChip
                link={shownCase}
                incidentId={picked.id}
                onRefreshed={setTacCase}
              />
            </p>
          )}
          {!corrId && <p className="ts-answer-f fact-line">A ticket needs a correlated case.</p>}
          {handoffNote && <p className="ts-answer-f fact-line" role="status">{handoffNote}</p>}

          {irisOpen && aiEnt.has("ai.chat") && (
            <IrisLane
              caseId={corrId || undefined}
              symptomLabel={row?.title}
              auto
              onOpenDrawer={shell ? () => shell.setCopilotOpen(true) : undefined}
            />
          )}
          {/* The SAME action, not a second implementation: pressing Escalate
              here mounts the panel with the one-action flow already in flight,
              so the operator never presses two identical buttons. */}
          {escalateOpen && (
            <TacEscalationPanel incidentId={picked.id} autoStart onCaseOpened={setTacCase} />
          )}

          {/* The case's path — the SAME single path view the RCA workspace
              renders, with its own honest fallbacks (spine / adjacency / not
              discovered). Correlated cases only: a described investigation has
              no engine timeline to draw from. */}
          {corrId && timeline && rcaCase && (
            <div className="ts-path panel" data-testid="ts-path">
              <div className="panel-tools"><h3>Case path</h3></div>
              <div className="rca-ws">
                <RcaPathCausality data={pathAttr} timeline={timeline} context={topoCtx}
                  ownership={rcaCase.ownershipLabel} possibleCause={rcaCase.possiblyCause}
                  measuredBreak={rcaCase.measuredBreak} />
              </div>
            </div>
          )}
        </section>
      )}

      {/* ── 3 · The evidence ───────────────────────────────────────────────── */}
      {picked && (
        <section className="ts-block ts-group" style={{ ["--g" as string]: "var(--mod-logs)" } as React.CSSProperties} aria-labelledby="ts-ev-h" data-testid="ts-evidence">
          <div className="ts-group-head">
            <BlockMark icon="layers" />
            <h2 id="ts-ev-h" className="ts-block-h">The evidence</h2>
          </div>
          <button
            type="button" className="ts-ev-toggle tsl-disclose"
            aria-expanded={evidenceOpen} aria-controls="ts-ev-body"
            onClick={() => setEvidenceOpen((o) => !o)}
          >
            <Icon name={evidenceOpen ? "chevron-down" : "chevron-right"} size={16} />
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
