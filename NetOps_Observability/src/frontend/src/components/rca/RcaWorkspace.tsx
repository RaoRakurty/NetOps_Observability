// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useState, ReactNode } from "react";
import "./RcaWorkspace.css";
import type { RcaCase, KV, CaseEvent } from "./rcaCase";
import { bandLabel, bandTone, appIdSourceLabel } from "./labels";
import FidelityBadge from "../FidelityBadge";
import RcaCaseHeader, { Pill } from "./RcaCaseHeader";
import AskIris from "../AskIris";
import { fmtTime, fmtDateTime, fmtDate, parseTs } from "../../lib/time";
import { RCA_SECTION_NAMES, HOW_TO_READ, WOULD_CONFIRM_LABEL } from "./rcaPhrases";

// RcaWorkspace — the production RCA detail view, organized after the reference
// template (light, single-column report). PURE PRESENTATION: it renders an
// RcaCase (see rcaCase.ts) and owns only ephemeral UI state (timeline marker
// detail). All verdict/evidence/ladder logic lives in the adapter + engine.
//
// Security / quality:
//  · CSP-safe — React event handlers only, no inline <script>, no
//    dangerouslySetInnerHTML; every value is rendered as escaped React text.
//  · Scoped — all styles live under `.rca-ws` (RcaWorkspace.css) and follow the
//    app theme through --rw-* tokens (light AND dark values, no literals).
//  · Honest — a suspected single-signal case renders sparse (locked ladder
//    steps, muted unwitnessed rungs); nothing is promoted to confirmed by the
//    view, and epistemic state is never a grey chip (owner 2026-07-19).


// Iris in the RCA view (RCA document v2 §5) is ONE docked conversation — the
// `aiSlot` (RcaAskAi), scoped to this problem. The second "Ask RCA Assistant"
// box that used to sit at the bottom of the sheet is gone: two assistants on one
// page answered the same question two ways.

// sectionTitle — "N · <name>" from the ONE section-name list the PDF also uses.
function sectionTitle(n: number): string {
  return `${n} · ${RCA_SECTION_NAMES[n - 1]}`;
}

// HowToReadPanel — the one-page "How to read this RCA" guide (owner
// 2026-11-11), a collapsible help panel. Native <details>: keyboard operable,
// no script state.
function HowToReadPanel() {
  return (
    <details className="rw-howto">
      <summary>How to read this RCA</summary>
      <ol>{HOW_TO_READ.map((t, i) => <li key={i}>{t}</li>)}</ol>
    </details>
  );
}

function KeyVal({ rows }: { rows: KV[] }) {
  return (
    <div className="rw-keyval">
      {rows.map((r, i) => (
        <div key={i} style={{ display: "contents" }}>
          <div className="rw-key">{r.k}</div>
          <div className={`rw-value${r.mono ? " mono" : ""}`} style={r.tone ? { color: `var(--rw-${r.tone})` } : undefined}>{r.v}</div>
        </div>
      ))}
    </div>
  );
}

// EventTimeline — the chronological "what happened when" list (owner P1
// 2026-07-19: timelines of events with timestamps are RCA basics). Every entry
// is a REAL recorded timestamp (see buildCaseEvents); rendered as an ordered
// list (list semantics for AT), collapsible via native <details> (keyboard
// operable), times carry <time dateTime> and the date appears whenever an event
// falls on a different day than the first (crossing midnight stays readable).
function EventTimeline({ events }: { events: CaseEvent[] }) {
  const firstDay = fmtDate(events[0]?.ts);
  return (
    <details className="rw-events" open>
      <summary className="rw-events-summary">
        <span className="rw-events-count">{events.length} event{events.length === 1 ? "" : "s"} · oldest first</span>
      </summary>
      <ol className="rw-events-list">
        {events.map((e, i) => {
          const iso = parseTs(e.ts)?.toISOString();
          const sameDay = fmtDate(e.ts) === firstDay;
          return (
            <li key={i} className="rw-event">
              <time className="rw-event-time" dateTime={iso}>
                {sameDay ? fmtTime(e.ts) : fmtDateTime(e.ts)}
              </time>
              <span className={`rw-event-dot ${e.tone}`} aria-hidden="true" />
              <span className="rw-event-text">
                {e.label}
                {e.detail && <span className="rw-event-detail"> · {e.detail}</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </details>
  );
}

export default function RcaWorkspace({
  data, view, onView, onExportPdf, exportDisabled, debugExtra, pathSlot, timeImpactSlot, ticketSlot, aiSlot, verifySlot,
  feedbackSlot, correlationId, similarSlot,
}: {
  data: RcaCase;
  /** The case's correlation id — the grounding KEY handed to /api/ai/ask by the
   *  assistant box. Absent for a synthetic/example case: the ask still goes to
   *  the grounded engine, just without the case context. */
  correlationId?: string;
  view: "operator" | "debug";
  onView: (v: "operator" | "debug") => void;
  onExportPdf: () => void;
  exportDisabled?: boolean;
  debugExtra?: ReactNode;
  // THE single network-path & causality render (RcaPathCausality over
  // pathModel.ts — owner P1 2026-07-19: one path view, one logic). The
  // component owns its own honest fallbacks (spine / adjacency / not
  // discovered), so no second topology section exists.
  pathSlot?: ReactNode;
  timeImpactSlot?: ReactNode; // RCA Time Intelligence — incident time decomposition card
  similarSlot?: ReactNode;    // Similar past incidents (tracker 337 N-F4)
  ticketSlot?: ReactNode;     // RCA auto-ticketing (#78) — live external ticket status + actions
  aiSlot?: ReactNode;         // Iris, docked beside the sheet — a conversation scoped to this problem
  verifySlot?: ReactNode;     // Active Verification (spec #8) — read-only device interrogation card
  // Operator verdict feedback (Project 2 P7) — "was this verdict right?".
  // Rendered as a compact full-width row under the case aside, where the reader
  // has just finished the verdict and the aside claims.
  feedbackSlot?: ReactNode;
}) {
  const [detail, setDetail] = useState<string>("");
  void correlationId; // kept on the contract for callers; Iris reads it via aiSlot

  return (
    <div className={`rca-ws${aiSlot ? " rw-docked" : ""}`}>
      <div className="rw-main">
      {/* topbar */}
      <div className="rw-topbar">
        <div className="rw-brand">
          <div className="rw-logo">RCA</div>
          <div>
            <h1 className="rw-h1">Root cause analysis</h1>
            <div className="rw-sub">{data.subtitle}</div>
          </div>
        </div>
        <div className="rw-actions">
          {data.synthetic && <span className="rw-watermark">Synthetic data · example case</span>}
          <button className="rw-btn" onClick={onExportPdf} disabled={exportDisabled}
            title="Download the incident report as a PDF document">⤓ Export PDF</button>
          {/* View switch as a toggle group (not ARIA tabs: no tabpanel/roving-
              focus wiring here, and plain buttons are fully keyboard operable). */}
          <div className="rw-tabs" role="group" aria-label="View">
            <button aria-pressed={view === "operator"} className={`rw-tab${view === "operator" ? " active" : ""}`} onClick={() => onView("operator")}>Operator View</button>
            <button aria-pressed={view === "debug"} className={`rw-tab${view === "debug" ? " active" : ""}`} onClick={() => onView("debug")}>Evidence detail</button>
          </div>
        </div>
      </div>

      {/* case title */}
      <RcaCaseHeader data={data} feedbackSlot={feedbackSlot} />

      {view === "operator" ? (
        <>
          {/* The NOC RCA document (owner 2026-11-11): ten sections in the order a
              NOC engineer reads them. The "How to read this RCA" guide sits on
              top, collapsed — one click away for whoever needs it. */}
          <HowToReadPanel />

          {/* 1 · What broke */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(1)}</h3>
          <section className="rw-panel rw-doc-sec">
            <p className="rw-whatbroke">{data.whatBroke}</p>
            <p className="rw-doc-text">{data.summary}</p>
          </section>

          {/* 2 · Who is affected — impact evidence only, never the verdict */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(2)}</h3>
          <section className="rw-panel rw-doc-sec">
            <div className="rw-table-wrap"><table className="rw-axes">
              <thead><tr><th>Who</th><th>Status</th><th>What we know</th></tr></thead>
              <tbody>
                {data.affected.map((a, i) => (
                  <tr key={i}>
                    <td className="rw-axes-k">{a.axis}</td>
                    <td><span className={`rw-pill ${a.state === "measured" ? "blue" : a.state === "indicated" ? "orange" : "gray"}`}>{a.state}</span></td>
                    <td>{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
            <h4 className="rw-doc-h">Impact &amp; blast radius</h4>
            <KeyVal rows={data.impact} />
            <div className="rw-doc-note">Read from impact measurements only — never from the verdict.</div>
          </section>

          {/* application impact (#81 P5) — additive; part of "who is affected" */}
          {data.appImpact && data.appImpact.apps.length > 0 && (
            <>
              <h3 className="rw-section-title">Application impact</h3>
              <section className="rw-panel rw-appimpact">
                <div className="rw-appimpact-grid">
                  {data.appImpact.apps.map((a, i) => (
                    <div key={i} className="rw-appimpact-row">
                      <span className="rw-appimpact-name">
                        <span className={`rw-dot ${bandTone(a.band)}`} />{a.app}
                        {a.provider && <span className="rw-appimpact-provider">{a.provider}</span>}
                      </span>
                      <Pill p={{ tone: bandTone(a.band), text: `${bandLabel(a.band)}${a.evidenceScore ? ` · ${a.evidenceScore}` : ""}` }} />
                      <span className="rw-appimpact-srcs">
                        {a.sources.length ? a.sources.map((s) => appIdSourceLabel(s)).join(" · ") : "no source recorded"}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="rw-cloud-note">{data.appImpact.note}</div>
              </section>
            </>
          )}

          {/* cloud application & resources (#81 P3G 1c) — additive */}
          {data.cloud && (
            <>
              <h3 className="rw-section-title">Cloud application &amp; resources</h3>
              <section className="rw-panel rw-cloud">
                <div className="rw-cloud-head">
                  <div className="rw-cloud-id">
                    <span className="rw-cloud-app">{data.cloud.app || "Cloud application"}</span>
                    <span className="rw-cloud-meta">
                      {data.cloud.account && <span>Account {data.cloud.account}</span>}
                      {data.cloud.region && <span>{data.cloud.region}</span>}
                      <span>{data.cloud.signalCount} cloud {data.cloud.signalCount === 1 ? "observation" : "observations"}</span>
                    </span>
                  </div>
                  <Pill p={data.cloud.crossPlane ? { tone: "green", text: "Corroborated cross-plane" } : { tone: "orange", text: "Single-plane · suspected" }} />
                </div>
                {data.cloud.resources.length > 0 && (
                  <div className="rw-cloud-block">
                    <h4>Affected cloud resources</h4>
                    <div className="rw-cloud-res-grid">
                      {data.cloud.resources.map((r, i) => (
                        <div key={i} className="rw-cloud-res">
                          <span className="rw-res-name"><span className={`rw-dot ${r.tone}`} />{r.name}</span>
                          <span className="rw-res-kind">{r.kind}</span>
                          <span className="rw-res-finding">{r.finding}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {data.cloud.changes.length > 0 && (
                  <div className="rw-cloud-block">
                    <h4>Cloud configuration changes</h4>
                    <ul className="rw-cloud-changes">
                      {data.cloud.changes.map((c, i) => <li key={i}><b>{c.name}</b> · {c.detail}</li>)}
                    </ul>
                  </div>
                )}
                <div className="rw-cloud-seam">
                  <span className={`rw-dot ${data.cloud.crossPlane ? "green" : "orange"}`} />
                  <b>Cloud ↔ network seam:</b>{" "}
                  {data.cloud.crossPlane
                    ? "an independent network observer grounds this across the path."
                    : "no independent underlay or probe evidence in this window."}
                </div>
                <div className="rw-cloud-note">{data.cloud.note}</div>
              </section>
            </>
          )}

          {/* 3 · When — dated events only */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(3)}</h3>
          {data.events && data.events.length > 0 ? (
            <>
              <h4 className="rw-doc-h">Event timeline</h4>
              <section className="rw-panel rw-events-panel" style={{ marginBottom: 4 }}>
                <EventTimeline events={data.events} />
              </section>
            </>
          ) : (
            <section className="rw-panel rw-doc-sec"><div className="rw-doc-empty">No dated events are recorded for this case.</div></section>
          )}
          <div className="rw-doc-note">Dated events only. Standing findings are in section 7.</div>
          {timeImpactSlot && (
            <>
              <h4 className="rw-doc-h">Time impact</h4>
              <section style={{ marginBottom: 4 }}>{timeImpactSlot}</section>
            </>
          )}

          {/* 4 · Cause and how sure we are — exactly one of the four phrases */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(4)}</h3>
          <section className="rw-panel rw-doc-sec">
            <div className={`rw-phrase ${data.confidence.level}`} data-testid="rca-phrase">
              {data.confidence.phrase}
              {data.confidence.cause && (data.confidence.level === "confirmed" || data.confidence.level === "likely") ? `: ${data.confidence.cause}` : ""}
            </div>
            <div className="rw-why">
              {data.why.filter((w) => w.label !== WOULD_CONFIRM_LABEL).map((w, i) => (
                <div key={i}><span className={`label ${w.tone}`}>{w.label}:</span> {w.text}</div>
              ))}
            </div>
            {data.wouldConfirm.length > 0 && (
              <>
                <h4 className="rw-doc-h">{WOULD_CONFIRM_LABEL}</h4>
                <ol className="rw-doc-list">{data.wouldConfirm.map((t, i) => <li key={i}>{t}</li>)}</ol>
              </>
            )}
          </section>
          {/* Active Verification (spec #8) — the read-only way to confirm it. */}
          {verifySlot && <section style={{ marginBottom: 4 }}>{verifySlot}</section>}
          <h4 className="rw-doc-h">
            Confidence ladder
            <AskIris topic="rca.confidence-ladder" label="Confidence ladder" />
          </h4>
          <section className="rw-panel">
            <div className="rw-ladder-row">
              {data.ladder.map((s, i) => <div key={i} className={`rw-ladder-step ${s.state}`}>{s.label}</div>)}
            </div>
            <div className="rw-ladder-caption">
              {data.ladder.map((s, i) => <div key={i}>{s.caption}</div>)}
            </div>
            {data.ladderNote && <div className="rw-ladder-note">{data.ladderNote}</div>}
          </section>

          {/* 5 · How we know — each observation names its source */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(5)}</h3>
          <section className="rw-panel rw-doc-sec">
            {data.howWeKnow.length > 0 ? (
              <ol className="rw-doc-list">{data.howWeKnow.map((r, i) => <li key={i}>{r.text}</li>)}</ol>
            ) : (
              <div className="rw-doc-empty">No observation supports a cause yet.</div>
            )}
            {data.oneWitness && <div className="rw-doc-caution">{data.oneWitness}</div>}
            {data.verifyDetail && data.verifyDetail.length > 0 && (
              <details className="rw-verify">
                <summary>How was this verified?</summary>
                <div className="rw-verify-body">
                  <div>The engine's verbatim verdict gates for this case:</div>
                  <ul>{data.verifyDetail.map((r, i) => <li key={i}>{r}</li>)}</ul>
                </div>
              </details>
            )}
          </section>
          <h4 className="rw-doc-h">Evidence matrix</h4>
          <section className="rw-evidence-grid">
            {data.evidence.map((e, i) => (
              <div key={i} className={`rw-ecard ${e.variant}`}>
                <div className="rw-ehead">
                  <span className="rw-etitle"><span className={`rw-dot ${e.dot}`} />{e.title}</span>
                  <Pill p={e.pill} />
                </div>
                <div className="rw-edesc">{e.desc}</div>
                {e.chips && e.chips.length > 0 && (
                  <div className="rw-echips">
                    {e.chips.map((c, j) => <span key={j} className="rw-echip">{c}</span>)}
                  </div>
                )}
                <div className="rw-efinding">{e.finding}</div>
                {e.fidelity && (
                  <div className="rw-efid">
                    <span className="rw-efid-k">Rule fidelity</span>
                    <FidelityBadge fidelity={e.fidelity} />
                  </div>
                )}
                <div className="rw-efoot">{e.foot}</div>
              </div>
            ))}
          </section>
          <h4 className="rw-doc-h">Evidence timeline</h4>
          <section className="rw-panel">
            <div className="rw-timeline-wrap">
              <div className="rw-timeline">
                <div className="rw-thead">
                  <div className="rw-tlabel">Evidence lane</div>
                  <div className="rw-ttrack">{data.timelineTicks.map((t, i) => <span key={i}>{t}</span>)}</div>
                </div>
                {data.timeline.map((lane, li) => (
                  <div key={li} className="rw-trow">
                    <div className="rw-tlabel"><span className={`rw-dot ${lane.dot}`} />{lane.label}</div>
                    <div className="rw-ttrack">
                      {lane.markers.map((m, mi) => (
                        <button key={mi} type="button" className={`rw-marker ${m.tone}${detail === m.detail ? " sel" : ""}`}
                          style={{ left: `${m.left}%` }} onClick={() => setDetail(m.detail)}>{m.label}</button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="rw-tdetail" role="status" aria-live="polite">
              {detail ? <><b>Marker detail:</b> {detail}</> : <>Each marker carries the reason it counted as evidence.</>}
            </div>
          </section>
          {data.cascade && data.cascade.length > 0 && (
            <>
              <h4 className="rw-doc-h">
                How it propagated
                <AskIris topic="rca.failure-propagation" label="How it propagated" />
              </h4>
              <section className="rw-panel">
                <div className="rw-cascade">
                  {data.cascade.map((s, i) => (
                    <div key={i} className={`rw-cascade-stage${s.witnessed ? " witnessed" : ""}`}>
                      <div className="rw-cascade-rail">
                        <span className={`rw-cascade-dot${s.witnessed ? (s.root ? " red" : " orange") : ""}`} />
                        {i < (data.cascade?.length ?? 0) - 1 && <span className="rw-cascade-line" />}
                      </div>
                      <div className="rw-cascade-body">
                        <div className="rw-cascade-head">
                          <span className="rw-cascade-label">{s.stage}</span>
                          {s.root && s.witnessed && <Pill p={{ tone: "red", text: "Likely origin" }} />}
                        </div>
                        <div className="rw-small">{s.witnessed ? s.kinds.join(" · ") : (s.note || "")}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="rw-tdetail">
                  A dimmed stage has no evidence in this window and is not claimed.
                </div>
              </section>
            </>
          )}

          {/* 6 · Where the break is — red only on a measured break */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(6)}</h3>
          {pathSlot ? (
            <>
              <h4 className="rw-doc-h">Network topology &amp; causality</h4>
              <section className="rw-panel" style={{ marginBottom: 4 }}>{pathSlot}</section>
            </>
          ) : (
            <section className="rw-panel rw-doc-sec"><div className="rw-doc-empty">Path not measured — no break drawn.</div></section>
          )}
          <div className="rw-doc-note">Red: measured break. Dotted: inferred.</div>

          {/* 7 · Background on this device (not a cause) */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(7)}</h3>
          <section className="rw-panel rw-doc-sec rw-background" aria-label="Background on this device (not a cause)">
            {data.background.length > 0 ? (
              <>
                <ul className="rw-bg-list">
                  {data.background.map((b, i) => (
                    <li key={i}>
                      <div className="rw-bg-title">{b.title}{b.firstSeen && <span className="rw-bg-when"> · first seen {b.firstSeen}</span>}</div>
                      <div className="rw-bg-detail">{b.detail}</div>
                      <div className="rw-bg-src">Seen by: {b.source}</div>
                    </li>
                  ))}
                </ul>
                <div className="rw-doc-note">Context only — never the cause, the impact or a break.</div>
              </>
            ) : (
              <div className="rw-doc-empty">Nothing recorded on this device.</div>
            )}
          </section>

          {/* 8 · Other explanations considered */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(8)}</h3>
          <section className="rw-panel rw-doc-sec">
            {data.others.length > 0 ? (
              <div className="rw-table-wrap"><table className="rw-axes">
                <thead><tr><th>Explanation</th><th>Why it is not the answer</th></tr></thead>
                <tbody>{data.others.map((o, i) => <tr key={i}><td className="rw-axes-k">{o.title}</td><td>{o.why}</td></tr>)}</tbody>
              </table></div>
            ) : (
              <div className="rw-doc-empty">No other explanation had evidence in this window.</div>
            )}
            {data.ruledOut.length > 0 && (
              <div className="rw-ruledout">
                <span className="label blue">Ruled out:</span>{" "}
                {data.ruledOut.join(" · ")}
                <div className="rw-ruledout-note">Competing causes the evidence does not support.</div>
              </div>
            )}
          </section>

          {/* 9 · Who owns the fix */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(9)}</h3>
          <section className="rw-panel rw-doc-sec">
            <KeyVal rows={[{ k: "Owner", v: data.ownerSection.owner }, { k: "Why", v: data.ownerSection.why }]} />
          </section>

          {/* 10 · What to do now · Watch for recurrence */}
          <h3 className="rw-section-title rw-doc-title">{sectionTitle(10)}</h3>
          <section className="rw-grid">
            <div className="rw-panel">
              <h3>Next actions</h3>
              <ol className="rw-next">
                {data.nextActions.map((a, i) => (
                  <li key={i}><span className={`rw-action-badge${a.tone ? " " + a.tone : ""}`}>{a.badge}</span><span>{a.text}</span></li>
                ))}
              </ol>
            </div>
            <div className="rw-panel">
              <h3>Ticket &amp; escalation decision</h3>
              <div className={`rw-callout${data.ticket.callout.tone ? " " + data.ticket.callout.tone : ""}`} style={{ marginTop: 0 }}>
                <strong>{data.ticket.callout.strong}</strong><span>{data.ticket.callout.text}</span>
              </div>
              <KeyVal rows={data.ticket.rows} />
              <h4 className="rw-doc-h">Watch for recurrence</h4>
              <ul className="rw-doc-list">{data.watch.map((w, i) => <li key={i}>{w}</li>)}</ul>
            </div>
          </section>
          {ticketSlot && (
            <>
              <h4 className="rw-doc-h">External ticket</h4>
              <section style={{ marginBottom: 4 }}>{ticketSlot}</section>
            </>
          )}
          {similarSlot && (
            <>
              <h4 className="rw-doc-h">Similar past incidents</h4>
              <section style={{ marginBottom: 4 }}>{similarSlot}</section>
            </>
          )}

        </>
      ) : (
        <>
          {/* DEBUG view */}
          <section className="rw-grid" style={{ marginTop: 4 }}>
            <div className="rw-panel">
              <h3>Evidence accounting</h3>
              <table>
                <thead><tr><th>Observation</th><th>Used?</th><th>Weight</th><th>Reason</th></tr></thead>
                <tbody>
                  {data.debug.accounting.length === 0 ? (
                    <tr><td colSpan={4} className="rw-small">No attached observations recorded for this object.</td></tr>
                  ) : data.debug.accounting.map((r, i) => (
                    <tr key={i}><td>{r.signal}</td><td><Pill p={r.used} /></td><td className="rw-value mono">{r.weight}</td><td>{r.reason}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="rw-panel">
              <h3>Promotion logic</h3>
              <KeyVal rows={data.debug.promotion} />
              <div className="rw-callout confirmed"><strong>Why:</strong><span>{data.debug.reasoning}</span></div>
            </div>
          </section>
          {debugExtra && <section className="rw-panel" style={{ marginTop: 12 }}>{debugExtra}</section>}
          <section className="rw-panel" style={{ marginTop: 12 }}>
            <h3>Correlation data model</h3>
            <pre className="rw-jsonbox">{JSON.stringify(data.debug.model, null, 2)}</pre>
          </section>
        </>
      )}
      </div>
      {/* Iris, docked beside the sheet (RCA document v2 §5) — a conversation
          scoped to this problem; it stays in view while the sheet scrolls. */}
      {aiSlot && <aside className="rw-dock">{aiSlot}</aside>}
    </div>
  );
}
