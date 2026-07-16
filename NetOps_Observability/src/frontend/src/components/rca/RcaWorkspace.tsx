import { useState, ReactNode } from "react";
import "./RcaWorkspace.css";
import { api } from "../../services/api";
import type { RcaCase, RcaPill, KV, TopoNode, TopoEdge } from "./rcaCase";
import { bandLabel, bandTone, appIdSourceLabel } from "./labels";

// RcaWorkspace — the production RCA detail view, organized after the reference
// template (light, single-column report). PURE PRESENTATION: it renders an
// RcaCase (see rcaCase.ts) and owns only ephemeral UI state (timeline marker
// detail). All verdict/evidence/ladder logic lives in the adapter + engine.
//
// Security / quality:
//  · CSP-safe — React event handlers only, no inline <script>, no
//    dangerouslySetInnerHTML; every value is rendered as escaped React text.
//  · Scoped — all styles live under `.rca-ws` (RcaWorkspace.css), isolated from
//    the app's dark theme in both directions.
//  · Honest — a suspected single-signal case renders sparse ("Not observed",
//    locked ladder steps); nothing is promoted to confirmed by the view.

const Pill = ({ p }: { p: RcaPill }) => <span className={`rw-pill ${p.tone}`}>{p.text}</span>;

// Operator-safe grounding for the assistant — RCA facts only (already shown on
// the page). No secrets/credentials/IDs are added (LLM06): the model sees exactly
// what the operator sees, nothing more.
function groundingText(d: RcaCase): string {
  return [
    `RCA: ${d.title}`,
    `Status: ${d.pills.map((p) => p.text).join(" · ")}`,
    `Summary: ${d.summary}`,
    ...d.why.map((w) => `${w.label}: ${w.text}`),
    `Impact: ${d.impact.map((i) => `${i.k}=${i.v}`).join("; ")}`,
    `Evidence: ${d.evidence.map((e) => `${e.title} [${e.pill.text}] ${e.finding}`).join(" | ")}`,
    `Hypotheses: ${d.hypotheses.map((h) => `${h.rank} ${h.hypo} (${h.conf.text})`).join("; ")}`,
    `Decision: ${d.decision.text}`,
  ].join("\n");
}

// AskRcaPanel — wires the assistant box to Iris AI (the copilot proxy).
// The server owns the system prompt (LLM01); we ground the question with the
// operator-facing RCA context as a normal user turn and never inject a system
// role. Degrades honestly when the assistant isn't enabled (no key / feature off).
function AskRcaPanel({ data }: { data: RcaCase }) {
  const [q, setQ] = useState(data.assistant.questions[0] ?? "");
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState("");
  const [offline, setOffline] = useState(false);

  const ask = async (question: string) => {
    const text = question.trim();
    if (!text || busy) return;
    setBusy(true); setAnswer(""); setOffline(false);
    try {
      const res = await api.copilotChat([{
        role: "user",
        content:
          "You are an RCA assistant for a network operations center. Answer the operator's question using ONLY the RCA context below. Be concise and factual. Do not claim customer impact is confirmed unless the status says CONFIRMED; if the context lacks the answer, say which evidence is missing.\n\n" +
          `RCA context:\n${groundingText(data)}\n\nQuestion: ${text}`,
      }]);
      const out = (res as { text?: string }).text
        ?? (res as { content?: { text?: string }[] }).content?.[0]?.text
        ?? (res as { choices?: { message?: { content?: string } }[] }).choices?.[0]?.message?.content
        ?? "";
      if (out) setAnswer(out); else setOffline(true);
    } catch {
      setOffline(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rw-panel rw-assistant">
      <h3>Ask RCA Assistant</h3>
      <h4>Suggested operator questions</h4>
      <div className="rw-small">
        {data.assistant.questions.map((s, i) => (
          <div key={i}>
            <button type="button" className="rw-ask-suggest" onClick={() => { setQ(s); ask(s); }}>• {s}</button>
          </div>
        ))}
      </div>
      <div className="rw-assistant-q">
        <input value={q} onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") ask(q); }}
          aria-label="Ask RCA Assistant" placeholder="Ask about this RCA…" />
        <button className="rw-btn primary" type="button" disabled={busy} onClick={() => ask(q)}>
          {busy ? "Asking…" : "Ask"}
        </button>
      </div>
      <div className="rw-tdetail" style={{ marginTop: 10 }}>
        {answer ? (
          <><b>Iris AI:</b> {answer}</>
        ) : offline ? (
          <><b>Assistant not connected.</b> Iris AI isn&apos;t enabled yet — an administrator can connect a provider and key under Assistant settings. Until then, use the suggested reasoning: {data.assistant.sampleAnswer}</>
        ) : (
          <><b>Sample answer:</b> {data.assistant.sampleAnswer}</>
        )}
      </div>
    </div>
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

function CausalTopology({ nodes, edges }: { nodes: TopoNode[]; edges: TopoEdge[] }) {
  return (
    <div className="rw-topo" role="img" aria-label="Causal topology">
      {nodes.map((n, i) => (
        <div key={i} style={{ display: "contents" }}>
          <div className={`rw-node ${n.kind}`}>
            <div className="circle">{n.abbr}</div>
            <div className="name">{n.name}</div>
            <div className="meta">{n.meta}</div>
            {n.tag && <div className="tag"><Pill p={n.tag} /></div>}
          </div>
          {i < nodes.length - 1 && (
            <div className="rw-edge-wrap">
              <div className={`rw-edge ${edges[i]?.state ?? "good"}`} />
              {edges[i]?.label && (
                <span className={`rw-edge-label ${edges[i]?.state ?? ""}${edges[i]?.side === 1 ? " side1" : ""}`}>{edges[i]?.label}</span>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function RcaWorkspace({
  data, view, onView, onExportPdf, exportDisabled, debugExtra, pathSlot, topologySlot, timeImpactSlot, ticketSlot, aiSlot,
}: {
  data: RcaCase;
  view: "operator" | "debug";
  onView: (v: "operator" | "debug") => void;
  onExportPdf: () => void;
  exportDisabled?: boolean;
  debugExtra?: ReactNode;
  pathSlot?: ReactNode;       // path-causality RCA (design §5/§5a) — the discovered typed SRC→DST path is the HERO
  topologySlot?: ReactNode;   // advanced Network-Path topology (RcaTopology); falls back to the data chain
  timeImpactSlot?: ReactNode; // RCA Time Intelligence — incident time decomposition card
  ticketSlot?: ReactNode;     // RCA auto-ticketing (#78) — live external ticket status + actions
  aiSlot?: ReactNode;         // Iris AI — grounded "Ask AI" RCA explanation card
}) {
  const [detail, setDetail] = useState<string>("");

  return (
    <div className="rca-ws">
      {/* topbar */}
      <div className="rw-topbar">
        <div className="rw-brand">
          <div className="rw-logo">RCA</div>
          <div>
            <div className="rw-h1">Root cause analysis</div>
            <div className="rw-sub">{data.subtitle}</div>
          </div>
        </div>
        <div className="rw-actions">
          {data.synthetic && <span className="rw-watermark">Synthetic data · example case</span>}
          <button className="rw-btn" onClick={onExportPdf} disabled={exportDisabled}
            title="Download the incident report as a PDF document">⤓ Export PDF</button>
          <div className="rw-tabs" role="tablist" aria-label="View">
            <button role="tab" aria-selected={view === "operator"} className={`rw-tab${view === "operator" ? " active" : ""}`} onClick={() => onView("operator")}>Operator View</button>
            <button role="tab" aria-selected={view === "debug"} className={`rw-tab${view === "debug" ? " active" : ""}`} onClick={() => onView("debug")}>Debug View</button>
          </div>
        </div>
      </div>

      {/* case title */}
      <section className="rw-case">
        <div>
          <h2>{data.title}</h2>
          <div className="rw-statusline">{data.pills.map((p, i) => <Pill key={i} p={p} />)}</div>
          {data.decision.text && (
            <div className={`rw-callout${data.decision.tone ? " " + data.decision.tone : ""}`}>
              <strong>Decision:</strong><span>{data.decision.text}</span>
            </div>
          )}
          <div className="rw-note">Observed at: <b>{data.observedAt}</b> · RCA ID: <b>{data.rcaId}</b></div>
        </div>
        <aside className="rw-aside">
          {data.aside.map((m, i) => <div key={i} className="rw-metric"><span>{m.k}</span><b>{m.v}</b></div>)}
        </aside>
      </section>

      {view === "operator" ? (
        <>
          {/* PATH-FIRST (design §5a: the path is the hero). The discovered typed
              SRC→DST path with the broken link highlighted + the named cause leads
              the operator view. Absent → the component renders an honest "no
              discovered path" note; a report without path attribution is unchanged. */}
          {pathSlot && (
            <>
              <div className="rw-section-title">Path causality</div>
              <section className="rw-panel" style={{ marginBottom: 4 }}>{pathSlot}</section>
            </>
          )}

          {/* summary + impact */}
          <section className="rw-grid">
            <div className="rw-panel">
              <h3>Executive RCA summary</h3>
              <p>{data.summary}</p>
              <div className="rw-why">
                {data.why.map((w, i) => (
                  <div key={i}><span className={`label ${w.tone}`}>{w.label}:</span> {w.text}</div>
                ))}
              </div>
              {data.ruledOut.length > 0 && (
                <div className="rw-ruledout">
                  <span className="label blue">Ruled out:</span>{" "}
                  {data.ruledOut.join(" · ")}
                  <div className="rw-ruledout-note">Competing causes the evidence does not support.</div>
                </div>
              )}
            </div>
            <div className="rw-panel">
              <h3>Impact &amp; blast radius</h3>
              <KeyVal rows={data.impact} />
            </div>
          </section>

          {/* Iris AI — grounded, cited "Ask AI" explanation of this RCA. */}
          {aiSlot && <section style={{ marginBottom: 4 }}>{aiSlot}</section>}

          {/* RCA Time Intelligence — where this incident's time was spent. */}
          {timeImpactSlot && (
            <>
              <div className="rw-section-title">Time impact</div>
              <section style={{ marginBottom: 4 }}>{timeImpactSlot}</section>
            </>
          )}

          {/* RCA auto-ticketing (#78) — live external ticket status + Create/Sync. */}
          {ticketSlot && (
            <>
              <div className="rw-section-title">External ticket</div>
              <section style={{ marginBottom: 4 }}>{ticketSlot}</section>
            </>
          )}

          {/* causal topology — advanced Network-Path graphics (RcaTopology) when
              provided, with the data-driven chain / placement card as fallback */}
          <div className="rw-section-title">Network path &amp; causal topology</div>
          {topologySlot ? (
            <section style={{ marginBottom: 4 }}>{topologySlot}</section>
          ) : (
            <section className="rw-panel" style={{ padding: 10 }}>
              {data.topology && data.topology.nodes.length > 0 ? (
                <CausalTopology nodes={data.topology.nodes} edges={data.topology.edges} />
              ) : (
                <div style={{ padding: "14px 6px", color: "var(--rw-muted)" }}>
                  <b style={{ color: "var(--rw-text)" }}>Path location not placed yet.</b> There isn&apos;t enough routing or path
                  evidence to place this issue on a specific link or device chain.
                </div>
              )}
            </section>
          )}

          {/* cloud application & resources (#81 P3G 1c) — additive; only present
              when the object carries cloud-plane evidence. Network RCA renders
              identically when this is absent. */}
          {data.cloud && (
            <>
              <div className="rw-section-title">Cloud application &amp; resources</div>
              <section className="rw-panel rw-cloud">
                <div className="rw-cloud-head">
                  <div className="rw-cloud-id">
                    <span className="rw-cloud-app">{data.cloud.app || "Cloud application"}</span>
                    <span className="rw-cloud-meta">
                      {data.cloud.account && <span>Account {data.cloud.account}</span>}
                      {data.cloud.region && <span>{data.cloud.region}</span>}
                      <span>{data.cloud.signalCount} cloud {data.cloud.signalCount === 1 ? "signal" : "signals"}</span>
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

          {/* application impact (#81 P5) — additive; only present when the object
              carries attached fused-identity evidence. Names which apps this incident
              affects, with provenance; absent → network RCA renders identically. */}
          {data.appImpact && data.appImpact.apps.length > 0 && (
            <>
              <div className="rw-section-title">Application impact</div>
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

          {/* evidence matrix */}
          <div className="rw-section-title">Evidence matrix</div>
          <section className="rw-evidence-grid">
            {data.evidence.map((e, i) => (
              <div key={i} className={`rw-ecard ${e.variant}`}>
                <div className="rw-ehead">
                  <span className="rw-etitle"><span className={`rw-dot ${e.dot}`} />{e.title}</span>
                  <Pill p={e.pill} />
                </div>
                <div className="rw-edesc">{e.desc}</div>
                <div className="rw-efinding">{e.finding}</div>
                <div className="rw-efoot">{e.foot}</div>
              </div>
            ))}
          </section>

          {/* confidence ladder */}
          <div className="rw-section-title">Confidence ladder</div>
          <section className="rw-panel">
            <div className="rw-ladder-row">
              {data.ladder.map((s, i) => <div key={i} className={`rw-ladder-step ${s.state}`}>{s.label}</div>)}
            </div>
            <div className="rw-ladder-caption">
              {data.ladder.map((s, i) => <div key={i}>{s.caption}</div>)}
            </div>
          </section>

          {/* evidence timeline */}
          <div className="rw-section-title">Evidence timeline</div>
          <section className="rw-panel">
            <div className="rw-timeline-wrap">
              <div className="rw-timeline">
                <div className="rw-thead">
                  <div className="rw-tlabel">Signal group</div>
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
            <div className="rw-tdetail">
              {detail ? <><b>Marker detail:</b> {detail}</> : <><b>Tip:</b> Click any marker to see why it was counted as evidence.</>}
            </div>
          </section>

          {/* failure-propagation ladder (owner directive 2026-07-13): how one
              failure caused the next; unwitnessed rungs stay visible but are
              marked Not observed — the ladder never claims without evidence */}
          {data.cascade && data.cascade.length > 0 && (
            <>
              <div className="rw-section-title">How the failure propagated</div>
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
                          {!s.witnessed && <Pill p={{ tone: "gray", text: "Not observed" }} />}
                        </div>
                        <div className="rw-small">{s.witnessed ? s.kinds.join(" · ") : (s.note || "No signals seen")}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="rw-tdetail">
                  <b>Reading this ladder:</b> a failure at the highlighted origin propagates downward — each witnessed stage carries the signals that saw it; a stage marked Not observed is part of the known propagation path but has no evidence in this window and is not claimed.
                </div>
              </section>
            </>
          )}

          {/* hypotheses + ticket */}
          <section className="rw-grid" style={{ marginTop: 12 }}>
            <div className="rw-panel">
              <h3>Hypothesis ranking</h3>
              <table>
                <thead><tr><th>Rank</th><th>Hypothesis</th><th>Confidence</th><th>Reason</th></tr></thead>
                <tbody>
                  {data.hypotheses.map((h, i) => (
                    <tr key={i}>
                      <td className="rw-rank">{h.rank}</td>
                      <td><div className="rw-hypo">{h.hypo}</div><div className="rw-small">{h.sub}</div></td>
                      <td><Pill p={h.conf} /></td>
                      <td>{h.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="rw-panel">
              <h3>Ticket &amp; escalation decision</h3>
              <div className={`rw-callout${data.ticket.callout.tone ? " " + data.ticket.callout.tone : ""}`} style={{ marginTop: 0 }}>
                <strong>{data.ticket.callout.strong}</strong><span>{data.ticket.callout.text}</span>
              </div>
              <KeyVal rows={data.ticket.rows} />
            </div>
          </section>

          {/* next actions + assistant */}
          <section className="rw-grid" style={{ marginTop: 12 }}>
            <div className="rw-panel">
              <h3>Next actions</h3>
              <ol className="rw-next">
                {data.nextActions.map((a, i) => (
                  <li key={i}><span className={`rw-action-badge${a.tone ? " " + a.tone : ""}`}>{a.badge}</span><span>{a.text}</span></li>
                ))}
              </ol>
            </div>
            <AskRcaPanel data={data} />
          </section>
        </>
      ) : (
        <>
          {/* DEBUG view */}
          <section className="rw-grid" style={{ marginTop: 4 }}>
            <div className="rw-panel">
              <h3>Evidence accounting</h3>
              <table>
                <thead><tr><th>Signal</th><th>Used?</th><th>Weight</th><th>Reason</th></tr></thead>
                <tbody>
                  {data.debug.accounting.length === 0 ? (
                    <tr><td colSpan={4} className="rw-small">No attached signals recorded for this object.</td></tr>
                  ) : data.debug.accounting.map((r, i) => (
                    <tr key={i}><td>{r.signal}</td><td><Pill p={r.used} /></td><td className="rw-value mono">{r.weight}</td><td>{r.reason}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="rw-panel">
              <h3>Promotion logic</h3>
              <KeyVal rows={data.debug.promotion} />
              <div className="rw-callout confirmed"><strong>Reasoning:</strong><span>{data.debug.reasoning}</span></div>
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
  );
}
