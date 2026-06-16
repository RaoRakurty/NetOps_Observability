import { useState, ReactNode } from "react";
import "./RcaWorkspace.css";
import type { RcaCase, RcaPill, KV, TopoNode, TopoEdge } from "./rcaCase";

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
  data, view, onView, onExportPdf, exportDisabled, debugExtra,
}: {
  data: RcaCase;
  view: "operator" | "debug";
  onView: (v: "operator" | "debug") => void;
  onExportPdf: () => void;
  exportDisabled?: boolean;
  debugExtra?: ReactNode;
}) {
  const [detail, setDetail] = useState<string>("");

  return (
    <div className="rca-ws">
      {/* topbar */}
      <div className="rw-topbar">
        <div className="rw-brand">
          <div className="rw-logo">C</div>
          <div>
            <div className="rw-h1">Root cause analysis</div>
            <div className="rw-sub">{data.subtitle}</div>
          </div>
        </div>
        <div className="rw-actions">
          {data.synthetic && <span className="rw-watermark">Synthetic data · example case</span>}
          <button className="rw-btn" onClick={onExportPdf} disabled={exportDisabled}
            title="Generate a print-ready RCA report (Save as PDF)">⤓ Export PDF</button>
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
            </div>
            <div className="rw-panel">
              <h3>Impact &amp; blast radius</h3>
              <KeyVal rows={data.impact} />
            </div>
          </section>

          {/* causal topology */}
          <div className="rw-section-title">Causal topology</div>
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
            <div className="rw-panel rw-assistant">
              <h3>Ask RCA Assistant</h3>
              <h4>Suggested operator questions</h4>
              <div className="rw-small">{data.assistant.questions.map((q, i) => <div key={i}>• {q}</div>)}</div>
              <div className="rw-assistant-q">
                <input defaultValue={data.assistant.questions[0] ?? ""} aria-label="Ask RCA Assistant" />
                <button className="rw-btn primary" type="button">Ask</button>
              </div>
              <div className="rw-tdetail" style={{ marginTop: 10 }}><b>Sample answer:</b> {data.assistant.sampleAnswer}</div>
            </div>
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
