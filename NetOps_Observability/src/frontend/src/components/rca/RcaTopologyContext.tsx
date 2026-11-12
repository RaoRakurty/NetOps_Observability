// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import "./RcaTopologyContext.css";
import type { ContextModel, DevicePanelView, EgoView, CausalLineView, OverlayTone } from "./pathModel";
import {
  type TopologyContext, type CausalRelation,
  topoStateLabel, topoSourcesLine, topoSourceLabel, readAndEmptySources, unreadSources,
  causalRelationLabel, topoTS, humanWord, interfaceFaults,
} from "./topologyContext";
import { kindLabel } from "./labels";

// RcaTopologyContext — section 6 "Where the break is", drawn from the server's
// ONE topology context (RCA document v2 §2). Four states, three layers:
//
//  · topology_with_path — the measured path (drawn by RcaPathCausality above
//    this block) plus the known topology with both overlays;
//  · topology_only      — the known topology; the causal path is marked
//    UNVERIFIED, never drawn as if it were measured;
//  · device_only        — a device diagnostic card: device, role, source, last
//    seen, evidence interfaces, the sources that were read and came back empty,
//    and what would complete the picture;
//  · no_asset_mapping   — an explicit data-availability error with remediation.
//
// Layers: known links (grey, dotted when stale) · measured fault overlay (amber /
// red device or port — observed, never causal) · causal overlay (verified solid,
// suspected dashed, unknown "?").
//
// Every node, edge and mark comes from the context; nothing is added here. The
// state words are the server document's own (topoStateLabel), so this view and
// the PDF read the same. Colours are design tokens (RcaTopologyContext.css) with
// a light AND a dark value; every state is carried by a WORD as well as a hue.

const STATE_TONE: Record<string, string> = {
  topology_with_path: "ok",
  topology_only: "warn",
  device_only: "warn",
  no_asset_mapping: "bad",
};

function shorten(s: string, max: number): string {
  const r = [...s];
  return r.length > max ? r.slice(0, max - 1).join("") + "…" : s;
}

// A filled arrowhead at (x2,y2) pointing along x1,y1→x2,y2 (polygon, not a
// <marker>: markers need document-unique ids).
function arrowPoints(x1: number, y1: number, x2: number, y2: number): string {
  const dx = x2 - x1, dy = y2 - y1, l = Math.hypot(dx, dy);
  if (l === 0) return "";
  const ux = dx / l, uy = dy / l, size = 8;
  const bx = x2 - ux * size, by = y2 - uy * size, px = -uy * size * 0.5, py = ux * size * 0.5;
  return `${x2.toFixed(1)},${y2.toFixed(1)} ${(bx + px).toFixed(1)},${(by + py).toFixed(1)} ${(bx - px).toFixed(1)},${(by - py).toFixed(1)}`;
}

function CausalLine({ l }: { l: CausalLineView | { x1: number; y1: number; x2: number; y2: number; relation: CausalRelation; directed: boolean } }) {
  const mx = (l.x1 + l.x2) / 2, my = (l.y1 + l.y2) / 2;
  return (
    <g className={`rtc-causal ${l.relation}`} data-relation={l.relation}>
      <line x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} />
      {l.directed && l.relation !== "unknown" && <polygon points={arrowPoints(l.x1, l.y1, l.x2, l.y2)} />}
      {l.relation === "unknown" && (
        <>
          <circle cx={mx} cy={my} r={8} className="rtc-q-bg" />
          <text x={mx} y={my + 4.5} textAnchor="middle" className="rtc-q">?</text>
        </>
      )}
    </g>
  );
}

function toneClass(t: OverlayTone): string {
  return `rtc-tone-${t}`;
}

function EgoGraph({ ego }: { ego: EgoView }) {
  return (
    <svg className="rtc-svg" viewBox={`0 0 ${ego.w} ${ego.h}`} role="img"
      aria-label="Known topology around the affected devices with fault and causal overlays">
      {ego.edges.map((e) => (
        <g key={e.edge.id} data-edge={e.edge.id}>
          <line className={`rtc-link${e.edge.stale ? " stale" : ""}`} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} />
          {e.unknownMark && <CausalLine l={{ ...e.unknownMark, relation: "unknown", directed: false }} />}
        </g>
      ))}
      {ego.causal.map((c, i) => <CausalLine key={i} l={c} />)}
      {ego.nodes.map((n) => (
        <g key={n.node.id} className={`rtc-node ${toneClass(n.tone)}${n.node.managed ? "" : " unmanaged"}`} data-node={n.node.id}>
          <title>{`${n.node.label}${n.roleText ? ` — ${n.roleText}` : ""}${n.node.stale ? " — stale" : ""}`}</title>
          <circle cx={n.x} cy={n.y} r={n.r} />
          {n.node.stale && <text x={n.x} y={n.y + 4} textAnchor="middle" className="rtc-svg-meta">stale</text>}
          <text x={n.x} y={n.y + n.r + 16} textAnchor="middle" className="rtc-svg-label">{shorten(n.node.label, 22)}</text>
          {n.roleText && <text x={n.x} y={n.y + n.r + 31} textAnchor="middle" className="rtc-svg-meta">{shorten(n.roleText, 24)}</text>}
          {n.anomalousPorts.length > 0 && (
            <text x={n.x} y={n.y - n.r - 7} textAnchor="middle" className="rtc-svg-mark">
              {shorten(`anomalous: ${n.anomalousPorts.join(" · ")}`, 36)}
            </text>
          )}
        </g>
      ))}
    </svg>
  );
}

function DevicePanel({ p }: { p: DevicePanelView }) {
  const cx = p.dev.x + p.dev.w / 2, cy = p.dev.y + p.dev.h / 2;
  return (
    <>
      <svg className="rtc-svg" viewBox={`0 0 ${p.w} ${p.h}`} role="img"
        aria-label={`${p.node.label}: its evidence interfaces and the causal marks between them`}>
        {p.connectors.map((c, i) => c.relation
          ? <CausalLine key={i} l={{ x1: c.x1, y1: c.y1, x2: c.x2, y2: c.y2, relation: c.relation, directed: c.directed }} />
          : <line key={i} className="rtc-link thin" x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} />)}
        {p.arcs.map((a, i) => (
          <g key={`arc${i}`} className={`rtc-causal ${a.relation}`} data-relation={a.relation}>
            <path d={`M ${a.x} ${a.y1} C ${a.bulge} ${a.y1} ${a.bulge} ${a.y2} ${a.x + 2} ${a.y2}`} fill="none" />
            <polygon points={arrowPoints(a.bulge, a.y2, a.x + 2, a.y2)} />
          </g>
        ))}
        <g className={`rtc-box ${toneClass(p.devTone)}`} data-node={p.node.id}>
          <rect x={p.dev.x} y={p.dev.y} width={p.dev.w} height={p.dev.h} rx={9} />
          <text x={cx} y={cy - 6} textAnchor="middle" className="rtc-svg-label">{shorten(p.node.label, 24)}</text>
          <text x={cx} y={cy + 12} textAnchor="middle" className="rtc-svg-meta">
            {shorten(p.devKinds.length ? `${p.roleText} · ${p.devKinds.map(kindLabel).join(", ")}` : p.roleText, 30)}
          </text>
        </g>
        {p.ports.map((pt) => (
          <g key={pt.fault.target_id} className={`rtc-box ${toneClass(pt.tone)}`} data-port={pt.fault.target_id}>
            <title>{`${pt.fault.port || pt.fault.target_id} — ${pt.fault.kinds.map(kindLabel).join(", ")} · ${pt.fault.peak_severity.toUpperCase()}`}</title>
            <rect x={pt.x} y={pt.y} width={pt.w} height={pt.h} rx={6} />
            <text x={pt.x + 9} y={pt.y + pt.h / 2 + 5} className="rtc-svg-port">{shorten(pt.fault.port || pt.fault.target_id, 10)}</text>
            <text x={pt.x + pt.w - 8} y={pt.y + pt.h / 2 + 4.5} textAnchor="end" className="rtc-svg-mark">{pt.fault.peak_severity.toUpperCase()}</text>
          </g>
        ))}
        {p.ports.length === 0 && (
          <text x={470} y={cy + 4} className="rtc-svg-meta">No interface carries attached evidence.</text>
        )}
      </svg>
      {(p.morePorts > 0 || p.undirectedPortPairs > 0) && (
        <div className="rtc-fact">
          {p.morePorts > 0 && `${p.morePorts} more interfaces in the table. `}
          {p.undirectedPortPairs > 0 && `${p.undirectedPortPairs} interface pairs with no direction — see causal links.`}
        </div>
      )}
    </>
  );
}

function DeviceCard({ tc, id }: { tc: TopologyContext; id: string }) {
  const n = tc.nodes.find((x) => x.id === id);
  if (!n) return null;
  const ports = interfaceFaults(tc, n.id);
  const empty = readAndEmptySources(tc);
  const unread = unreadSources(tc);
  const lastSeen = n.stale
    ? `stale${n.last_seen ? ` — last seen ${topoTS(n.last_seen)}` : ""}`
    : n.last_seen ? `current — seen by its inventory source${n.first_seen ? ` (known since ${topoTS(n.first_seen)})` : ""}` : "not recorded";
  return (
    <section className="rtc-card" aria-label={`Device diagnostic — ${n.label}`} data-testid="topo-device-card">
      <h5 className="rtc-card-h">Device diagnostic — {n.label}</h5>
      <dl className="rtc-kv">
        <dt>Device</dt><dd>{n.label}{n.label !== n.id && <span className="rtc-muted"> ({n.id})</span>}</dd>
        <dt>Role</dt><dd>{n.role ? humanWord(n.role) : "not classified"}</dd>
        <dt>Source</dt><dd>{topoSourceLabel(n.source)}</dd>
        <dt>Last seen</dt><dd>{lastSeen}</dd>
        <dt>Evidence interfaces</dt>
        <dd>{ports.length ? ports.map((f, i) => (
          <span key={f.target_id}>{i > 0 && " · "}<span className="rtc-mono">{f.port}</span> <span className="rtc-muted">({f.kinds.map(kindLabel).join(", ")})</span></span>
        )) : "none"}</dd>
        <dt>Read and empty</dt><dd>{empty.length ? empty.map((s) => topoSourceLabel(s.kind)).join(", ") : "—"}</dd>
        <dt>Could not be read</dt><dd>{unread.length ? unread.map((s) => topoSourceLabel(s.kind)).join(", ") : "none"}</dd>
      </dl>
    </section>
  );
}

const CAUSAL_TABLE_CAP = 30;

export default function RcaTopologyContext({ tc, model }: { tc: TopologyContext; model: ContextModel }) {
  const tone = STATE_TONE[tc.state] ?? "warn";
  const anchors = tc.nodes.filter((n) => n.anchor);
  return (
    <div className="rtc" data-state={tc.state} data-testid="topo-context">
      <div className="rtc-head">
        <span className={`rtc-state ${tone}`} data-testid="topo-state">{topoStateLabel(tc.state)}</span>
        <span className="rtc-sources">Sources: {topoSourcesLine(tc)}</span>
      </div>
      {tc.reason && <p className="rtc-reason" data-testid="topo-reason">{tc.reason}</p>}

      {tc.state === "no_asset_mapping" && (
        <div className="rtc-error" role="alert" data-testid="topo-error">
          <b>Data-availability error</b> — the affected entity could not be placed in the network topology.
          This is a gap in the data, not a finding about the network.
          {tc.unmapped.length > 0 && <> Not in the inventory: {tc.unmapped.join(", ")}.</>}
        </div>
      )}

      {tc.state === "topology_only" && (
        <div className="rtc-unverified" data-testid="topo-unverified">
          <span className="rtc-unverified-tag">Causal path unverified</span>
          No measured path is attached: the causal path across this topology is unverified.
        </div>
      )}

      {model.ego && <EgoGraph ego={model.ego} />}
      {model.panels.map((p) => <DevicePanel key={p.node.id} p={p} />)}
      {model.panelsCapped && <div className="rtc-fact">Showing 3 affected devices; the tables list all.</div>}
      {(model.ego || model.panels.length > 0) && (
        <div className="rtc-legend" aria-label="Legend">
          {model.ego && <span><i className="rtc-lg-link" /> known link</span>}
          {model.ego && <span><i className="rtc-lg-link stale" /> stale link</span>}
          <span><i className="rtc-lg-dot amber" /> anomalous evidence (no causation implied)</span>
          <span><i className="rtc-lg-causal verified" /> verified</span>
          <span><i className="rtc-lg-causal suspected" /> suspected</span>
          <span><b className="rtc-lg-q">?</b> relationship unknown</span>
          {tc.more_nodes > 0 && <span>{tc.more_nodes} more neighbours not drawn</span>}
        </div>
      )}

      {tc.state === "device_only" && anchors.map((n) => <DeviceCard key={n.id} tc={tc} id={n.id} />)}

      {tc.edges.length > 0 && (
        <details className="rtc-details">
          <summary>Known links ({tc.edges.length})</summary>
          <div className="rtc-table-wrap"><table className="rtc-table">
            <thead><tr><th>Device</th><th>Neighbour</th><th>Ports</th><th>Link</th><th>First seen</th><th>Freshness</th></tr></thead>
            <tbody>{tc.edges.map((e) => (
              <tr key={e.id}>
                <td>{tc.nodes.find((n) => n.id === e.a)?.label ?? e.a}</td>
                <td>{tc.nodes.find((n) => n.id === e.b)?.label ?? e.b}</td>
                <td className="rtc-mono">{e.a_port || "—"} → {e.b_port || "—"}</td>
                <td>{humanWord(e.relationship)}{e.sources.length > 0 && <div className="rtc-muted">{e.sources.map(topoSourceLabel).join(", ")}</div>}</td>
                <td>{e.first_seen ? topoTS(e.first_seen) : "—"}</td>
                <td>{humanWord(e.freshness)}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </details>
      )}

      {tc.faults.length > 0 && (
        <details className="rtc-details" open={tc.state === "device_only"}>
          <summary>Where anomalous evidence was observed ({tc.faults.length})</summary>
          <div className="rtc-table-wrap"><table className="rtc-table">
            <thead><tr><th>Where (measured)</th><th>Evidence</th><th>Peak severity</th><th>Observations</th></tr></thead>
            <tbody>{tc.faults.map((f) => (
              <tr key={`${f.target_type}|${f.target_id}`}>
                <td>{f.target_type === "interface" ? <>{f.device} · <span className="rtc-mono">{f.port}</span></> : <>{f.device} (device)</>}</td>
                <td>{f.kinds.map(kindLabel).join(", ")}</td>
                <td><span className={`rtc-sev ${f.peak_severity === "crit" ? "red" : "amber"}`}>{f.peak_severity.toUpperCase()}</span></td>
                <td>{f.evidence_refs.length}</td>
              </tr>
            ))}</tbody>
          </table></div>
          <div className="rtc-note">Observed only — this never implies causation on its own.</div>
        </details>
      )}

      {tc.causal.length > 0 && (
        <details className="rtc-details">
          <summary>Causal links ({tc.causal.length})</summary>
          <div className="rtc-table-wrap"><table className="rtc-table">
            <thead><tr><th>From → to</th><th>Causal link</th><th>Basis</th></tr></thead>
            <tbody>{tc.causal.slice(0, CAUSAL_TABLE_CAP).map((m, i) => (
              <tr key={i}>
                <td>
                  {m.from}{m.from_kind && <span className="rtc-muted"> ({kindLabel(m.from_kind)})</span>}
                  {m.directed ? " → " : " — "}
                  {m.to}{m.to_kind && <span className="rtc-muted"> ({kindLabel(m.to_kind)})</span>}
                </td>
                <td><span className={`rtc-rel ${m.relation}`}>{causalRelationLabel(m.relation)}</span></td>
                <td className="rtc-muted">{m.basis}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {tc.causal.length > CAUSAL_TABLE_CAP && <div className="rtc-fact">{tc.causal.length - CAUSAL_TABLE_CAP} more causal links in the full report.</div>}
        </details>
      )}

      {tc.remediation.length > 0 && (
        <div className="rtc-remedy" data-testid="topo-remediation">
          <h5 className="rtc-card-h">Complete the picture</h5>
          <ol>{tc.remediation.map((r, i) => <li key={i}>{r}</li>)}</ol>
        </div>
      )}
    </div>
  );
}
