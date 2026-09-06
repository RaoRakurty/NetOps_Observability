// PeersPanel — "Sessions down or flapping" (BGP ops tracker #4): the BGP
// neighbours on the operator's OWN routers, and who carries their traffic.
//
// The heading is the NOC admin's question, not the protocol's name (owner,
// 2026-09-06). "BMP", "Adj-RIB-In" and the metric name still appear — in the
// section's secondary line, the row tooltips and the Details disclosure, which
// is where an engineer looks and a NOC admin does not have to.
//
// TWO SOURCES, NEVER CONFLATED. A BMP session is one of the operator's own
// routers pushing its Adj-RIB-In to us; `device_bgp_peer_state` is an SNMP/gNMI
// sample of the same session from the outside. They are different witnesses, so
// each row says which one is talking, and a BMP row wins for the same
// (device, peer) because only it carries the transition reason and the counters.
//
// FIVE HONEST STATES (peersState in the model), because the difference between
// them is the whole value of the tab:
//   bmp_off      — FEATURE_BMP is off; the receiver is not even running.
//   no_exporter  — the receiver is up but no router is exporting to it.
//   no_peers     — sessions exist but we have seen no peer state.
//   rows         — real rows.
//   error        — the read failed; we say so instead of showing an empty table.

import { useCallback, useEffect, useState } from "react";
import {
  api, type BgpBmpSessionsResp, type BgpIncident, type PromInstantResponse,
} from "../../services/api";
import { Chip } from "../../components/noc";
import {
  mergePeerRows, peerRowsFromMetrics, peerRowsFromSessions, peersState,
  transitSet, type PeerRow,
} from "./bgpAlerts.model";
import { Details, Section, ShowAll, SubBlock, useCap } from "./Section";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_PEERS = 12;
const FIRST_TRANSIT = 6;

const PEER_QUERY = "device_bgp_peer_state";

function stateChip(r: PeerRow) {
  if (r.state === "up") return <Chip label="Up" tone="var(--ok)" title="The session is established." />;
  if (r.state === "down") return <Chip label="Down" tone="var(--crit)" title={r.reason || "The session is not established."} />;
  return (
    <Chip
      label="Not reported"
      tone="var(--muted)"
      title="Nothing has told us the state of this session. That is a missing measurement, not a healthy neighbour."
    />
  );
}

export function PeersPanel({ incidents }: { incidents?: BgpIncident[] }) {
  const [sessions, setSessions] = useState<BgpBmpSessionsResp | null>(null);
  const [bmpAvailable, setBmpAvailable] = useState(false);
  const [metrics, setMetrics] = useState<PromInstantResponse | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(true);
  const [at, setAt] = useState<number | null>(null);

  const load = useCallback(() => {
    let alive = true;
    setBusy(true); setErr("");
    // Each source loads independently and fails independently: a dead metric
    // store must not blank the BMP half, and vice versa.
    api.bgpBmpSessions()
      .then((d) => { if (alive) { setSessions(d); setBmpAvailable(true); } })
      .catch(() => { if (alive) { setSessions(null); setBmpAvailable(false); } });
    api.metricsQuery(PEER_QUERY)
      .then((d) => { if (alive) setMetrics(d); })
      .catch((e: Error) => { if (alive) setErr(e.message || "The device peer-state query failed."); })
      .finally(() => { if (alive) { setBusy(false); setAt(Date.now()); } });
    return () => { alive = false; };
  }, []);
  useEffect(load, [load]);

  const bmpRows = peerRowsFromSessions(sessions?.sessions);
  const devRows = peerRowsFromMetrics(metrics);
  const rows = mergePeerRows(bmpRows, devRows);
  const state = peersState({
    error: !!err && rows.length === 0,
    bmpAvailable,
    sessions: sessions?.sessions.length ?? 0,
    rows: rows.length,
  });

  const withTransit = (incidents ?? []).filter((i) => transitSet(i).length > 0);
  const peerCap = useCap(rows, FIRST_PEERS);
  const transitCap = useCap(withTransit, FIRST_TRANSIT);

  return (
    <Section
      id="peers"
      title="Sessions down or flapping"
      sub="BGP neighbours on your own routers, and who carries your traffic"
      updatedAt={at}
    >
      <SubBlock title="Neighbour sessions">

        {busy && rows.length === 0 && <div className="empty">Reading peer state…</div>}

        {!busy && state === "bmp_off" && (
          <div className="empty">
            Nothing is reporting neighbour state: the BMP receiver is off (<span className="mono">FEATURE_BMP</span>)
            and no router is sending its BGP peer counter. This is an absent feed, not a healthy fleet — point a
            router&apos;s BMP export at the platform, or enable the BGP peer OID in the device profile.
          </div>
        )}
        {!busy && state === "no_exporter" && (
          <div className="empty">
            No router is sending neighbour state to this platform yet. Nothing is being measured here — this is an
            empty feed, not a converged network.
          </div>
        )}
        {!busy && state === "no_peers" && (
          <div className="empty">
            {sessions?.sessions.length} router session(s) are open, but none of them has reported a neighbour coming up
            or going down yet. The state is left unreported rather than assumed.
          </div>
        )}
        {!busy && state === "error" && (
          <p className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>
            Neighbour state could not be read: {err}
          </p>
        )}

        {rows.length > 0 && (
          <div className="bgp-scroll">
            <table className="tbl bgp-tbl" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Router</th><th>Neighbour</th><th>Their AS</th><th>State</th>
                  <th>Reported by</th><th className="num">Learned</th><th className="num">Withdrawn</th><th>Last change</th>
                </tr>
              </thead>
              <tbody>
                {peerCap.rows.map((r) => (
                  <tr key={r.key}>
                    <td className="mono">{r.device || "—"}</td>
                    <td className="mono">{r.peer || "—"}</td>
                    <td className="mono">{r.peerAs ? `AS${r.peerAs}` : "—"}</td>
                    <td>{stateChip(r)}</td>
                    <td>
                      <span className="mini-meta" title={r.source === "bmp"
                        ? "Reported by the router's own BMP export (Adj-RIB-In)."
                        : "Sampled from the router's own BGP peer-state counter — only 'established' counts as up."}>
                        {r.source === "bmp" ? "BMP" : "device metric"}
                      </span>
                    </td>
                    <td className="mono num">{r.announced ?? "—"}</td>
                    <td className="mono num">{r.withdrawn ?? "—"}</td>
                    <td className="mini-meta">{r.changedAt ? new Date(r.changedAt).toLocaleString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <ShowAll cap={peerCap} noun="peers" />

        {sessions?.coverage?.notes?.length ? (
          <ul className="mini-meta" style={{ marginBottom: 0, paddingLeft: 18 }}>
            {sessions.coverage.notes.map((n, i) => <li key={i}>{n}</li>)}
          </ul>
        ) : null}
      </SubBlock>

      <SubBlock title="Who carries your traffic">
        {withTransit.length === 0 ? (
          <div className="empty">
            No paths have been observed for the watched prefixes yet, so we cannot say who is carrying them. With no
            measurement there is nothing to show, and nothing is assumed.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {transitCap.rows.map((inc) => (
              <div key={inc.prefix} style={{
                display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap",
                padding: "6px 8px", borderRadius: 6, border: "1px solid var(--border)",
              }}>
                <span className="mono" style={{ minWidth: 160 }}>{inc.prefix}</span>
                {inc.class === "route_leak" && (
                  <Chip label="Carrier changed" tone="var(--warn)" title={inc.summary} />
                )}
                {inc.class === "visibility_loss" && (
                  <Chip label="Flapping or withdrawn" tone="var(--warn)" title={inc.summary} />
                )}
                {transitSet(inc).slice(0, 10).map((t) => (
                  <span key={t.asn} className="mono" title={t.adjacent
                    ? "Your direct upstream — the hop next to the origin."
                    : "Seen further up the path."} style={{
                    padding: "2px 8px", borderRadius: 999, fontSize: 13,
                    border: "1px solid var(--border)",
                    background: t.adjacent ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--surface)",
                  }}>
                    AS{t.asn}
                  </span>
                ))}
              </div>
            ))}
            <ShowAll cap={transitCap} noun="prefixes" />
          </div>
        )}
        <p className="mini-meta">
          The highlighted AS is your direct upstream. A carrier that changed without a maintenance window is what the
          watchlist flags as unexpected transit.
        </p>
        <Details summary="Where these rows come from">
          <p className="mini-meta">
            Two witnesses, never conflated. A row reported by BMP comes from one of your own routers pushing its
            Adj-RIB-In to the platform, and it is the only source carrying the reason for a change and the counters; a
            row reported by a device metric is an SNMP or gNMI sample of the same session seen from outside. Where both
            describe the same router and neighbour, the router&apos;s own report wins.
          </p>
          <p className="mini-meta" style={{ marginBottom: 0 }}>
            Who carries your traffic is derived from the AS paths the watchlist evaluator measured — it is an
            observation, never an assumption about your contracts.
          </p>
        </Details>
      </SubBlock>
    </Section>
  );
}

export default PeersPanel;
