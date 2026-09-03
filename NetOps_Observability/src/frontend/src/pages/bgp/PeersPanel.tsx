// PeersPanel — the Peers tab (BGP ops tracker #4): BGP adjacency and transit in
// one table.
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
import { Section, ShowAll, SubBlock, useCap } from "./Section";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_PEERS = 12;
const FIRST_TRANSIT = 6;

const PEER_QUERY = "device_bgp_peer_state";

function stateChip(r: PeerRow) {
  if (r.state === "up") return <Chip label="UP" tone="var(--ok)" title="Established" />;
  if (r.state === "down") return <Chip label="DOWN" tone="var(--crit)" title={r.reason || "Not established"} />;
  return (
    <Chip
      label="UNKNOWN"
      tone="var(--muted)"
      title="No peer state has been observed for this session. This is an absent measurement, not a healthy peer."
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
    <Section id="peers" title="Peers — sessions and transit" updatedAt={at}>
      <SubBlock title="BGP peers">

        {busy && rows.length === 0 && <div className="empty">Reading peer state…</div>}

        {!busy && state === "bmp_off" && (
          <div className="empty">
            The BMP receiver is not running (<span className="mono">FEATURE_BMP</span> is off) and no device is
            reporting <span className="mono">device_bgp_peer_state</span>. This is an absent feed, not a healthy fleet:
            point a router's BMP export at the platform, or enable the BGP peer OID in the device profile.
          </div>
        )}
        {!busy && state === "no_exporter" && (
          <div className="empty">
            No router is exporting BMP to this platform, and no device peer-state samples arrived. Nothing is being
            measured here yet — this is an empty FEED, not a converged network.
          </div>
        )}
        {!busy && state === "no_peers" && (
          <div className="empty">
            {sessions?.sessions.length} BMP session(s) are open, but no Peer Up or Peer Down has been observed on any of
            them. Peer state is reported as unknown rather than assumed.
          </div>
        )}
        {!busy && state === "error" && (
          <p className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>
            Peer state could not be read: {err}
          </p>
        )}

        {rows.length > 0 && (
          <div className="bgp-scroll">
            <table className="tbl bgp-tbl" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Device</th><th>Peer</th><th>AS</th><th>State</th>
                  <th>Source</th><th>Announced</th><th>Withdrawn</th><th>Changed</th>
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
                        : "Sampled from the device's own BGP peer-state counter — only 'established' counts as up."}>
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

      <SubBlock title="Transit per watched prefix">
        {withTransit.length === 0 ? (
          <div className="empty">
            No AS paths have been observed for the watched prefixes yet. The transit set is derived from the paths the
            evaluator measured — with no measurement there is nothing to show, and nothing is assumed.
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
                  <Chip label="TRANSIT CHANGED" tone="var(--warn)" title={inc.summary} />
                )}
                {inc.class === "visibility_loss" && (
                  <Chip label="FLAPPING / WITHDRAWN" tone="var(--warn)" title={inc.summary} />
                )}
                {transitSet(inc).slice(0, 10).map((t) => (
                  <span key={t.asn} className="mono" title={t.adjacent
                    ? "The hop adjacent to the origin — this prefix's actual upstream."
                    : "Observed further up the path."} style={{
                    padding: "2px 8px", borderRadius: 999, fontSize: 12,
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
        <p className="mini-meta" style={{ marginBottom: 0 }}>
          The upstream chip is the hop adjacent to the origin. A transit set that changed without a maintenance window
          is the route-leak signature the incidents section classifies.
        </p>
      </SubBlock>
    </Section>
  );
}

export default PeersPanel;
