// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { GLOBAL_DEFAULT_LABEL, instanceDisplay, vrfTerm } from "../lib/vendorTerms";
import { api, Device, TopoLink, PromInstantSeries } from "../services/api";
import { operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";

// DeviceNeighbors — the Neighbours tab of the device page. Three live
// views, all from data we already collect: L2/topology neighbors (LLDP/CDP/BGP-LS
// via /api/topology/links), BGP peers (device_bgp_peer_state, 1..6), and OSPF
// neighbors (device_ospf_nbr_state, 1..8). State→label + a colour dot so an
// operator reads adjacency health at a glance. Empty states are honest.

const BGP_STATE: Record<string, string> = { "1": "idle", "2": "connect", "3": "active", "4": "opensent", "5": "openconfirm", "6": "established" };
const OSPF_STATE: Record<string, string> = { "1": "down", "2": "attempt", "3": "init", "4": "two-way", "5": "exch-start", "6": "exchange", "7": "loading", "8": "full" };
// Cisco SD-WAN OMP session states (VIPTELA-OMP / CISCO-SDWAN-OMP-MIB); up(3)
// and up-in-gr(8, graceful restart) are healthy.
export const OMP_STATE: Record<string, string> = {
  "0": "invalid", "1": "init", "2": "handshake", "3": "up", "4": "down",
  "5": "init (graceful restart)", "6": "down (graceful restart)", "7": "handshake (graceful restart)", "8": "up (graceful restart)",
};
export const ompUp = (v: string) => v === "3" || v === "8";

/** BGP4-MIB series carry no vrf label; the VRF lanes say "default" for the same table. */
export const peerKey = (vrf: string | undefined, peer: string) => {
  const v = (vrf ?? "").toLowerCase();
  return `${v === "" || v === "default" || v === "global" || v === "master" ? "" : vrf}|${peer}`;
};
const tone = (up: boolean) => (up ? "var(--good)" : "var(--bad)");

function StateDot({ color }: { color: string }) {
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 999, background: color, marginRight: 8, flex: "none" }} />;
}

function Section({ title, sub, ask, children }: { title: string; sub?: string; ask?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="cc-panel" style={{ marginBottom: 14 }}>
      <div className="cc-panel-h"><h3 className="cc-panel-t">{title}</h3>{ask}{sub && <span className="cc-panel-meta">{sub}</span>}</div>
      <div style={{ padding: "6px 4px 10px" }}>{children}</div>
    </div>
  );
}

const th: React.CSSProperties = { textAlign: "left", fontSize: 12.5, letterSpacing: ".04em", color: "var(--fg-muted)", padding: "4px 12px", fontWeight: 500 };
const td: React.CSSProperties = { padding: "5px 12px", fontSize: 12.5, borderTop: "1px solid var(--panel-border, var(--border))" };
const mono: React.CSSProperties = { ...td, fontFamily: "var(--font-mono)" };

export default function DeviceNeighbors({ device }: { device: Device }) {
  const [links, setLinks] = useState<TopoLink[] | null>(null);
  // The adjacency READ failing is not the same fact as this device having no
  // neighbour (tracker 290). This tab used to catch the failure into an empty
  // list and render "No neighbour protocol reported one here." — a statement
  // about the network, made from no evidence at all. /api/topology/links now
  // refuses (502) rather than answering count:0, and the refusal is shown.
  const [linksError, setLinksError] = useState<string | null>(null);
  const [bgp, setBgp] = useState<PromInstantSeries[] | null>(null);
  const [ospf, setOspf] = useState<PromInstantSeries[] | null>(null);
  // An unread metric query is UNKNOWN, never "no peers" (the tracker-290 rule
  // the adjacency section already follows).
  const [bgpErr, setBgpErr] = useState<string | null>(null);
  const [ospfErr, setOspfErr] = useState<string | null>(null);
  const [remoteAs, setRemoteAs] = useState<Map<string, string>>(new Map());
  // OMP (SD-WAN control plane). null = not read yet; [] with no counts = this
  // device runs no OMP, and the section stays hidden.
  const [omp, setOmp] = useState<PromInstantSeries[] | null>(null);
  const [ompCounts, setOmpCounts] = useState<{ up: number; notUp: number } | null>(null);
  const [ompErr, setOmpErr] = useState<string | null>(null);
  const id = device.id;

  useEffect(() => {
    let alive = true;
    api.topologyLinks()
      .then((r) => {
        if (!alive) return;
        setLinks((r?.links ?? []).filter((l) => l.source === id || l.target === id));
        setLinksError(null);
      })
      .catch((e) => {
        if (!alive) return;
        setLinks([]);
        setLinksError(operatorError(e, "The adjacency evidence could not be read."));
      });
    api.metricsQuery(`device_bgp_peer_state{device="${id}"}`)
      .then((r) => { if (alive) { setBgp(r?.data?.result ?? []); setBgpErr(null); } })
      .catch((e) => { if (alive) { setBgp([]); setBgpErr(operatorError(e, "BGP peer state could not be read.")); } });
    api.metricsQuery(`device_bgp_peer_remote_as{device="${id}"}`)
      .then((r) => {
        if (!alive) return;
        const m = new Map<string, string>();
        for (const s of r?.data?.result ?? []) {
          const peer = s.metric.peer || s.metric.index;
          // Keyed by instance too: one peer address can live in two VRFs.
          if (peer) m.set(peerKey(s.metric.vrf, peer), String(Math.round(Number(s.value?.[1]))));
        }
        setRemoteAs(m);
      })
      .catch(() => { /* best-effort column: the AS cell shows — and the state is unaffected */ });
    api.metricsQuery(`device_omp_peer_state{device="${id}"}`)
      .then((r) => { if (alive) { setOmp(r?.data?.result ?? []); setOmpErr(null); } })
      .catch((e) => { if (alive) { setOmp([]); setOmpErr(operatorError(e, "OMP session state could not be read.")); } });
    api.metricsQuery(`device_omp_peers{device="${id}"}`)
      .then((r) => {
        if (!alive) return;
        const rows = r?.data?.result ?? [];
        if (rows.length === 0) { setOmpCounts(null); return; }
        const get = (st: string) => Math.round(Number(rows.find((x) => x.metric.state === st)?.value?.[1] ?? 0));
        setOmpCounts({ up: get("up"), notUp: get("not_up") });
      })
      .catch(() => { /* the per-peer read reports the failure */ });
    api.metricsQuery(`device_ospf_nbr_state{device="${id}"}`)
      .then((r) => { if (alive) { setOspf(r?.data?.result ?? []); setOspfErr(null); } })
      .catch((e) => { if (alive) { setOspf([]); setOspfErr(operatorError(e, "OSPF neighbor state could not be read.")); } });
    return () => { alive = false; };
  }, [id]);

  return (
    <div style={{ maxWidth: 1100 }}>
      <Section title="Neighbors" sub={linksError ? "unread" : links ? `${links.length} adjacenc${links.length === 1 ? "y" : "ies"}` : "loading…"} ask={<AskIris topic="device.neighbors" label="Neighbours" />}>
        {linksError ? (
          <p role="alert" data-testid="device-neighbours-unread" style={{ color: "var(--bad)", padding: "0 12px" }}>
            The adjacency evidence could not be read, so this device&rsquo;s neighbors are UNKNOWN here — not absent. {linksError}
          </p>
        ) : links === null ? <div className="empty">Loading…</div> : links.length === 0 ? <p className="cc-empty" style={{ padding: "0 12px" }}>No neighbor protocol reported one here.</p> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={th}>Local port</th><th style={th}>Neighbor</th><th style={th}>Remote port</th><th style={th}>Protocol</th></tr></thead>
            <tbody>
              {links.map((l, i) => {
                const local = l.source === id; const nbr = local ? l.target_name : l.source_name;
                const proto = l.igp ? `${l.source_protocol} · ${l.igp}` : l.source_protocol;
                return (
                  <tr key={i}>
                    <td style={mono}>{(local ? l.local_port : l.remote_port) || "—"}</td>
                    <td style={td}>{nbr || "—"}</td>
                    <td style={mono}>{(local ? l.remote_port : l.local_port) || "—"}</td>
                    <td style={td}><span className="badge accent-badge" style={{ fontSize: 12.5 }}>{proto}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="BGP neighbors" sub={bgpErr ? "unread" : bgp ? `${bgp.length} peer${bgp.length === 1 ? "" : "s"}` : "loading…"}>
        {bgpErr ? (
          <p role="alert" data-testid="device-bgp-unread" style={{ color: "var(--bad)", padding: "0 12px" }}>
            BGP state could not be read, so this device&rsquo;s BGP peers are UNKNOWN here — not absent. {bgpErr}
          </p>
        ) : bgp === null ? <div className="empty">Loading…</div> : bgp.length === 0 ? <p className="cc-empty" style={{ padding: "0 12px" }}>No BGP peer seen on this device.</p> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={th}>Peer</th><th style={th}>State</th><th style={th}>Remote AS</th><th style={th}>{vrfTerm(device.vendor)}</th></tr></thead>
            <tbody>
              {bgp.map((s, i) => {
                const v = String(Math.round(Number(s.value?.[1])));
                const label = BGP_STATE[v] ?? `state ${v}`; const up = v === "6";
                const peer = s.metric.peer || s.metric.index || "";
                return (
                  <tr key={i}>
                    <td style={mono}>{peer || "—"}</td>
                    <td style={td}><StateDot color={tone(up)} />{label}</td>
                    <td style={mono}>{remoteAs.get(peerKey(s.metric.vrf, peer)) || s.metric.asn || "—"}</td>
                    <td style={td} title={s.metric.vrf ? instanceDisplay(s.metric.vrf, device.vendor).title : s.metric.vrf === undefined ? "BGP4-MIB reports the default routing table" : undefined}>
                      {s.metric.vrf ? instanceDisplay(s.metric.vrf, device.vendor).text : s.metric.vrf === undefined ? GLOBAL_DEFAULT_LABEL : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      {(ompErr || ompCounts || (omp && omp.length > 0)) && (
        <Section
          title="SD-WAN control sessions (OMP)"
          sub={ompErr ? "unread" : ompCounts ? `${ompCounts.up} up · ${ompCounts.notUp} not up` : "loading…"}
        >
          {ompErr ? (
            <p role="alert" data-testid="device-omp-unread" style={{ color: "var(--bad)", padding: "0 12px" }}>
              OMP state could not be read, so this device&rsquo;s control sessions are UNKNOWN here — not absent. {ompErr}
            </p>
          ) : omp && omp.length > 0 ? (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><th style={th}>Peer system IP</th><th style={th}>Peer</th><th style={th}>State</th><th style={th}>Site</th></tr></thead>
              <tbody>
                {omp.map((s, i) => {
                  const v = String(Math.round(Number(s.value?.[1])));
                  return (
                    <tr key={i}>
                      <td style={mono}>{s.metric.peer || "—"}</td>
                      <td style={td}>{s.metric.type || "—"}</td>
                      <td style={td}><StateDot color={tone(ompUp(v))} />{OMP_STATE[v] ?? `state ${v}`}</td>
                      <td style={mono}>{s.metric.site_id || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : ompCounts && ompCounts.up + ompCounts.notUp > 0 ? (
            <p className="cc-empty" style={{ padding: "0 12px" }}>Controller — session counts only.</p>
          ) : (
            <p className="cc-empty" style={{ padding: "0 12px" }}>This device reports no OMP session.</p>
          )}
        </Section>
      )}

      <Section title="OSPF neighbors" sub={ospfErr ? "unread" : ospf ? `${ospf.length} adjacenc${ospf.length === 1 ? "y" : "ies"}` : "loading…"}>
        {ospfErr ? (
          <p role="alert" data-testid="device-ospf-unread" style={{ color: "var(--bad)", padding: "0 12px" }}>
            OSPF state could not be read, so this device&rsquo;s OSPF neighbors are UNKNOWN here — not absent. {ospfErr}
          </p>
        ) : ospf === null ? <div className="empty">Loading…</div> : ospf.length === 0 ? <p className="cc-empty" style={{ padding: "0 12px" }}>No OSPF neighbor seen on this device.</p> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={th}>Neighbor</th><th style={th}>State</th></tr></thead>
            <tbody>
              {ospf.map((s, i) => {
                const v = String(Math.round(Number(s.value?.[1])));
                const label = OSPF_STATE[v] ?? `state ${v}`; const up = v === "8";
                // The adjacency contract's label is "neighbor" (profiles.go); rows
                // written before the rename carry "index".
                return <tr key={i}><td style={mono}>{s.metric.neighbor || s.metric.index || s.metric.nbr || "—"}</td><td style={td}><StateDot color={tone(up)} />{label}</td></tr>;
              })}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}
