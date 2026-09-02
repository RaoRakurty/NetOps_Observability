import { useEffect, useState } from "react";
import { vrfTerm } from "../lib/vendorTerms";
import { api, Device, TopoLink, PromInstantSeries } from "../services/api";

// DeviceNeighbors — the Routing & neighbors tab of the device page. Three live
// views, all from data we already collect: L2/topology neighbors (LLDP/CDP/BGP-LS
// via /api/topology/links), BGP peers (device_bgp_peer_state, 1..6), and OSPF
// neighbors (device_ospf_nbr_state, 1..8). State→label + a colour dot so an
// operator reads adjacency health at a glance. Empty states are honest.

const BGP_STATE: Record<string, string> = { "1": "idle", "2": "connect", "3": "active", "4": "opensent", "5": "openconfirm", "6": "established" };
const OSPF_STATE: Record<string, string> = { "1": "down", "2": "attempt", "3": "init", "4": "two-way", "5": "exch-start", "6": "exchange", "7": "loading", "8": "full" };
const tone = (up: boolean) => (up ? "var(--good)" : "var(--bad)");

function StateDot({ color }: { color: string }) {
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 999, background: color, marginRight: 8, flex: "none" }} />;
}

function Section({ title, sub, children }: { title: string; sub?: string; children: React.ReactNode }) {
  return (
    <div className="cc-panel" style={{ marginBottom: 14 }}>
      <div className="cc-panel-h"><h3 className="cc-panel-t">{title}</h3>{sub && <span className="cc-panel-meta">{sub}</span>}</div>
      <div style={{ padding: "6px 4px 10px" }}>{children}</div>
    </div>
  );
}

const th: React.CSSProperties = { textAlign: "left", fontSize: 11, textTransform: "uppercase", letterSpacing: ".04em", color: "var(--fg-muted)", padding: "4px 12px", fontWeight: 600 };
const td: React.CSSProperties = { padding: "5px 12px", fontSize: 12.5, borderTop: "1px solid var(--panel-border, var(--border))" };
const mono: React.CSSProperties = { ...td, fontFamily: "var(--font-mono)" };

export default function DeviceNeighbors({ device }: { device: Device }) {
  const [links, setLinks] = useState<TopoLink[] | null>(null);
  const [bgp, setBgp] = useState<PromInstantSeries[] | null>(null);
  const [ospf, setOspf] = useState<PromInstantSeries[] | null>(null);
  const id = device.id;

  useEffect(() => {
    let alive = true;
    api.topologyLinks().then((r) => alive && setLinks((r?.links ?? []).filter((l) => l.source === id || l.target === id))).catch(() => alive && setLinks([]));
    api.metricsQuery(`device_bgp_peer_state{device="${id}"}`).then((r) => alive && setBgp(r?.data?.result ?? [])).catch(() => alive && setBgp([]));
    api.metricsQuery(`device_ospf_nbr_state{device="${id}"}`).then((r) => alive && setOspf(r?.data?.result ?? [])).catch(() => alive && setOspf([]));
    return () => { alive = false; };
  }, [id]);

  return (
    <div style={{ maxWidth: 1100 }}>
      <Section title="Layer-2 / topology neighbors" sub={links ? `${links.length} adjacenc${links.length === 1 ? "y" : "ies"} · LLDP · CDP · BGP-LS` : "loading…"}>
        {links === null ? <div className="empty">Loading…</div> : links.length === 0 ? <p className="mini-meta" style={{ padding: "0 12px" }}>No LLDP/CDP/BGP-LS neighbors observed for this device.</p> : (
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
                    <td style={td}><span className="badge accent-badge" style={{ textTransform: "uppercase", fontSize: 10 }}>{proto}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="BGP neighbors" sub={bgp ? `${bgp.length} peer${bgp.length === 1 ? "" : "s"}` : "loading…"}>
        {bgp === null ? <div className="empty">Loading…</div> : bgp.length === 0 ? <p className="mini-meta" style={{ padding: "0 12px" }}>No BGP peers have been seen for this device.</p> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={th}>Peer</th><th style={th}>State</th><th style={th}>AS / {vrfTerm(device.vendor)}</th></tr></thead>
            <tbody>
              {bgp.map((s, i) => {
                const v = String(Math.round(Number(s.value?.[1])));
                const label = BGP_STATE[v] ?? `state ${v}`; const up = v === "6";
                return (
                  <tr key={i}>
                    <td style={mono}>{s.metric.index || s.metric.peer || "—"}</td>
                    <td style={td}><StateDot color={tone(up)} />{label}</td>
                    <td style={td}>{s.metric.asn || s.metric.vrf || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="OSPF neighbors" sub={ospf ? `${ospf.length} adjacenc${ospf.length === 1 ? "y" : "ies"}` : "loading…"}>
        {ospf === null ? <div className="empty">Loading…</div> : ospf.length === 0 ? <p className="mini-meta" style={{ padding: "0 12px" }}>No OSPF neighbours have been seen for this device.</p> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={th}>Neighbor</th><th style={th}>State</th></tr></thead>
            <tbody>
              {ospf.map((s, i) => {
                const v = String(Math.round(Number(s.value?.[1])));
                const label = OSPF_STATE[v] ?? `state ${v}`; const up = v === "8";
                return <tr key={i}><td style={mono}>{s.metric.index || s.metric.nbr || "—"}</td><td style={td}><StateDot color={tone(up)} />{label}</td></tr>;
              })}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}
