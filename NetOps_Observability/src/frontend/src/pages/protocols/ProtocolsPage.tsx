// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ProtocolsPage — Analytics › Protocol Monitoring: one leaf, three tabs.
//
//   #/analytics/protocols/bgp    BGP — the outage view (sessions down or
//                                flapping, prefixes, what to do next), formerly
//                                its own "BGP Operations" leaf, plus session
//                                trends behind a closed group
//   #/analytics/protocols/ospf   OSPF adjacencies — what needs attention first
//   #/analytics/protocols/isis   IS-IS adjacencies — the same
//
// Owner, 2026-11-22: "lots of verbose … make it more elegant and useful". What
// left the page: the "Device context" group (uptime and interfaces up live on
// Device Monitoring), the PromQL count tiles (`count(...) or vector(0)` drew a
// green 0 both for "all up" and for "nothing collects this", and the tab's own
// counts already answer honestly), the state-code legend sentences (Ask Iris),
// and the coverage paragraphs (the chips keep the fact; the detail is a tooltip).
// Trends stay, closed, and mount only when opened so a closed group does not poll.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { MetricLine } from "../../components/board/panels";
import AskIris from "../../components/AskIris";
import { api, type CorrObject, type Device } from "../../services/api";
import BgpOps from "../BgpOps";
import IgpAdjacencies from "../igp/IgpAdjacencies";
import {
  PROTOCOL_TABS, deviceIndex, problemsByDevice, tabFromHash, tabHash, type ProtocolTab,
} from "./protocolsModel";

/** A closed-by-default group whose body mounts only once it is opened. */
function Trends({ title, keyNote, children }: { title: string; keyNote?: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <details className="dm-group protocols-trends" onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary className="dm-group-head">{title}</summary>
      {open && (
        <div className="dm-group-body">
          {keyNote && <p className="proto-key">{keyNote}</p>}
          <div className="dm-grid">{children}</div>
        </div>
      )}
    </details>
  );
}

export default function ProtocolsPage({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  const [tab, setTab] = useState<ProtocolTab>(() => tabFromHash(typeof window === "undefined" ? "" : window.location.hash));
  const [devices, setDevices] = useState<Device[]>([]);
  const [corrs, setCorrs] = useState<CorrObject[]>([]);

  useEffect(() => {
    const apply = () => setTab(tabFromHash(window.location.hash));
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  // Inventory (names, sites) and open problems, read once for the IGP tabs'
  // "Problem" chips. Either read failing leaves the chips out, never the page.
  useEffect(() => {
    let alive = true;
    Promise.resolve().then(() => api.devices())
      .then((d) => { if (alive) setDevices(Array.isArray(d) ? d : []); })
      .catch(() => { /* names fall back to ids */ });
    Promise.resolve().then(() => api.correlations(200, 86400, "open"))
      .then((r) => { if (alive) setCorrs(Array.isArray(r?.data) ? r.data : []); })
      .catch(() => { /* no chips */ });
    return () => { alive = false; };
  }, []);

  const problems = useMemo(() => problemsByDevice(corrs, deviceIndex(devices)), [corrs, devices]);

  const open = (t: ProtocolTab) => {
    if (t === tab) return;
    window.location.hash = tabHash(t);
    setTab(t);
  };

  return (
    <div className="paths-shell paths-page protocols-page" data-testid="protocols-page">
      <div className="paths-head">
        <h2>Protocol Monitoring</h2>
        <nav className="paths-tabs" role="tablist" aria-label="Protocols">
          {PROTOCOL_TABS.map((t) => (
            <button key={t.id} type="button" role="tab" id={`protocols-tab-${t.id}`}
              aria-selected={tab === t.id} aria-controls="protocols-panel" className="paths-tab"
              data-testid={`protocols-tab-${t.id}`} onClick={() => open(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div id="protocols-panel" role="tabpanel" aria-labelledby={`protocols-tab-${tab}`}>
        {tab === "bgp" && (
          <>
            <BgpOps embedded />
            <Trends title="Session trends" keyNote={<>State 6 is established.<AskIris topic="bgp.peer-states" label="BGP peer state" /></>}>
              <MetricLine title="Peer state over time" query="device_bgp_peer_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "peer"]} stepped />
              <MetricLine title="Session changes (/min)" query="rate(device_bgp_fsm_transitions[5m]) * 60" minutes={m} fmtY={(n) => `${n.toFixed(2)}/min`} labelKeys={["device", "peer"]} />
              <MetricLine title="Prefixes received" query="device_bgp_pfx_in" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "peer"]} stepped />
            </Trends>
          </>
        )}
        {tab === "ospf" && (
          <>
            <IgpAdjacencies proto="ospf" problems={problems} />
            <Trends title="State trends" keyNote={<>State 8 is full.<AskIris topic="ospf.neighbor-states" label="OSPF neighbor state" /></>}>
              <MetricLine title="Neighbor state over time" query="device_ospf_nbr_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "neighbor"]} stepped />
              <MetricLine title="Interface state over time" query="device_ospf_if_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
            </Trends>
          </>
        )}
        {tab === "isis" && (
          <>
            <IgpAdjacencies proto="isis" problems={problems} />
            <Trends title="State trends" keyNote={<>State 3 is up.<AskIris topic="isis.adjacency-states" label="IS-IS adjacency state" /></>}>
              <MetricLine title="Adjacency state over time" query="device_isis_adj_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "isis_neighbor"]} stepped />
              <MetricLine title="Adjacencies up by device" query="count by (device) (device_isis_adj_state == 3)" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device"]} stepped />
            </Trends>
          </>
        )}
      </div>
    </div>
  );
}
