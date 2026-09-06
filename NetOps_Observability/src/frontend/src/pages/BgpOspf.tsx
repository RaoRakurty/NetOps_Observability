// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import {
  Group, MetricLine, MetricTop, MetricStat, fmtUptime,
} from "../components/board/panels";
import IgpAdjacencies from "./igp/IgpAdjacencies";
import AskIris from "../components/AskIris";

// Routing protocols — BGP / OSPF / IS-IS session & adjacency health.
//   BGP   is gNMI-OWNED per-device (single-contract): device_bgp_peer_state /
//         _fsm_transitions / _pfx_in, labelled {device, peer, vrf}. On gNMI-capable
//         devices SNMP yields BGP to gNMI; on agentless gear SNMP stays the floor and
//         emits the same {peer} contract — so the panels work for either source.
//   OSPF  is SNMP-owned (OSPF-MIB ospfNbrTable/ospfIfTable), labelled {device, neighbor}.
//   IS-IS is gNMI-owned (the fabric IGP — leaf↔spine L2): device_isis_adj_state,
//         labelled {device, ifName, isis_level, isis_neighbor}.
// Panels show "No data" until a device exposes the corresponding session/adjacency.
//
// UI-words sweep 4 (tracker 270): the three protocol state-code legends (six BGP
// FSM states, eight OSPF neighbour states, four IS-IS adjacency states) left the
// page. `.proto-key` keeps the one fact an operator acts on — which value means
// healthy — and the `(i)` beside it reaches the authored file that names the rest
// (ai/skills/explain/{bgp.peer-states,ospf.neighbor-states,isis.adjacency-states}.md).
// A STATED FACT is not an explanatory note, which is why this is not a mini-meta.
//
// ADVANCED OSPF / IS-IS (Project 4 D item 11) is the IgpAdjacencies block in
// each IGP group. The PromQL stat panels below CANNOT be honest on their own:
// `count(device_ospf_nbr_state != 8) or vector(0)` renders "0 neighbours not
// full" both when every neighbour is full AND when nothing collects OSPF here.
// The advanced view reads /api/protocols/{proto}/* instead, which reports an
// uncollected source as "not collected" with the reason attached, joins the
// live state to the syslog/trap adjacency-change history, and gives a
// per-adjacency timeline and a per-device roll-up. Read the coverage strip
// there before believing a zero anywhere on this page.

export default function BgpOspf({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  return (
    <div className="dm-board">
      <Group title="Device context" hue="#94A3B8">
        <div className="dm-grid">
          <MetricTop title="System uptime by device" query="device_sysuptime / 100" minutes={m} fmtX={fmtUptime} labelKeys={["device"]} />
          <MetricTop title="Interfaces up by device" query='count by (device) (device_if_oper_status == 1)' minutes={m} fmtX={(n) => `${n.toFixed(0)}`} labelKeys={["device"]} />
        </div>
      </Group>

      <Group title="BGP sessions" hue="#F59E0B">
        <div className="ds-stats">
          <MetricStat label="Established peers" query="count(device_bgp_peer_state == 6) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "")} />
          <MetricStat label="Peers not established" query="count(device_bgp_peer_state != 6) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
          <MetricStat label="Total BGP peers" query="count(device_bgp_peer_state) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
        </div>
        <div className="dm-grid">
          <MetricLine title="BGP peer state over time" query="device_bgp_peer_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "peer"]} stepped />
          <MetricLine title="BGP established transitions (/min)" query="rate(device_bgp_fsm_transitions[5m]) * 60" minutes={m} fmtY={(n) => `${n.toFixed(2)}/min`} labelKeys={["device", "peer"]} />
          <MetricLine title="BGP prefixes received" query="device_bgp_pfx_in" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "peer"]} stepped />
        </div>
        <p className="proto-key">Only state 6 carries routes.<AskIris topic="bgp.peer-states" label="BGP peer state" /></p>
      </Group>

      <Group title="OSPF adjacencies" hue="#0EA5E9">
        <div className="ds-stats">
          <MetricStat label="Full adjacencies" query="count(device_ospf_nbr_state == 8) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "")} />
          <MetricStat label="Neighbors not full" query="count(device_ospf_nbr_state != 8) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "warn" : "good")} />
          <MetricStat label="OSPF interfaces" query="count(device_ospf_if_state) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
        </div>
        <div className="dm-grid">
          <MetricLine title="OSPF neighbor state over time" query="device_ospf_nbr_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "neighbor"]} stepped />
          <MetricLine title="OSPF interface state over time" query="device_ospf_if_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
        </div>
        <p className="proto-key">Only state 8 is a full adjacency.<AskIris topic="ospf.neighbor-states" label="OSPF neighbour state" /></p>
        <IgpAdjacencies proto="ospf" />
      </Group>

      <Group title="IS-IS adjacencies" hue="#10B981">
        <div className="ds-stats">
          <MetricStat label="Adjacencies up" query="count(device_isis_adj_state == 3) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "")} />
          <MetricStat label="Adjacencies not up" query="count(device_isis_adj_state != 3) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
          <MetricStat label="Total adjacencies" query="count(device_isis_adj_state) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
        </div>
        <div className="dm-grid">
          <MetricLine title="IS-IS adjacency state over time" query="device_isis_adj_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "isis_neighbor"]} stepped />
          <MetricLine title="IS-IS adjacencies by device" query="count by (device) (device_isis_adj_state == 3)" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device"]} stepped />
        </div>
        <p className="proto-key">Only state 3 is up.<AskIris topic="isis.adjacency-states" label="IS-IS adjacency state" /></p>
        <IgpAdjacencies proto="isis" />
      </Group>
    </div>
  );
}
