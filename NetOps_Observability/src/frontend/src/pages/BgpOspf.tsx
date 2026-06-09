import {
  Group, MetricLine, MetricTop, MetricStat, fmtUptime,
} from "../components/board/panels";

// BGP / OSPF Overview — routing-protocol session & adjacency health. Backed by
// the BGP4-MIB (bgpPeerTable) and OSPF-MIB (ospfNbrTable/ospfIfTable) metrics the
// SNMP collector now walks (added to the generic profile): device_bgp_peer_state,
// device_bgp_fsm_transitions, device_bgp_in_updates, device_ospf_nbr_state,
// device_ospf_if_state — labelled device + index (peer/neighbor address). Panels
// show "No data" until a device with BGP/OSPF sessions exposes those MIBs.

const BGP_STATES = "1 idle · 2 connect · 3 active · 4 opensent · 5 openconfirm · 6 established";
const OSPF_STATES = "1 down · 2 attempt · 3 init · 4 twoWay · 5 exchangeStart · 6 exchange · 7 loading · 8 full";

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

      <Group title="BGP — session health" hue="#F59E0B">
        <div className="ds-stats">
          <MetricStat label="Established peers" query="count(device_bgp_peer_state == 6) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "")} />
          <MetricStat label="Peers not established" query="count(device_bgp_peer_state != 6) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
          <MetricStat label="Total BGP peers" query="count(device_bgp_peer_state) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
        </div>
        <div className="dm-grid">
          <MetricLine title="BGP peer state over time" query="device_bgp_peer_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
          <MetricLine title="BGP established transitions (/min)" query="rate(device_bgp_fsm_transitions[5m]) * 60" minutes={m} fmtY={(n) => `${n.toFixed(2)}/min`} labelKeys={["device", "index"]} />
          <MetricLine title="BGP update rate (/s)" query="rate(device_bgp_in_updates[5m])" minutes={m} fmtY={(n) => `${n.toFixed(2)}/s`} labelKeys={["device", "index"]} />
        </div>
        <p className="mini-meta" style={{ margin: 0 }}><strong>BGP peer state</strong>: {BGP_STATES}</p>
      </Group>

      <Group title="OSPF — IGP health" hue="#0EA5E9">
        <div className="ds-stats">
          <MetricStat label="Full adjacencies" query="count(device_ospf_nbr_state == 8) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "good" : "")} />
          <MetricStat label="Neighbors not full" query="count(device_ospf_nbr_state != 8) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "warn" : "good")} />
          <MetricStat label="OSPF interfaces" query="count(device_ospf_if_state) or vector(0)" minutes={m} fmt={(n) => `${n.toFixed(0)}`} />
        </div>
        <div className="dm-grid">
          <MetricLine title="OSPF neighbor state over time" query="device_ospf_nbr_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
          <MetricLine title="OSPF interface state over time" query="device_ospf_if_state" minutes={m} fmtY={(n) => `${n.toFixed(0)}`} labelKeys={["device", "index"]} stepped />
        </div>
        <p className="mini-meta" style={{ margin: 0 }}><strong>OSPF state</strong>: {OSPF_STATES}</p>
      </Group>
    </div>
  );
}
