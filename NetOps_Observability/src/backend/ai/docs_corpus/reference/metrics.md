---
title: Metric families
sidebar_label: Metric families
description: Every metric family Correlix collects, what it measures, which transport owns it, and whether it is collected by default.
page_type: reference
sidebar_position: 11
---

# Metric families

Correlix writes time series into VictoriaMetrics under the family names below. Every family carries a `device` label, and the interface families additionally carry `index`, `ifName` and `ifAlias`.

Two columns need a definition.

**Owner** is the transport that is allowed to produce the family. Only one transport ever produces a given series, so a device streaming gNMI and answering SNMP does not double-write the same measurement.

**Default** says whether the shipped compose file collects it without any further configuration. Only the SNMP families are collected by default. Every probe, synthetic, optics and gNMI family is opt-in.

## The ownership gate

Interfaces, CPU and temperature are **SNMP-owned even when gNMI is enabled**. The gNMI pipeline maps them, and then deletes them before publishing, precisely so the same canonical series cannot arrive from two transports. The deletion covers `device_if_*`, `device_cpu_percent` and `device_temp_celsius`.

The SNMP side enforces the mirror image: a metric yields to another transport only when it declares that transport as its owner **and** the device actually has that transport. Three metrics declare gNMI as their owner, all from BGP4-MIB: `device_bgp_peer_state`, `device_bgp_fsm_transitions` and `device_bgp_in_updates`.

The families gNMI carries that no SNMP profile produces are the IS-IS set and `device_bgp_pfx_in`. OSPF stays SNMP-owned; gNMI carries IS-IS here, not OSPF.

## Interface families

Every row is SNMP-owned and collected by default, from the generic profile that applies to every device.

| Family | Measures | Unit |
| --- | --- | --- |
| `device_if_oper_status` | `ifOperStatus` | Enum, 1 is up |
| `device_if_admin_status` | `ifAdminStatus` | Enum |
| `device_if_in_octets` | `ifHCInOctets` | Bytes, counter |
| `device_if_out_octets` | `ifHCOutOctets` | Bytes, counter |
| `device_if_in_errors` | `ifInErrors` | Counter |
| `device_if_out_errors` | `ifOutErrors` | Counter |
| `device_if_in_discards` | `ifInDiscards` | Counter |
| `device_if_out_discards` | `ifOutDiscards` | Counter |
| `device_if_in_ucast_pkts` | Unicast packets in | Counter |
| `device_if_out_ucast_pkts` | Unicast packets out | Counter |
| `device_if_in_mcast_pkts` | Multicast packets in | Counter |
| `device_if_out_mcast_pkts` | Multicast packets out | Counter |
| `device_if_in_bcast_pkts` | Broadcast packets in | Counter |
| `device_if_out_bcast_pkts` | Broadcast packets out | Counter |
| `device_if_speed` | `ifHighSpeed` | Megabits per second |
| `device_if_mtu` | `ifMtu` | Bytes |

## System and resource families

| Family | Measures | Owner | Default |
| --- | --- | --- | --- |
| `device_sysuptime` | `sysUpTime` | SNMP | Yes |
| `device_cpu_percent` | Processor load | SNMP | Yes |
| `device_mem_total_kb` | Total memory | SNMP | Yes |
| `device_storage_size` | Storage allocation units | SNMP | Yes |
| `device_storage_used` | Storage used | SNMP | Yes |
| `device_sensor_value` | ENTITY-SENSOR reading, sensor-dependent unit | SNMP | Yes |
| `device_entity_info` | Physical inventory, value always 1, read the labels | SNMP | Yes |
| `device_mem_percent` | Memory used, percent | gNMI on a device with no SNMP memory source, SNMP elsewhere | With gNMI, or via a vendor profile |

## Protocol families

| Family | Measures | Owner | Default |
| --- | --- | --- | --- |
| `device_bgp_peer_state` | `bgpPeerState`, labelled `peer` | gNMI where present, SNMP otherwise | Yes over SNMP |
| `device_bgp_fsm_transitions` | Established-state transitions | gNMI where present, SNMP otherwise | Yes over SNMP |
| `device_bgp_pfx_in` | Prefixes received | gNMI only | No |
| `device_ospf_nbr_state` | `ospfNbrState`, labelled `neighbor` | SNMP | Yes |
| `device_ospf_if_state` | `ospfIfState` | SNMP | Yes |
| `device_ospf_lsdb_count` | LSAs per area, labelled `area` | SNMP | Yes |
| `device_ospf_area` | Area membership. An info series: read the label, not the value. | SNMP | Yes |
| `device_ospf_spf_runs_total` | SPF runs per area | SNMP | Yes |
| `device_ospf_if_hello_seconds` | Hello interval per interface | SNMP | Yes |
| `device_ospf_if_dead_seconds` | Dead interval per interface | SNMP | Yes |
| `device_isis_adj_state` | Adjacency state | gNMI only | No |
| `device_isis_adj_hold_seconds` | Adjacency hold time | gNMI only | No |
| `device_isis_lsp_count` | LSPs in the database | gNMI only | No |
| `device_isis_spf_runs_total` | SPF runs | gNMI only | No |
| `device_isis_area` | Area membership, an info series | gNMI only | No |

## Vendor families

These come from the vendor profile matched by the device's SNMP enterprise number, so they exist only on the matching hardware. All are SNMP-owned and collected by default where the profile matches.

| Vendor | Families |
| --- | --- |
| Cisco | `device_cpu_percent`, `device_cpu_1min_percent`, `device_mem_used_bytes`, `device_mem_free_bytes`, `device_temp_celsius`, `device_temp_state`, `device_fan_state`, `device_psu_state` |
| Arista | `device_cpu_percent`, `device_mem_total_kb`, `device_storage_size`, `device_storage_used`, `device_temp_celsius` |
| Juniper | `device_cpu_percent`, `device_mem_percent`, `device_temp_celsius`, `device_dram_bytes` |
| Nokia | `device_cpu_percent`, `device_mem_used_kb`, `device_mem_available_kb`, `device_temp_celsius` |
| Fortinet | `device_cpu_percent`, `device_mem_percent`, `device_mem_total_kb`, `device_disk_used_mb`, `device_disk_capacity_mb`, `device_session_count` |
| Palo Alto | `device_session_count`, `device_session_max`, `device_session_util_percent`, `device_ha_state`, plus `device_fw_*` from the built-in profile |
| F5 | `device_lb_*` |
| Check Point | `device_fw_conns`, `device_fw_cpu_pct`, `device_fw_mem_active_bytes` |
| MikroTik | `device_temp_celsius`, `device_cpu_temp_celsius`, `device_voltage_dv` |
| Huawei | `device_cpu_percent`, `device_mem_percent`, `device_temp_celsius` |
| Extreme | `device_cpu_percent`, `device_mem_free_kb`, `device_temp_celsius` |

## Optics families

Optical digital-diagnostic monitoring is SNMP-owned and gated by `FEATURE_PORT_DOM`, which is off by default.

| Family | Measures | Unit |
| --- | --- | --- |
| `port_optics_rx_power_dbm` | Receive power | dBm |
| `port_optics_tx_power_dbm` | Transmit power | dBm |
| `port_optics_tx_bias_ma` | Laser bias current | mA |
| `port_optics_temperature_c` | Transceiver temperature | Celsius |
| `port_optics_supply_voltage_v` | Transceiver supply voltage | Volts |

## Probe and synthetic families

Each block is produced by one opt-in collector. `probe_*` is shared by two of them and disambiguated by the `probe` label.

| Family | Measures | Collector | Gate |
| --- | --- | --- | --- |
| `circuit_latency_ms`, `circuit_jitter_ms`, `circuit_loss_pct`, `circuit_qoe`, `circuit_sent`, `circuit_recv` | Circuit quality from active echo | wan-echo | `FEATURE_WAN_ECHO`, off |
| `probe_rtt_ms`, `probe_owd_ms`, `probe_pdv_ms`, `probe_loss_pct`, `probe_sent`, `probe_recv` with `probe="stamp"` | One-way delay, delay variation and loss | STAMP sender | `FEATURE_ACTIVE_PROBE`, off |
| `probe_hop_rtt_ms`, `probe_path_length`, `probe_path_reached`, `probe_path_changed` with `probe="traceroute"` | Hop-by-hop path measurement | traceroute | `FEATURE_TRACEROUTE`, off |
| `synthetic_up`, `synthetic_http_status_code`, `synthetic_http_dns_ms`, `synthetic_http_connect_ms`, `synthetic_http_tls_ms`, `synthetic_http_ttfb_ms`, `synthetic_http_total_ms`, `synthetic_http_cert_expiry_days`, `synthetic_tcp_connect_ms`, `synthetic_icmp_rtt_ms`, `synthetic_icmp_loss_pct` | Synthetic HTTP, TCP and ICMP checks | synthetics | `FEATURE_SYNTHETICS`, off |
| `device_unifi_state`, `device_unifi_clients`, `device_unifi_uptime_seconds`, `device_unifi_satisfaction_pct`, `device_unifi_cpu_pct`, `device_unifi_mem_pct` | UniFi controller device health | unifi | `FEATURE_UNIFI`, off |

## The correlation allowlist

Fifteen families are additionally forwarded to the correlation engine as metric events, grouped under three family names:

| Group | Families |
| --- | --- |
| `interface` | `device_if_oper_status`, `device_if_admin_status`, `device_if_in_octets`, `device_if_out_octets`, `device_if_in_errors`, `device_if_out_errors`, `device_if_in_discards`, `device_if_out_discards`, `device_if_fcs_errors`, `device_if_speed` |
| `bgp` | `device_bgp_peer_state`, `device_bgp_fsm_transitions` |
| `device_resource` | `device_cpu_percent`, `device_mem_percent`, `device_temp_celsius` |

This list is a filter on the correlation bus, not the collection inventory. Every collected family still reaches VictoriaMetrics whether or not it is on this list.

## Families no shipped collector emits

These names exist in the product and produce no series in a shipped deployment. They are listed here so that finding one in a query and getting nothing back is not a mystery.

| Family | Why it is empty |
| --- | --- |
| `device_if_fcs_errors` | On the correlation allowlist and in the older built-in SNMP profile, but not in the profile the shipped compose file mounts, and no gNMI mapping produces it. |
| `device_bgp_in_updates` | Declared gNMI-owned, so SNMP withholds it on a gNMI-capable device, and the gNMI configuration has no mapping that produces it. The gNMI BGP counter is `device_bgp_pfx_in`, which is a different measurement. On a device without gNMI, SNMP does emit it. |
| `port_coherent_osnr_db`, `port_prefec_ber`, `port_postfec_ber` | Defined for coherent optics and reachable from no shipped collector. |
| `device_if_last_change`, `device_poe_port_detection_status`, `device_poe_port_power_class`, `device_poe_pse_consumption_watts` | Present in the built-in profiles and absent from the profile the shipped compose file mounts, which replaces the built-in of the same name. |

## Absence is reported as absent, never as zero

A family that nothing collects is reported as `null` with a note naming what would have produced it. It is never reported as `0`.

The reason is that zero is a claim about the device. An LSDB nobody is measuring rendered as an LSDB of size zero says "this router's database is empty", which is the most alarming possible false statement about a healthy router. An interface whose operational status was never read rendered as zero says the interface is down.

The API therefore uses nullable fields for these, without omitting them, so absence arrives explicitly:

- `lsp_count`, `spf runs`, `areas` and the timer values on the IGP surfaces.
- `oper_value`, the rate fields, `speed_bps` and the utilisation and error-rate fields on the interface surfaces.

A read that **failed** is also kept distinct from a value that is **absent**. A failed enrichment query adds the note "the series could not be read on this request; the fields it feeds are null rather than zero". A genuine absence instead gets a note naming the exact metric and the MIB or transport it would have come from.

## Related

- [Send metrics](/send-data/metrics) for getting a device polled.
- [Explore metrics](/explore/metrics) for querying these families.
- [Data sources and coverage](/onboard-devices/data-sources) for what is collected per device.
- [Feature flags](/reference/feature-flags) for every gate named above.
- [Honest states](/reference/honest-states) for the absence rules in full.
