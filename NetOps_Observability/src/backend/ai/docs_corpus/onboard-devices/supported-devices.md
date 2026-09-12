---
title: Supported devices
sidebar_label: Supported devices
description: The vendors Correlix recognizes, the metric families it reads over each transport, and what support does not include.
page_type: reference
sidebar_position: 2
---

# Supported devices

Correlix reads devices over SNMP and accepts syslog, SNMP traps and flow
records from any device that can send them. "Supported" therefore means three
separate things, and this page separates them: the vendor is recognized
(Correlix names it from its SNMP identity), the vendor has a metric pack
(extra OIDs beyond the standard MIBs), and the vendor has a configuration
template (Correlix can generate its device CLI). A vendor can be recognized
and have neither of the other two.

All identifiers below are taken from the shipped source: the vendor profile
registry in `src/backend/internal/vendorprofile/profiles/`, the SNMP metric
profiles in `src/backend/collectors/profiles.go`, and the ingest configuration
in `deployment/docker/`.

## Vendor recognition

On the first poll Correlix reads `sysObjectID` (`1.3.6.1.2.1.1.2.0`) and maps
its IANA Private Enterprise Number to a vendor. When the enterprise number is
unclaimed, it falls back to a substring match on `sysDescr`
(`1.3.6.1.2.1.1.1.0`). A device whose enterprise number and description match
nothing keeps an empty vendor, which the console shows as unknown. That is an
honest unknown, not a guess, and it does not affect collection.

| Vendor | Enterprise number | `sysDescr` fallback matches |
|---|---|---|
| Arista Networks | 30065 | `arista` |
| Aruba Networks | 14823 | `arubaos`, `aruba` |
| Check Point | 2620 | `check point`, `gaia`, `checkpoint` |
| Cisco | 9 | `cisco` |
| Dell | 674 | none |
| Extreme Networks | 1916 | none |
| F5 Networks | 3375 | `big-ip`, `bigip`, `f5 networks` |
| Fortinet | 12356 | `fortinet`, `fortigate` |
| HP | 11 | none |
| Huawei | 2011 | `huawei`, `vrp` |
| Juniper Networks | 2636 | `junos`, `juniper` |
| Linux | none | `linux` |
| MikroTik | 14988 | `mikrotik`, `routeros` |
| Net-SNMP | 8072 | none |
| Nokia | 6527 | `nokia`, `timos`, `sr os` |
| Palo Alto Networks | 25461 | `palo alto`, `pan-os` |
| Ruckus Wireless | 25053 | `ruckus` |
| Sophos | 21067, 9789 | `sophos`, `sfos`, `astaro` |
| Ubiquiti | 41112 | `ubiquiti`, `edgeos`, `edgerouter`, `unifi` |

The `sysDescr` fallback is ordered, because a BIG-IP description contains
`Linux`. F5 is tested before the Linux backstop.

Correlix also derives a device **type** from the same identity: `router`,
`switch`, `firewall`, `load-balancer`, `ap`, `wlc`, `cloud-gw` or `generic`. An
operator can override it with the device label `device_type`.

## What every recognized device gets

The `generic` SNMP profile carries enterprise number 0 and applies to every
device. It reads 33 objects from standard MIBs. No configuration selects it.

| Family | Metrics |
|---|---|
| System | `device_sysuptime` |
| Interface state | `device_if_oper_status`, `device_if_admin_status`, `device_if_last_change`, `device_if_speed` |
| Interface traffic | `device_if_in_octets`, `device_if_out_octets` (both `ifHC*` 64-bit counters) |
| Interface errors | `device_if_in_errors`, `device_if_out_errors`, `device_if_in_discards`, `device_if_out_discards`, `device_if_fcs_errors` |
| Interface packet mix | unicast, multicast and broadcast counters in each direction |
| Host resources | `device_cpu_percent` (`hrProcessorLoad`) |
| Environment | `device_sensor_value` (`entPhySensorValue`) |
| BGP | `device_bgp_peer_state`, `device_bgp_fsm_transitions`, `device_bgp_in_updates` (BGP4-MIB) |
| OSPF | `device_ospf_nbr_state`, `device_ospf_if_state`, `device_ospf_area`, `device_ospf_lsdb_count`, `device_ospf_spf_runs_total`, `device_ospf_if_hello_seconds`, `device_ospf_if_dead_seconds` |
| Power over Ethernet | `device_poe_port_detection_status`, `device_poe_port_power_class`, `device_poe_pse_consumption_watts` |

The three BGP metrics carry `owner: gnmi`. On a device labelled `gnmi: "true"`
the SNMP collector withholds them and gNMI serves them instead. On every other
device SNMP serves them. See
[Set up gNMI streaming telemetry](/onboard-devices/streaming-gnmi).

## Vendor metric packs

A vendor pack is selected in addition to the generic profile when the device's
enterprise number matches. Five of the registered vendors carry no extra OIDs;
they are registered so the device is labelled and so the generic floor applies.
The source states why in each case.

| Vendor | Extra metrics |
|---|---|
| Cisco | `device_cpu_percent`, `device_mem_used_bytes`, `device_temp_celsius` |
| Juniper | `device_cpu_percent`, `device_mem_percent`, `device_temp_celsius` |
| Huawei | `device_cpu_percent`, `device_mem_percent`, `device_temp_celsius` |
| Extreme | `device_cpu_percent`, `device_mem_free_kb`, `device_temp_celsius` |
| MikroTik | `device_temp_celsius`, `device_cpu_temp_celsius`, `device_voltage_dv` |
| Fortinet | `device_fw_cpu_pct`, `device_fw_mem_pct`, `device_fw_session_active` |
| Palo Alto | `device_fw_session_active`, `device_fw_session_max`, `device_fw_session_util_pct`, `device_fw_ha_state`, `device_fw_gp_tunnels` |
| Check Point | `device_fw_cpu_pct`, `device_fw_mem_active_bytes`, `device_fw_conns` |
| F5 | eight `device_lb_*` metrics: virtual-server and pool-member availability, pool and client connections, trunk status and member counts, memory used |
| Arista | none. CPU, memory and temperature come from HOST-RESOURCES-MIB and ENTITY-SENSOR-MIB, which the generic profile already reads. |
| Dell | none. The networking OS families sit under different sub-trees, and 674 also covers iDRAC servers. |
| Sophos | none. SFOS MIB coverage varies by version, so no OIDs are asserted. |
| Ubiquiti | none. UniFi device health lives in the controller API, not in device SNMP. |
| Aruba, Ruckus | none. Wired uplink ports come from the generic floor; wireless radio and client metrics are a separate family. |

Nokia, HP, Linux and Net-SNMP are recognized as vendors but have no SNMP metric
pack at all. Those devices get the generic profile only.

To add an OID for a platform, extend a profile from
**Administration → Data sources → SNMP Profiles → Profiles**, or supply a
JSON file at `SNMP_PROFILES_FILE`. A file profile whose name matches a built-in
replaces it.

## Device configuration templates

Correlix generates the device-side SNMP CLI for these eleven vendors. Every
other vendor gets a real generated credential plus generic guidance, because
inventing a CLI block for an unvalidated platform would be a claim about a
device nobody has tested.

Arista · Check Point · Cisco · Extreme · F5 · Fortinet · Huawei · Juniper ·
MikroTik · Palo Alto · Ubiquiti

The blocks are in
[SNMP configuration by vendor](/onboard-devices/vendor-snmp-configs).

## Syslog

Any device can send syslog. Correlix labels the vendor from the message
signature, then runs a structured parser where one exists.

| Vendor label | How it is recognized | Structured parser |
|---|---|---|
| `fortinet` | `devname=` together with `logid=` | Key-value body parsed into `fgt.*`, including the on-box application classification |
| `paloalto` | A comma-delimited `TRAFFIC`, `THREAT`, `SYSTEM`, `CONFIG` or `HIPMATCH` field | none |
| `juniper` | `[junos@2636`, `RT_FLOW`, or a Junos daemon in the application name | none |
| `arista` | An EOS agent name such as `ebra`, `mlag`, `stp`, `lldp` | `ios_style.v1` |
| `cisco` | The `%FACILITY-SEVERITY-MNEMONIC` shape | `ios_style.v1` |
| `nokia` | The SR Linux pipe-delimited body | `srlinux.v1` |

Every message carries `parser_status`, which reads `parsed` or `unparsed`. An
unparsed message is still stored, searchable and attributed. Only the derived
fields are missing.

## Flow records

The collector listens for NetFlow on UDP 2055, IPFIX on UDP 4739 and sFlow on
UDP 6343. NetFlow v5, v9 and IPFIX all arrive through the NetFlow decoder.

## SNMP traps

The receiver decodes SNMP v1, v2c and v3 traps and informs from any vendor. A
trap OID that is not in the MIB index is recorded as `enterpriseSpecific` at
`notice` severity with its OID and variable bindings intact.

## Streaming telemetry

The shipped `gnmic` configuration carries subscription sets for two platforms:
Nokia SR Linux native paths and Arista EOS OpenConfig paths. Adding another
platform means adding its paths, and no other platform's paths are shipped.

## What is not claimed

- **No agent.** There is nothing to install on a device.
- **No configuration writes.** SNMP access is read-only, and Correlix never
  pushes configuration to a device during onboarding.
- **No device-pushed metric ingest.** There is no endpoint a device can POST
  metrics to. Metrics are polled or streamed.
- **The NETCONF collector is a reachability probe.** It opens TCP 830 and reads
  the SSH banner. It runs no NETCONF RPC and produces no metrics.
- **A vendor pack is not a guarantee the OIDs answer.** The source comments say
  which packs are unverified against live hardware. A missing metric shows as
  no data, never as zero.

## Related

- [Add an SNMP credential](/onboard-devices/snmp-profiles)
- [SNMP configuration by vendor](/onboard-devices/vendor-snmp-configs)
- [Connectivity requirements](/reference/connectivity-requirements)
- [What an empty result means](/reference/honest-states)
