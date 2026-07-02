---
title: Supported devices & vendors
sidebar_label: Supported devices
sidebar_position: 8
description: What Correlix can monitor out of the box, and how coverage extends to any SNMP-capable device.
---

# Supported devices & vendors

Correlix is **vendor-neutral**: it builds on standard protocols (SNMP, syslog, SNMP traps, NetFlow/IPFIX/sFlow, gNMI), so the honest baseline is simple — **anything SNMP-capable works**. On top of that baseline, specific vendors get automatic recognition, richer metric packs, and deeper log parsing. This page tells you exactly which is which.

## The universal baseline — any SNMP device

Every device with a working SNMP credential gets, with **no profile configuration**:

- **Identity & inventory** — vendor/model/OS description, uptime, the interface list.
- **Interface health** — admin/oper status, state-change (flap) timestamps, high-capacity traffic counters, interface speed (feeding utilization), errors, discards, physical-layer FCS errors, and unicast/multicast/broadcast packet mix.
- **System health** — CPU load and environmental sensors where the device exposes the standard tables.
- **Protocol state** — BGP peer state, session transitions and updates, and OSPF neighbor/interface state via the standard protocol MIBs.

These come from the **Universal** profiles (standard MIB families — system, interfaces, host resources, L3), which apply to every device regardless of vendor.

## Automatic vendor recognition

On first contact, Correlix fingerprints the device from its SNMP identity and fills in the **Manufacturer** and functional **Type** (router/switch/firewall/…) automatically. Recognized vendor families:

Cisco · Juniper · Arista · Fortinet · Palo Alto Networks · Nokia · Huawei · MikroTik · Extreme · F5 · Dell · HP · Check Point · Linux/hosts (standard host agents)

A device outside this list still monitors fine — it just shows "Unknown" as the manufacturer until you set it on the record.

## Built-in vendor metric packs

The [SNMP Profile Manager](/onboard-devices/snmp-profiles)'s profile library ships with vendor packs that layer platform-specific health on top of the universal baseline (vendor CPU/memory/temperature tables and the like), matched to devices automatically by their identity fingerprint:

| Category | Built-in profiles |
| --- | --- |
| **Universal** | System, Interfaces, L3 (IP/TCP) — applied to everything |
| **Routers / Switches** | Cisco IOS / IOS-XE · Juniper JUNOS · Arista EOS · Huawei · MikroTik RouterOS · Extreme EXOS/VOSS · Ubiquiti EdgeOS/EdgeRouter |
| **Firewalls / SD-WAN** | Fortinet FortiGate · Palo Alto PAN-OS · Palo Alto CloudGenix SD-WAN · Versa FlexVNF |
| **Servers / Hosts** | Host Resources · Server/Host (standard host agents, Windows) |
| **Other** | Printer · UPS |

All profiles are extensible: add an OID to an existing pack, or create a **Custom** profile for an unlisted platform — see [vendor profiles](/onboard-devices/snmp-profiles#vendor-profiles-oid--metric-library). A missing metric is almost always a profile extension away, not an unsupported device.

## Log (syslog) parsing by vendor

Any device can send syslog; every message becomes a searchable, device-attributed event. On top of that, logs from **Cisco, Arista, Juniper, Nokia, Fortinet, and Palo Alto** formats are recognized by their signature and labeled by vendor for filtering. Fortinet-format firewall logs get the deepest treatment: their structured bodies are parsed **field by field**, including the firewall's own **application identification** on traffic logs — which feeds application analytics and the Service View (see [Service View](/incidents/overview)).

## Flow exporters

NetFlow **v5/v9**, **IPFIX**, and **sFlow** are all accepted, from any exporter that implements them — routers, switches, firewalls, or software exporters. See [Flows](/send-data/flows).

## Traps

SNMP traps are accepted from **any device**; see [SNMP traps](/send-data/traps).

## Streaming telemetry (gNMI)

Streaming is supported per device on gNMI-capable platforms, with subscription sets validated on **Arista EOS** (OpenConfig models) and **Nokia SR Linux** (native models) — covering interface counters, BGP session state, IS-IS adjacencies, and control-plane health. Other gNMI-capable platforms can be added per device; see [Streaming telemetry](/onboard-devices/streaming-gnmi).

## Honest expectations

- **"Supported" at baseline means SNMP.** If your device answers SNMP, you get inventory, interfaces, availability, and standard protocol state — full stop.
- **Vendor packs deepen, they don't gate.** A vendor missing from the tables above loses only the vendor-specific extras (e.g. its proprietary CPU table), never the baseline.
- **When in doubt, just add it.** Add the device with a credential and check the [Data Sources matrix](/onboard-devices/data-sources) — if SNMP turns green, you're monitored. If a metric you need is missing, extend the profile.

## Next

- **[SNMP profiles & credentials](/onboard-devices/snmp-profiles)**
- **[Connectivity requirements](/reference/connectivity-requirements)**
