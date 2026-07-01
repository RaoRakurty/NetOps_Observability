---
title: Connectivity requirements
sidebar_label: Connectivity requirements
sidebar_position: 1
description: Ports and network access Correlix needs to monitor your devices.
---

# Connectivity requirements

Correlix monitors agentlessly, so the main requirement is **network reachability** between Correlix and your devices on a handful of standard ports. Open these on the path (firewalls/ACLs) as needed.

## Correlix → device (polling & probes)

| Purpose | Protocol / Port | Direction |
| --- | --- | --- |
| SNMP polling | UDP **161** | Correlix → device |
| ICMP reachability / path probes | ICMP echo | Correlix → device |
| Streaming telemetry (gNMI) | gRPC (device‑configured port, often **57400**) | Correlix → device |
| Active path measurement (STAMP/TWAMP) | UDP (configured) | Correlix → reflector |

## Device → Correlix (pushed telemetry)

| Purpose | Protocol / Port | Direction |
| --- | --- | --- |
| Syslog | UDP **514** (or TCP) | device → Correlix |
| SNMP traps | UDP **162** | device → Correlix |
| NetFlow | UDP **2055** (v9) / configurable | device → Correlix |
| IPFIX | UDP **4739** | device → Correlix |
| sFlow | UDP **6343** | device → Correlix |

## User → Correlix

| Purpose | Protocol / Port |
| --- | --- |
| Web console & API | HTTPS **443** (or your configured port) |

:::tip Source addresses
For **syslog** and **traps**, Correlix identifies the device by its **source IP**. Make sure devices send from an address Correlix knows (their management IP). NAT or loopback sourcing must be accounted for so events attribute to the right device.
:::

## Credentials summary

- **SNMP v2c** community, or **SNMP v3** user (auth + priv) — read‑only recommended. See [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
- For **gNMI**, an account the device authorizes for telemetry.
