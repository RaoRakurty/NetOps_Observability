---
title: Connectivity requirements
sidebar_label: Connectivity requirements
sidebar_position: 1
description: The authoritative port table, firewall guidance, and browser requirements for Correlix.
---

# Connectivity requirements

Correlix monitors agentlessly, so the main requirement is **network reachability** between Correlix and your devices on a handful of standard ports. This page is the authoritative reference — hand the table below to your firewall team, and open the rows that match the telemetry planes you use.

## The port table

Directions are from the perspective of the network: **Correlix → device** means the Correlix host initiates the connection; **device → Correlix** means the device pushes telemetry in.

| Protocol / Port | Direction | Purpose | Notes |
| --- | --- | --- | --- |
| TCP **8000** | browser / API client → Correlix | Web console & REST API | Default install port — your deployment may change it or front it with HTTPS on 443. |
| UDP **161** | Correlix → device | SNMP polling & discovery | The foundation plane. Read-only. |
| ICMP echo | Correlix → device | Reachability & latency probes | Allow echo request out, echo reply back. |
| TCP (gRPC), device-configured — commonly **57400** | Correlix → device | Streaming telemetry (gNMI) | Only if you enable [gNMI streaming](/onboard-devices/streaming-gnmi); the port is set on the device. |
| UDP **514** (TCP 514 also accepted) | device → Correlix | Syslog | See [Send syslog](/send-data/syslog). Deployments can serve an alternate port — confirm with your admin. |
| UDP **162** | device → Correlix | SNMP traps | See [Send traps](/send-data/traps). |
| UDP **2055** | device → Correlix | NetFlow (v5/v9) | See [Send flows](/send-data/flows). |
| UDP **4739** | device → Correlix | IPFIX | See [Send flows](/send-data/flows). |
| UDP **6343** | device → Correlix | sFlow | See [Send flows](/send-data/flows). |
| UDP **862** (default) | Correlix → reflector | Active path measurement (STAMP) | Only if you run STAMP probes; the reflector port is configurable. |
| ICMP echo / TCP **443** | Correlix → measurement target | WAN interface echo probes | Only if you use [WAN Interface Metrics](/infrastructure/wan-interface-metrics) with a public measurement target. |

Flow, syslog, and trap ports are the platform defaults and can be changed at deployment time — if your instance was installed with non-default ports, your platform administrator has the values.

## Firewall guidance

Work through the path in three segments:

1. **Users → Correlix.** Allow TCP 8000 (or your configured console port) from operator networks to the Correlix host. Nothing else needs to be exposed to users.
2. **Correlix → device management network.** Allow UDP 161 and ICMP from the Correlix host to your management subnets. Add the gNMI port only for devices you stream from. This is the direction that unblocks discovery and metric polling — start here.
3. **Devices → Correlix.** Allow UDP 514, 162, and your flow ports (2055/4739/6343) from device management addresses to the Correlix host. These are push planes: nothing arrives until the devices are also *configured* to send — see [Send data](/send-data/overview).

:::tip Source addresses matter
For **syslog** and **traps**, Correlix attributes the message to a device by its **source IP**. Devices must send from an address Correlix knows — normally the management IP it polls. If a device sources from a loopback or the path NATs the traffic, events can arrive but attach to no device; account for this in device config (source-interface commands) rather than at the firewall.
:::

:::warning UDP is fire-and-forget
Syslog over UDP, traps, and flow export don't retransmit. A firewall silently dropping these ports produces the classic symptom of "device green for SNMP metrics, but Syslog/Traps/Flows stuck on no data" — see [Troubleshooting](/reference/troubleshooting). Where the device supports it, syslog over TCP gives reliable delivery.
:::

## What Correlix never needs

- **No inbound access to your devices beyond SNMP/ICMP/gNMI** — there is no agent, no CLI scraping in the default setup, and SNMP is read-only.
- **No connectivity between your devices and the internet** — all telemetry terminates at your Correlix instance.

## Credentials summary

Connectivity gets packets through; these get them *answered*:

- **SNMP v2c** community or **SNMP v3** user (auth + priv) — read-only recommended. Managed in the [SNMP Profile Manager](/onboard-devices/snmp-profiles).
- **gNMI** — an account the device authorizes for telemetry subscriptions.

## Browser requirements

The console is a single-page web application:

- A **current version of a modern browser** (Chrome, Edge, Firefox, Safari).
- **JavaScript enabled**, and **WebSocket connections permitted** to the Correlix host — live-updating views stream over WebSocket, so proxies that strip WebSocket upgrades will break live panels while leaving static pages working.
- No plugins or extensions are required.

## Related

- [Getting Started overview](/getting-started/overview) — the full prerequisite checklist.
- [Send data](/send-data/overview) — per-plane device configuration.
- [Troubleshooting](/reference/troubleshooting) — what to check when a plane stays empty.
