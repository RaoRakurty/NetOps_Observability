---
title: Send Data overview
sidebar_label: Overview
sidebar_position: 1
description: The telemetry planes you can send to Correlix, the port each one uses, and which to set up first.
---

# Send Data

Correlix collects four telemetry planes. One is **pulled** (Correlix reaches out to your devices), three are **pushed** (your devices send to Correlix):

| Plane | What it gives you | How it moves |
| --- | --- | --- |
| **[Metrics](/send-data/metrics)** | Health, interface counters, protocol state as time series | **Pulled** — SNMP polling / streaming telemetry (mostly automatic after onboarding) |
| **[Syslog](/send-data/syslog)** | Device log messages as searchable events + correlation signals | **Pushed** — point device syslog at Correlix |
| **[SNMP traps](/send-data/traps)** | Instant device notifications (link down, PSU failure, neighbor loss) | **Pushed** — point device trap destination at Correlix |
| **[Flow records](/send-data/flows)** | Traffic analytics: top talkers, conversations, application attribution | **Pushed** — enable NetFlow / IPFIX / sFlow export |

Metrics start flowing as soon as a device is [onboarded](/onboard-devices/overview). The other three planes require a small, one-time configuration change **on each device** — that's what this section walks you through, step by step, per vendor family.

## Ports at a glance

All pushed telemetry arrives on standard UDP ports. Open these on any firewall or ACL between your devices and Correlix. The full matrix (including the pull direction) is in [Connectivity requirements](/reference/connectivity-requirements).

| Plane | Protocol / Port | Direction |
| --- | --- | --- |
| SNMP polling (metrics) | UDP **161** | Correlix → device |
| Streaming telemetry (gNMI) | gRPC, device-configured port (often **57400**) | Correlix → device |
| Syslog | UDP **514** (TCP **514** also accepted) | device → Correlix |
| SNMP traps | UDP **162** | device → Correlix |
| NetFlow v5 / v9 | UDP **2055** | device → Correlix |
| IPFIX | UDP **4739** | device → Correlix |
| sFlow | UDP **6343** | device → Correlix |

:::info Source addresses matter
For pushed telemetry, Correlix attributes each message to a device in your inventory — by the hostname carried in the message (syslog), by the source IP, or by identity fields inside the packet (traps). Configure devices to send from their **management or loopback address** — the one Correlix knows them by — so events land on the right device. Each plane's page covers the specifics.
:::

## Which plane should I set up first?

A practical order, once metrics are green:

1. **Syslog** — the highest-value plane after metrics. Link flaps, protocol adjacency changes, hardware alarms, and config events arrive as first-class, searchable events, and they feed correlation directly. One or two CLI lines per device.
2. **SNMP traps** — near-zero-latency notification of faults between polls. Especially valuable for hardware and environment failures that a 1-minute poll can miss the onset of.
3. **Flow records** — traffic analytics. Set this up on the devices where traffic visibility matters: WAN edges, data-center cores, internet borders, firewalls.

Use this decision guide when you're deciding what to send from where:

| You want to… | Send |
| --- | --- |
| Know *when* something broke and what the device said about it | **Syslog** |
| Be told the *instant* a link, PSU, fan, or neighbor fails | **Traps** |
| Know *who is talking to whom* and which applications use a link | **Flows** |
| Trend utilization, errors, CPU/memory over time | **Metrics** (automatic) |

You don't need every plane from every device. Aim for **all four planes on core and edge devices**, and at minimum metrics + syslog everywhere else.

## Why multiple planes raise root-cause confidence

Correlix's correlation engine treats each plane as an **independent witness**. A fault that appears in one plane (a metric anomaly alone) is a lead; the same fault confirmed across planes — a syslog event *and* a metric anomaly *and* a trap, on the same device at the same time — produces a **confirmed** verdict instead of a guess. Multi-plane coverage on your critical devices is the single biggest lever on root-cause quality.

## Track your coverage

The **[Data Sources coverage matrix](/onboard-devices/data-sources)** (<kbd>Administration → Data Collection → Data Sources</kbd>) shows one row per device and one column per plane, so you can watch columns turn green as you work through this section — and immediately spot the device where a config change didn't take.

## In this section

- **[Metrics](/send-data/metrics)** — how the pulled plane works, and how to verify it.
- **[Syslog](/send-data/syslog)** — step-by-step device configuration, severity guidance, verification, troubleshooting.
- **[SNMP traps](/send-data/traps)** — trap destinations per vendor, which trap families matter, verification.
- **[Flow records](/send-data/flows)** — choosing a flow protocol, exporter configuration, sampling guidance.
