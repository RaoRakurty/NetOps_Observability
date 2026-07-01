---
title: Send Data overview
sidebar_label: Overview
sidebar_position: 1
description: The telemetry planes you can send to Correlix, and why more planes mean better root cause.
---

# Send Data

SNMP polling gives you metrics and inventory. To get the full picture — events, traffic, and high‑confidence root cause — configure your devices to **push** the other telemetry planes to Correlix.

| Plane | What it gives you | Setup |
| --- | --- | --- |
| **[Metrics](/send-data/metrics)** | Health, interfaces, protocol state (time series) | SNMP polling / gNMI (mostly automatic) |
| **[Syslog](/send-data/syslog)** | Device log events on the timeline + correlation signals | Point device syslog at Correlix |
| **[SNMP traps](/send-data/traps)** | Asynchronous device notifications | Point device traps at Correlix |
| **[Flow records](/send-data/flows)** | Traffic analytics, top talkers, app attribution | Enable NetFlow/sFlow/IPFIX export |

:::tip Why send more than metrics?
Correlix's correlation engine is most confident when a fault appears across **independent planes** — a syslog event *and* a metric anomaly *and* a trap pointing at the same device and time is a **confirmed** verdict, not a guess. Multi‑plane coverage on your core and edge devices is the single biggest lever on root‑cause quality.
:::

Track your progress on the **[Data Sources coverage matrix](/onboard-devices/data-sources)**.
