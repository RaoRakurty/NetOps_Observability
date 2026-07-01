---
title: Metrics
sidebar_label: Metrics
sidebar_position: 2
description: How Correlix collects device and interface metrics, and what you get.
---

# Metrics

Metrics are the numeric time series that back most of Correlix's dashboards and monitors. They're collected for you once a device is onboarded — there's usually nothing extra to configure.

## How metrics are collected

- **SNMP polling** (default) — Correlix polls each device about once a minute for interface counters, CPU/memory, environment sensors, and protocol state. See [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
- **Streaming telemetry (gNMI)** — higher‑resolution, pushed metrics on supported platforms. See [Streaming telemetry](/onboard-devices/streaming-gnmi).

Both are normalized to the same metric names, so they're interchangeable on dashboards.

## What you get

- **Device** — CPU, memory, temperature, uptime, availability.
- **Interfaces** — in/out throughput, utilization, errors/discards, oper/admin status, speed.
- **Protocols** — BGP/OSPF/IS‑IS neighbor state and changes.

## Where to see it

- <kbd>Infrastructure → Device Monitoring</kbd> — per‑device health.
- <kbd>Infrastructure → Interface Performance</kbd> — per‑interface throughput/utilization.
- <kbd>Infrastructure → Protocol Monitoring</kbd> — routing‑protocol state.
- <kbd>Metrics</kbd> — the raw Metrics Explorer to query any series ad hoc.

## Tuning

The default **1‑minute poll** matches the industry standard for interface statistics and keeps device load low. Streaming telemetry is the path to sub‑minute resolution where you need it.

## Next

- **[Send syslog](/send-data/syslog)** and **[flows](/send-data/flows)** to round out coverage.
