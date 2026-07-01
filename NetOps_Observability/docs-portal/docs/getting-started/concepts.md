---
title: Key concepts
sidebar_label: Key concepts
sidebar_position: 3
description: The core vocabulary of Correlix — devices, telemetry planes, monitors, events, incidents, correlations, and seams.
---

# Key concepts

A short glossary so the rest of the docs read clearly. You configure all of these from the console — the definitions here are the *operator's* mental model.

## Inventory

- **Device** — a network element Correlix monitors (router, switch, firewall, load balancer, etc.). Devices are discovered over SNMP or added manually.
- **Interface** — a port on a device. Interface metrics (throughput, utilization, errors, oper‑status) are the backbone of network monitoring.
- **Site** — a location grouping for devices (a DC, branch, region). Used for scoping and topology.
- **Source of Truth (SoT)** — your authoritative inventory. Correlix keeps its own, and can sync with NetBox. See [Automation & Source of Truth](/automation/overview).

## Telemetry planes

Correlix collects several independent **planes** of telemetry. More planes = stronger correlation.

- **Metrics** — numeric time series polled over SNMP (or streamed via gNMI): CPU, memory, interface counters, protocol state.
- **Flows** — traffic records (NetFlow / sFlow / IPFIX) describing who talked to whom, how much.
- **Logs** — syslog messages pushed by devices.
- **Traps** — SNMP trap notifications pushed by devices.
- **Active measurement** — Correlix‑originated probes (ICMP, STAMP, traceroute) that measure path latency, jitter, and loss.

## Detection

- **Monitor** — a rule you define that watches a metric or condition and raises an **alert** when it's breached.
- **Anomaly** — an automatically detected deviation from normal (rolling z‑score), no threshold required.
- **Alert** — an active, unresolved monitor breach.
- **Event** — anything noteworthy on the timeline: a syslog message, a trap, an alert, an anomaly, a change.

## Root cause

- **Correlation / Incident** — Correlix groups related signals (across planes and devices) that share a cause and time window into **one incident**, instead of many alerts.
- **Verdict** — how sure Correlix is about an incident's fault domain:
  - **Confirmed** — evidence aligned across independent signals.
  - **Suspected** — multiple supporting signals, not yet fully validated.
  - **Undetermined** — a low‑evidence correlation; a watch item, not yet actionable.
- **Evidence** — the specific signals (and their sources) that support or contradict a verdict. Every conclusion is backed by clickable evidence — nothing is a black box.
- **Recommended owner** — the team a fault domain maps to (routing, provider, security, etc.).
- **Seam** — a responsibility boundary in the path (for example, where your network hands off to an ISP or a cloud). Correlix uses seams to attribute a fault to the right side.

## Access model

- **Tenant** — an isolated customer/organization view. A tenant only ever sees its own data.
- **Organization** — an account layer above tenants (for multi‑tenant operators).
- **Role** — a set of permissions. Access is role‑based and enforced on every surface.
- **Platform owner** — the cross‑tenant super‑admin who manages the platform itself.

:::info Isolation is built in
Every feature gives each tenant a unique, scoped view. A tenant can never see another tenant's devices, metrics, logs, or incidents.
:::

Next: **[Onboard Network Devices](/onboard-devices/overview)**.
