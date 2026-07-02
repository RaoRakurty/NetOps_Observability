---
title: Key concepts
sidebar_label: Key concepts
sidebar_position: 3
description: The core vocabulary of Correlix — devices, telemetry planes, monitors, events, incidents, correlations, and seams.
---

# Key concepts

This page is the operator's mental model — the handful of ideas the rest of the docs (and the console itself) are built on. Each concept notes **where you'll meet it in the console**, so the vocabulary and the UI reinforce each other. For quick alphabetical lookups, use the [Glossary](/reference/glossary).

## Inventory: devices, interfaces, sites

- **Device** — a network element Correlix monitors: router, switch, firewall, load balancer. Devices enter the inventory by [SNMP discovery](/onboard-devices/snmp-discovery), by being [added manually](/onboard-devices/add-devices-manually), or via a Source-of-Truth import.
- **Interface** — a port on a device. Interface metrics (throughput, utilization, errors, oper-status) are the backbone of network monitoring.
- **Site** — a location grouping for devices (a data center, branch, region). Sites scope views and place devices on maps.

**Where you'll meet it:** <kbd>Infrastructure → Devices</kbd> is the fleet inventory — live status dot, vendor, type, and discovery source per device. Interfaces render under <kbd>Infrastructure → Interface Performance</kbd>; sites drive the <kbd>Device Geomap</kbd>.

## Telemetry planes

Correlix collects several **independent planes** of telemetry about the same network. Independence is the point: when the same fault shows up in more than one plane, confidence in the diagnosis rises sharply.

- **Metrics** — numeric time series polled over SNMP (or streamed via [gNMI](/onboard-devices/streaming-gnmi)): CPU, memory, interface counters, protocol state.
- **Flows** — traffic records (NetFlow / sFlow / IPFIX) describing who talked to whom, and how much.
- **Logs** — syslog messages the devices themselves emit.
- **Traps** — SNMP notifications devices push when something changes.
- **Active measurement** — probes Correlix originates (ICMP, STAMP, path trace) measuring latency, jitter, and loss along real paths.

**Where you'll meet it:** the **Data** zone of the icon rail — <kbd>Metrics</kbd>, <kbd>Flows</kbd>, <kbd>Logs</kbd> — explores each plane raw. The [Data Sources coverage matrix](/onboard-devices/data-sources) shows, per device, which planes are actually being collected.

## Detection: monitors, anomalies, alerts, events

- **Monitor** — a rule *you* define that watches a metric or condition and raises an alert when breached. Explicit, predictable, yours.
- **Anomaly** — a deviation from normal that Correlix detects *automatically* from each metric's own history — no threshold required.
- **Alert** — an active, unresolved monitor breach.
- **Event** — anything noteworthy on the timeline: a syslog message, a trap, an alert, an anomaly, a change.

Monitors and anomalies are complementary: monitors encode what you already know matters; anomaly detection catches what you didn't think to watch.

**Where you'll meet it:** everything lives under <kbd>Monitoring</kbd> — **Monitor Rules** and **Create Monitor** for definitions, **Active Alerts** for live breaches, **Anomalies** and **Events** under Event Management.

## Root cause: incidents, evidence, verdicts, seams

This is Correlix's center of gravity. Instead of paging you once per symptom, the correlation engine groups related signals — across planes *and* devices — that share a cause and time window into **one incident**.

- **Correlation / Incident** — the grouped problem, with a proposed root cause and blast radius.
- **Verdict** — how sure Correlix is about the incident's **fault domain**:
  - **Confirmed** — evidence aligned across independent signals.
  - **Suspected** — multiple supporting signals, not yet fully validated.
  - **Undetermined** — a low-evidence correlation; a watch item, not yet actionable.
- **Evidence** — the specific signals (and their sources) supporting or contradicting the verdict. Every conclusion is backed by clickable evidence — nothing is a black box, and a verdict is never stronger than its evidence.
- **Recommended owner** — the team the fault domain maps to (routing, provider, security…).
- **Seam** — a responsibility boundary in the path, such as where your network hands off to an ISP or a cloud. Seams let Correlix attribute a fault to the right *side* of a handoff — often the difference between "open an internal ticket" and "call the provider".

**Where you'll meet it:** <kbd>Monitoring → Incidents</kbd> and <kbd>Monitoring → Correlations</kbd>; the <kbd>Incident Response → Command Center</kbd> puts active incidents, verdicts, and evidence on one operational screen. Routing incidents outward (notifications, tickets) lives under [Incident Response](/incident-response/overview).

## The maps: topology and paths

Correlix learns the network's shape rather than asking you to draw it: neighbor relationships discovered from the devices themselves build the **[Topology Canvas](/infrastructure/topology-canvas)**, and active measurements trace the hop-by-hop paths traffic really takes (<kbd>Infrastructure → Flow Trace</kbd>). Incidents reference this graph — a fault's blast radius is a topological statement, not a list.

## Access model: tenants, organizations, roles

- **Tenant** — an isolated view of the platform. A tenant only ever sees its own devices, telemetry, and incidents — isolation is enforced on every surface, not by convention.
- **Organization** — an account layer that groups tenants, for operators running Correlix for multiple customers or business units.
- **Role** — a named permission set; all access is role-based.
- **Platform owner** — the cross-tenant super-admin who manages the platform itself. Some console sections (e.g. <kbd>Automation → Source Of Truth</kbd>, <kbd>Stack</kbd>) are visible only to the platform owner.

**Where you'll meet it:** <kbd>Administration → Identity & Access</kbd> manages organizations, tenants, users, and roles; details in [Identity & Access](/administration/identity-access) and [Tenants & organizations](/administration/tenants-orgs).

## Source of Truth

The **Source of Truth (SoT)** is the *intended* inventory — what should exist — as opposed to the *discovered* inventory of what actually answers. Correlix keeps its own internal SoT and can optionally exchange records with an external system. Comparing intent to reality is how drift gets caught.

**Where you'll meet it:** <kbd>Automation → Source Of Truth</kbd> (platform owner); see [Automation & Source of Truth](/automation/overview).

:::info Isolation is built in
Every feature gives each tenant a unique, scoped view. A tenant can never see another tenant's devices, metrics, logs, flows, or incidents — and this holds for every new feature by design.
:::

## Next

Put the vocabulary to work: **[Quickstart](/getting-started/quickstart)**, then **[Onboard Network Devices](/onboard-devices/overview)**.
