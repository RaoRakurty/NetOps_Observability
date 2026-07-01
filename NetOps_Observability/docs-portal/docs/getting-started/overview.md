---
title: Getting Started overview
sidebar_label: Overview
sidebar_position: 1
description: What you need before you onboard your first device, and the shape of the onboarding journey.
---

# Getting Started

This section gets you from a running Correlix instance to your **first device reporting data**. If you just want the fastest path, jump to the **[Quickstart](/getting-started/quickstart)**.

## How onboarding works (the big picture)

Correlix monitors your network **agentlessly first** — it talks to your devices over standard protocols (SNMP, ICMP, streaming telemetry) and receives pushed telemetry (syslog, SNMP traps, flow records). You don't have to install software on every device.

The journey is always the same four moves:

1. **Discover or add** your devices, so Correlix knows what exists.
2. **Give it credentials** (SNMP community strings / SNMPv3 users) so it can read them.
3. **Point telemetry at it** — syslog, flows, and traps that devices push.
4. **Verify** each device is green on the coverage matrix and its dashboards fill in.

Everything after that — dashboards, monitors, topology, correlation — happens automatically on the data you've onboarded.

## Before you begin

You'll want the following ready:

| Requirement | Why |
| --- | --- |
| **Network reachability** from Correlix to your devices' management IPs | SNMP polling, ICMP, streaming telemetry |
| **SNMP enabled** on the devices (v2c community *or* v3 user) | Read interface, device, and protocol metrics |
| **Credentials** — v2c community strings, or SNMPv3 username + auth/priv secrets | Authenticate to each device |
| **Firewall rules** allowing UDP 161 (SNMP), UDP 162 (traps), UDP 514 (syslog), and your flow ports (2055/4739/6343) | Poll and receive telemetry — see [Connectivity requirements](/reference/connectivity-requirements) |
| A **Correlix admin account** | Configure credentials, sources, and users |

:::info Read‑only by default
SNMP monitoring is **read‑only** — Correlix polls counters and state, it never changes device configuration. Use a read‑only community/user.
:::

## Signing in

Open your Correlix URL in a browser and sign in with your administrator account. The left **icon rail** is your main navigation, organized into zones:

- **Monitor** — Dashboards, Monitoring, Incident Response, Automation
- **Infrastructure** — the device fleet, maps, paths, and data collection
- **Security** — vulnerability, threat, compliance
- **Data** — Metrics, Flows, Logs
- **Correlix AI** and **Administration** are pinned at the bottom

Most onboarding happens under <kbd>Administration → Data Collection</kbd> and <kbd>Infrastructure → Devices</kbd>.

## Next steps

- **[Quickstart](/getting-started/quickstart)** — onboard one device end to end in ~15 minutes.
- **[Key concepts](/getting-started/concepts)** — the vocabulary (devices, monitors, incidents, correlations, seams).
- **[Onboard Network Devices](/onboard-devices/overview)** — the complete, per‑method onboarding reference.
