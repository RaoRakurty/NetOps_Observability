---
title: What is Correlix?
sidebar_label: Introduction
sidebar_position: 1
description: Correlix is a network observability platform that discovers your devices, watches every plane of telemetry, and tells you the root cause of an incident — with the evidence.
slug: /
---

# What is Correlix?

Correlix is a **network observability platform** for NOC and network‑engineering teams. It discovers your network devices, collects telemetry from every plane (metrics, flows, logs, traps, and active path measurements), detects when something is wrong, and — the part that sets it apart — **correlates the signals into a single root cause, with the evidence that proves it.**

You point Correlix at your network. It builds an inventory, starts monitoring, draws the topology, and when an incident happens it tells you *what broke, where, who owns it, and why* — instead of handing you a wall of disconnected alerts.

## What you can do with Correlix

- **Onboard your network** — auto‑discover devices over SNMP, add streaming telemetry (gNMI/NETCONF), and ingest syslog, SNMP traps, and flow records (NetFlow/sFlow/IPFIX).
- **Monitor everything** — device health, interface performance, routing protocols (BGP/OSPF/IS‑IS), link quality, WAN circuits, and tunnels — on ready‑made dashboards.
- **See your network** — a live topology canvas, a geographic map, and hop‑by‑hop path traces.
- **Catch problems early** — z‑score anomaly detection, threshold monitors, and alert rules with notifications to Slack, PagerDuty, email, SMS, and more.
- **Find root cause fast** — the correlation engine groups related signals into one incident, ranks it, names the fault domain, and recommends an owner and next actions.
- **Close the loop** — auto‑file a ticket in ServiceNow/Jira, and measure how long each phase of the incident took.
- **Ask in plain language** — Correlix AI answers "what's going on right now?" and "explain the top incident" grounded in your live, tenant‑scoped data.
- **Stay secure & compliant** — vulnerability, threat, and compliance posture across the fleet, with full role‑based access and audit.

## How this documentation is organized

This portal is **task‑oriented** — it tells you *how to configure and use* each feature, step by step, from an operator's point of view. You don't need to know the internals.

1. **[Getting Started](/getting-started/overview)** — what you need, and a 15‑minute quickstart to onboard your first device.
2. **[Onboard Network Devices](/onboard-devices/overview)** — the full device‑onboarding journey: discovery, credentials, streaming telemetry, and verification.
3. **[Send Data](/send-data/overview)** — point metrics, flows, logs, and traps at Correlix.
4. **Product sections** — Infrastructure, Monitoring, Incidents, Incident Response, Security, Explore, Correlix AI, Dashboards, Automation.
5. **[Administration](/administration/overview)** — users, roles, SSO, API access, tenants, and audit.
6. **[Reference](/reference/connectivity-requirements)** — connectivity requirements, glossary, and troubleshooting.

:::tip New to Correlix?
Start with the **[Quickstart](/getting-started/quickstart)** — you'll have a device discovered and reporting in about 15 minutes.
:::
