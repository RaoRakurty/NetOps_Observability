---
title: What is Correlix?
sidebar_label: Introduction
sidebar_position: 1
description: Correlix is a network observability platform that discovers your devices, watches every plane of telemetry, and tells you the root cause of an incident — with the evidence.
slug: /
hide_title: true
---

import Link from '@docusaurus/Link';

<div className="cx-hero">
  <span className="cx-hero__eyebrow">Correlix Documentation</span>
  <h1 className="cx-hero__title">Network observability that names the <span className="grad">root cause</span> — with the evidence.</h1>
  <p className="cx-hero__lead">
    Point Correlix at your network. It discovers your devices, watches every plane of
    telemetry, and when something breaks it correlates the signals into a single incident —
    telling you <em>what broke, where, who owns it, and why</em> instead of a wall of alerts.
  </p>
  <div className="cx-hero__actions">
    <Link className="cx-btn cx-btn--primary" to="/getting-started/quickstart">Quickstart — 15 min ↗</Link>
    <Link className="cx-btn cx-btn--ghost" to="/onboard-devices/overview">Onboard your devices</Link>
  </div>
</div>

## Start here

<div className="cx-cards">
  <Link className="cx-card" to="/getting-started/overview">
    <span className="cx-card__icon">🚀</span>
    <p className="cx-card__title">Getting Started</p>
    <p className="cx-card__desc">What you need, core concepts, and a 15-minute path to your first monitored device.</p>
    <span className="cx-card__arrow">Read →</span>
  </Link>
  <Link className="cx-card" to="/onboard-devices/overview">
    <span className="cx-card__icon">🔌</span>
    <p className="cx-card__title">Onboard Devices</p>
    <p className="cx-card__desc">SNMP discovery, credentials, streaming telemetry (gNMI/NETCONF), and verification.</p>
    <span className="cx-card__arrow">Read →</span>
  </Link>
  <Link className="cx-card" to="/send-data/overview">
    <span className="cx-card__icon">📡</span>
    <p className="cx-card__title">Send Data</p>
    <p className="cx-card__desc">Point metrics, flows, logs, and SNMP traps at Correlix from any vendor.</p>
    <span className="cx-card__arrow">Read →</span>
  </Link>
  <Link className="cx-card" to="/noc-guide/overview">
    <span className="cx-card__icon">🧭</span>
    <p className="cx-card__title">NOC Operator Guide</p>
    <p className="cx-card__desc">How each tab builds the story of an outage — from raw signals to correlation, root cause, and the ticket.</p>
    <span className="cx-card__arrow">Read →</span>
  </Link>
</div>

## What you can do with Correlix

<div className="cx-cards">
  <Link className="cx-card" to="/infrastructure/overview">
    <span className="cx-card__icon">🗺️</span>
    <p className="cx-card__title">See your network</p>
    <p className="cx-card__desc">A live topology canvas, a geographic map, and hop-by-hop path traces.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
  <Link className="cx-card" to="/monitoring/overview">
    <span className="cx-card__icon">📈</span>
    <p className="cx-card__title">Monitor everything</p>
    <p className="cx-card__desc">Device health, interfaces, BGP/OSPF/IS-IS, link quality, WAN circuits, and tunnels.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
  <Link className="cx-card" to="/incidents/overview">
    <span className="cx-card__icon">🎯</span>
    <p className="cx-card__title">Find root cause fast</p>
    <p className="cx-card__desc">The correlation engine groups related signals into one ranked incident with a fault domain.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
  <Link className="cx-card cx-card--ai" to="/iris-ai/overview">
    <span className="cx-card__icon">🤖</span>
    <p className="cx-card__title">Ask in plain language</p>
    <p className="cx-card__desc">Iris AI answers "what's going on right now?" grounded in your live, tenant-scoped data.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
  <Link className="cx-card" to="/incident-response/overview">
    <span className="cx-card__icon">🔔</span>
    <p className="cx-card__title">Close the loop</p>
    <p className="cx-card__desc">Notify Slack, PagerDuty, email and SMS; auto-file ServiceNow/Jira tickets and time each phase.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
  <Link className="cx-card cx-card--sec" to="/security/overview">
    <span className="cx-card__icon">🛡️</span>
    <p className="cx-card__title">Stay secure & compliant</p>
    <p className="cx-card__desc">Vulnerability, threat, and compliance posture across the fleet — with RBAC and full audit.</p>
    <span className="cx-card__arrow">Explore →</span>
  </Link>
</div>

## How this documentation is organized

This portal is **task-oriented** — it tells you *how to configure and use* each feature, step by step, from an operator's point of view. You don't need to know the internals.

1. **[Getting Started](/getting-started/overview)** — what you need, and a 15-minute quickstart to onboard your first device.
2. **[Onboard Network Devices](/onboard-devices/overview)** — the full device-onboarding journey: discovery, credentials, streaming telemetry, and verification.
3. **[Send Data](/send-data/overview)** — point metrics, flows, logs, and traps at Correlix.
4. **Product sections** — Infrastructure, Monitoring, Incidents, Incident Response, Security, Explore, Iris AI, Dashboards, Automation.
5. **[Administration](/administration/overview)** — users, roles, SSO, API access, tenants, and audit.
6. **[Reference](/reference/connectivity-requirements)** — connectivity requirements, glossary, and troubleshooting.

:::tip New to Correlix?
Start with the **[Quickstart](/getting-started/quickstart)** — you'll have a device discovered and reporting in about 15 minutes.
:::
