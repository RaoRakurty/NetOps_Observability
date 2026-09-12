---
title: Correlix documentation
sidebar_label: Documentation
description: What Correlix is, who this documentation is for, and where each of the nine sections starts.
page_type: index
sidebar_position: 1
slug: /
---

# Correlix documentation

Correlix is a network observability platform. It collects telemetry from network
devices, groups the observations that share a cause into one RCA case, names the seam
that owns the fault, and shows the evidence behind every verdict. This
documentation is for the people who run Correlix: the operators who work a
shift, the engineers who investigate an outage, and the administrators who
onboard devices and manage access.

The console listens on TCP port 8000 by default. This portal is served by the
product at `/docs/`, and the question-mark button in the console's top bar opens
it in a Help drawer beside the page you are on.

## Sections

| Section | What it covers |
|---|---|
| [Get started](/getting-started/overview) | What Correlix does, the concepts the rest of the set assumes, and a first monitored device. |
| [Deploy](/deploy/overview) | Requirements, sizing, installation on Linux and air-gapped hosts, TLS, verification, upgrade and restore. |
| [Operate](/noc-guide/overview) | Getting data in and keeping it flowing: devices, telemetry, monitors, alerts, incidents and dashboards. |
| [Investigate](/investigate/overview) | Why something broke: RCA cases, the troubleshooting workspace, protocol diagnostics and Iris. |
| [Security](/security/overview) | Continuous threat and exposure management: findings, exposures, compliance, detection rules, configuration drift and packet capture. |
| [BGP operations](/bgp/overview) | The routing observatory: prefix watchlist, RPKI, geofeed, AS paths, BMP sessions, bogons and routing alerts. |
| [Administration](/administration/overview) | Users, roles, tenants, authentication, API access, audit, and data-collection administration. |
| [Reference](/reference/glossary) | Lookup tables: API routes, feature flags, alert rules, ports, metrics and the glossary. |
| [Release notes](/release-notes/whats-new) | What changed, by month. |

## Start here

1. [What Correlix does](/getting-started/overview) states what the product
   collects, what it decides, and what it deliberately does not claim.
2. [Core concepts](/getting-started/concepts) defines the mental model the rest
   of this set assumes: telemetry classes, correlation, RCA cases, seams,
   tenants, and the honesty principle.
3. [Onboard your first device](/getting-started/quickstart) takes one device
   from an empty inventory to live metrics, with a checkpoint after each step.
4. [Start a shift](/noc-guide/where-to-start) is the operator routine once
   devices are reporting.
