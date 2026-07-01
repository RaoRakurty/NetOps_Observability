---
title: Events & Incidents overview
sidebar_label: Overview
sidebar_position: 1
description: How raw signals become anomalies, correlations, and ranked incidents — and where each lives in the console.
---

# Events & Incidents

This is where Correlix earns its keep: instead of a flood of alerts, it groups related signals into **incidents** and names the **root cause** with evidence you can click and verify. Nothing here is a black box — every verdict states what supports it, what contradicts it, and what's still missing.

## What's in it

Everything lives under the console's <kbd>Monitoring</kbd> section, in the **Event Management** group:

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Events** | <kbd>Monitoring → Events</kbd> | Raw signal stream — syslog, SNMP traps, and active alerts on one timeline |
| **Incidents** | <kbd>Monitoring → Incidents</kbd> | Tracked, deduplicated problem records with a lifecycle (ack → investigate → resolve) |
| **Anomalies** | <kbd>Monitoring → Anomalies</kbd> | Automatically detected deviations from baseline — no thresholds to tune |
| **Correlations** | <kbd>Monitoring → Correlations</kbd> | The RCA view — evidence-linked candidates with an honest verdict |
| **Service View** | <kbd>Monitoring → Service View</kbd> | Application-centric health and attribution |
| **Recovery Scorecard** | <kbd>Monitoring → Recovery Scorecard</kbd> | Per-phase incident timing (MTTI, correlation time, recovery, repeat rate) |

## From signal to incident

Correlix builds an incident in layers. Each layer is visible in the console, so you can always trace a conclusion back to the raw signal that started it.

1. **Events** — the raw feed. Syslog messages, SNMP traps, and monitor-rule alerts arrive on one time-sorted timeline (<kbd>Monitoring → Events</kbd>). At this stage nothing is interpreted; it's the ground truth every later layer points back to.
2. **Anomalies** — automatic detection. For every device + metric pair, Correlix keeps a rolling baseline of recent samples and flags values that deviate sharply from it (a rolling z-score — see [Anomalies & Correlations](/incidents/anomalies-and-correlations)). Deviations appear as **findings** under <kbd>Monitoring → Anomalies</kbd>, scored and severity-ranked, with no threshold for you to configure.
3. **Correlations** — evidence linking. The correlation engine groups anomalies, routing/link events, traffic-flow changes, and active-probe results that share a time window and a network relationship (same path, or a responsibility boundary such as your ISP handoff). Each group becomes an **RCA candidate** under <kbd>Monitoring → Correlations</kbd>, ranked against a catalog of known failure signatures (BGP peer flap, local link fault, WAN edge congestion, and so on) and given a verdict.
4. **Incidents** — the actionable record. A tracked incident under <kbd>Monitoring → Incidents</kbd> is the system-of-record view: deduplicated (recurrences fold into one row with an occurrence count), driven through a lifecycle, and optionally mirrored to your ITSM as **one ticket per incident** (see [RCA Auto-Ticketing](/incident-response/rca-ticketing)).
5. **Recovery Scorecard** — the feedback loop. Each incident's clock is decomposed into phases — detect → correlate → isolate → owner → recover → close — so you can see *where time went* and improve the process, not just react (<kbd>Monitoring → Recovery Scorecard</kbd>).

## How a verdict reads

Every RCA candidate carries a **status** — the engine's honest claim about what it knows:

- **Confirmed** — independent evidence agrees across at least **two signal classes** (for example a routing event *and* a traffic-flow drop, or a device fault *and* a failing active probe). Correlix never shows "confirmed" on a single evidence stream, however strong.
- **Suspected** — a real signal was observed and localized, but customer impact is not yet confirmed by an independent stream.
- **Not confirmed** — evidence is still being gathered; a watch item, not yet actionable.

Alongside the status you get the **likely cause** (a named failure signature), the **recommended owner** (NetOps, ISP / carrier, cloud provider, app team, …), the **supporting evidence** with what's missing spelled out, and **next actions**. See [Key concepts](/getting-started/concepts) for the vocabulary.

:::tip Feed it more planes
Correlation strength scales with independent telemetry. A metrics-only deployment can still detect and suspect; adding [syslog](/send-data/syslog), [traps](/send-data/traps), and [flows](/send-data/flows) gives the engine the independent streams it needs to *confirm*.
:::

## In this section

- **[Reading an incident](/incidents/reading-an-incident)** — a guided walk through the RCA detail view: verdict, evidence matrix, causal topology, timeline, ticket card, and time metrics.
- **[Working incidents](/incidents/working-incidents)** — the operator loop: triage the queue, drill down, drive the lifecycle, file the ticket, and know when to trust a verdict.
- **[Anomalies & Correlations](/incidents/anomalies-and-correlations)** — how detection and correlation work under the hood, and how to use both console pages.
