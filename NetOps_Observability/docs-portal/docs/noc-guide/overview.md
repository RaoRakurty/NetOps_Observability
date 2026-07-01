---
title: How Correlix tells the story of an outage
sidebar_label: The story of an outage
sidebar_position: 1
description: The pipeline from raw telemetry to a filed ticket — which console tab each stage lives in, what you see there, and what it contributes to the root-cause story.
---

# How Correlix tells the story of an outage

Correlix is built around one idea: an outage is a **story**, and every tab in the console is a chapter of it. Raw telemetry becomes events, events become anomalies, anomalies and events correlate into a ranked incident with a root-cause verdict, and a confirmed incident becomes a notification and a single ticket. If you know which chapter each tab tells, you always know where to look next.

The arc, end to end:

```
Raw telemetry (metrics · logs · flows · traps)
        │  devices send, Correlix collects
        ▼
Events            — Monitoring → Events
        │  one time-sorted stream of everything the network said
        ▼
Anomalies         — Monitoring → Anomalies
        │  signals that deviate from the statistical baseline
        ▼
Correlation       — Monitoring → Correlations
        │  related evidence grouped, ranked, given a verdict
        ▼
Incident + RCA    — Dashboards → Home (Command Center) · Monitoring → Incidents
        │  what's burning, who owns it, what to do next
        ▼
Notification      — Incident Response → Notifications
        │  the right people hear about it
        ▼
Ticket            — Incident Response → RCA Auto-Ticketing
           one ticket per root cause, never per raw alert
```

The sections below walk each stage: where it lives, what you see, and what it adds to the final root-cause story.

## Stage 1 — Raw telemetry

**Where it lives:** nowhere you triage directly — this is the input. Devices send [syslog](/send-data/syslog), [SNMP metrics](/send-data/metrics), [flow records](/send-data/flows), and [SNMP traps](/send-data/traps). You can inspect any of it raw under <kbd>Logs → Log Search</kbd>, <kbd>Metrics</kbd>, and <kbd>Flows</kbd>.

**What it contributes:** every later claim is grounded in this data. When an RCA says "confirmed", it can point back to the exact log lines, metric excursions, and probe results that support it. If telemetry from a device is missing, everything downstream about that device is blind — so [verify monitoring](/onboard-devices/verify-monitoring) is step zero.

## Stage 2 — Events

**Where it lives:** <kbd>Monitoring → Events</kbd>.

**What you see:** a single time-sorted **Signal stream** merging three sources — device **syslog**, **SNMP traps**, and **active alerts** (monitor rules currently firing). Each row carries Time, Type, Severity, Source, and the event text. A search box and a type filter (All / syslog / trap / alert) narrow the stream; clicking a row opens the full detail, including the raw message.

**What it contributes:** this is the *unfiltered narrative* — everything the network said, in order. Nothing is judged yet. When you need to know "what happened around 14:32", this is the one timeline that has it all.

## Stage 3 — Anomalies

**Where it lives:** <kbd>Monitoring → Anomalies</kbd>.

**What you see:** the **Detected Findings** queue — "signals that deviate from baseline and may contribute to incidents or RCA candidates." Each finding row shows Time, Severity (info / warning / critical), Kind, Device, Component, a plain-language Summary, and a Score. Clicking a row opens its context, with a **View logs** button that pivots straight to that device's logs.

**What it contributes:** judgment enters the story. Correlix keeps a rolling statistical baseline per device and metric; a finding says "this is *not normal* for this device" — a claim a raw event can't make. Findings are the individual clues the correlation engine will try to assemble.

## Stage 4 — Correlation

**Where it lives:** <kbd>Monitoring → Correlations</kbd>.

**What you see:** the **RCA Candidates** queue. Each row is a *correlation group* — related anomalies and events bound together by time and by network relationships (same path, or a shared boundary). Columns show Status (**Confirmed** / **Suspected** / **Not confirmed**), Quality, **Likely cause** (a named failure pattern, or "Not yet determined"), Owner, **Linked by** (how the evidence is related: Boundary, Boundary + path, Same path), the count of independent **Evidence types**, and the number of correlated **Signals**. Clicking a row opens the full RCA workspace.

**What it contributes:** the clues become a *hypothesis*. The engine matches the group's shape against a catalog of known failure patterns and issues an honest verdict. The bar is strict and worth memorizing: **a root cause is confirmed only when independent evidence agrees across at least two signal classes** — a single stream, however loud, stays *Suspected*, and weaker candidates say exactly what evidence is missing.

## Stage 5 — Incident with RCA

**Where it lives:** two places, for two jobs.

- <kbd>Dashboards → Home</kbd> — the **Command Center**. Its **Action Queue** lists correlated incidents (not raw alerts) ranked by severity and age, each with a Problem ID, RCA state, Impact, Fault domain, Evidence completeness, Owner, Ticket state, and a recommended **Next action**. This is the triage cockpit; see [Where to start](/noc-guide/where-to-start).
- <kbd>Monitoring → Incidents</kbd> — **Operational Incidents**, the tracked system of record. Here you drive the lifecycle: Acknowledge → Investigate → Resolve, add notes, and see the full timeline including ticket-sync events.

**What it contributes:** the story gets a protagonist (an owner), a scope (impacted devices and sites), and a plan (next actions). Opening a queue row's RCA shows the complete evidence-backed case — confidence, blast radius, causal path, evidence timeline, hypothesis ranking. The walkthrough in [From signal to ticket](/noc-guide/from-signal-to-ticket) covers every element.

## Stage 6 — Notification

**Where it lives:** <kbd>Incident Response → Notifications</kbd> (configuration).

**What you see:** delivery channels — email, Slack, PagerDuty, SMS, and push — plus reusable contact points. Configured once by an administrator; from then on incidents reach people without anyone watching the screen. Details in [Notifications](/incident-response/notifications).

**What it contributes:** the story reaches its audience. Because notifications ride on correlated incidents rather than raw alerts, one root cause produces one page — not fifty.

## Stage 7 — Ticket

**Where it lives:** policy at <kbd>Incident Response → RCA Auto-Ticketing</kbd>; the live ticket on the incident's own RCA view (the **External ticket** card).

**What you see:** policies that decide when an RCA object opens a ServiceNow ticket — **one ticket per root cause, never per raw alert** — gated by minimum verdict, customer-facing impact, severity, and persistence. On the RCA itself, the External ticket card shows the ticket number (deep-linked), last sync time, the verdict at sync, and the action history. See [RCA Auto-Ticketing](/incident-response/rca-ticketing).

**What it contributes:** the story becomes a record. The ticket carries the diagnosis and evidence, stays synced as the verdict evolves, and closes the loop when the incident resolves.

## Which tab do I open when

| You want to… | Open | You'll see |
|---|---|---|
| Start a shift / triage what matters | <kbd>Dashboards → Home</kbd> | Command Center Action Queue — ranked correlated incidents |
| See everything the network said, raw | <kbd>Monitoring → Events</kbd> | Merged syslog + trap + alert stream |
| See what's abnormal vs. baseline | <kbd>Monitoring → Anomalies</kbd> | Detected Findings with severity and score |
| See grouped evidence and the verdict | <kbd>Monitoring → Correlations</kbd> | RCA Candidates; click a row for the full RCA |
| Work an incident's lifecycle | <kbd>Monitoring → Incidents</kbd> | Ack / Investigate / Resolve + timeline |
| Check which monitor rules are firing now | <kbd>Monitoring → Active Alerts</kbd> | Live alert queue |
| Search device logs directly | <kbd>Logs → Log Search</kbd> | Query, filter, export — see [Reading logs](/noc-guide/reading-logs) |
| Verify a fault's location on the map | <kbd>Infrastructure → Topology Canvas</kbd> | Investigate mode lands on the RCA path |
| Control when tickets are filed | <kbd>Incident Response → RCA Auto-Ticketing</kbd> | Ticketing policies + simulator |

:::tip
Every stage links to the next in the UI itself — findings have **View logs**, queue rows have **Open RCA**, RCAs have the ticket card. When in doubt, follow the buttons; they follow the story.
:::
