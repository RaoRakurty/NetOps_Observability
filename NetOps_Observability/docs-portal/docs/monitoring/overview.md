---
title: Monitoring & Alerting overview
sidebar_label: Overview
sidebar_position: 1
description: How monitor rules, active alerts, notifications, and link-quality baselines fit together.
---

# Monitoring & Alerting

Define what "bad" looks like and get told when it happens. Correlix combines **threshold monitors** you define with **automatic anomaly detection**, so you catch both the conditions you know about and the ones you don't.

## The monitoring model

Monitoring in Correlix is a pipeline with three stages:

1. **Monitor rules** define a condition over collected telemetry — "CPU above 85% for 5 minutes", "a BGP session left Established". Every rule is evaluated **every 30 seconds** against the metric store.
2. **Active alerts** are the rules that are firing *right now*. One rule can raise several alerts at once — a "High CPU" rule fires **one alert per matching device**, so the alert queue tells you exactly which devices and interfaces are affected, not just which rules tripped.
3. **Notifications and incidents** carry the alert to people and tools. When an alert first fires it is dispatched once to your configured [notification channels](/incident-response/notifications) and fed into [correlation](/incidents/overview), where it can combine with logs, events, and other alerts into an incident.

Alerts **resolve themselves**: when the condition stops holding, the alert clears on the next 30-second evaluation. There is no manual acknowledge/close step to forget.

## What's in this section

| Page | Console path | What it's for |
| --- | --- | --- |
| **Monitor Rules** | <kbd>Monitoring → Monitor Rules</kbd> | Every rule the engine is evaluating — built-in and custom — with delete for custom monitors |
| **[Create Monitor](/monitoring/create-a-monitor)** | <kbd>Monitoring → Create Monitor</kbd> | Guided three-step wizard: pick a signal, tune the condition, review with a live preview |
| **[Active Alerts](/monitoring/manage-alerts)** | <kbd>Monitoring → Active Alerts</kbd> | The live alert queue — triage what is firing right now |
| **[Link Quality](/monitoring/link-quality)** | <kbd>Monitoring → Link Quality</kbd> | Error, discard, saturation, and overlay-tunnel quality across the fleet |
| **Anomalies** | <kbd>Monitoring → Anomalies</kbd> | Auto-detected deviations from each metric's learned baseline — no threshold to tune |

## Built-in vs. custom monitors

The **Monitor Rules** page (<kbd>Monitoring → Monitor Rules</kbd>) lists two kinds of rules, distinguished by the **Source** badge:

- **Built-in** rules ship with the platform and cover core hygiene out of the box. They cannot be deleted from the console.
- **Custom** monitors are yours — created through the [Create Monitor wizard](/monitoring/create-a-monitor) or the quick **Add rule** button on Monitor Rules. Only custom monitors show a **Delete** action.

Deleting a custom monitor takes effect on the next evaluation: any alerts it raised resolve automatically within about 30 seconds.

## How a rule decides to fire

Understanding three behaviors will save you tuning time:

- **Evaluation tick.** The engine evaluates every rule every **30 seconds**. Firing and resolving both happen on that tick, so a condition can never be caught faster than 30 seconds after it starts.
- **"Must hold for" gating.** Each rule has a hold-for duration. A condition that starts matching becomes *pending*; it is promoted to a firing alert only after it has held **continuously** for that long. If the condition drops out even briefly, the clock restarts. This is your main anti-flap control — a 300-second hold-for means a 10-second CPU spike never pages anyone.
- **Per-series alerts with stable identity.** Each matching device/interface gets its own alert, and an alert keeps its original **Fired** time for as long as it stays firing — the "Aging" figure on Active Alerts is real time-in-breach, not time since the last evaluation.

Notifications are sent **only when an alert first fires** — an alert that stays firing for three hours produces one notification, not one every 30 seconds.

## Thresholds vs. anomalies

You don't have to write a rule for everything:

- Use **monitors** for the conditions you can name and want a hard contract on — saturation limits, protocol sessions, device reachability, path SLA.
- Let **anomaly detection** (<kbd>Monitoring → Anomalies</kbd>) cover the long tail. It learns each metric's normal range and flags statistical deviations with no threshold to tune, catching the "this link is suddenly behaving differently" cases you'd never write rules for.

Both feed the same [correlation and incident pipeline](/incidents/overview), so a monitor breach that lines up with an anomaly and matching log events strengthens the incident's verdict.

## Prerequisites

Monitors only fire on telemetry that is actually arriving. Before writing rules, make sure your devices are onboarded and reporting — see [Verify monitoring](/onboard-devices/verify-monitoring). The Create Monitor wizard flags any signal template with a **no live data** badge when its underlying telemetry isn't being collected yet, so you won't silently build a monitor that can never fire.

## Where to start

1. Create your first monitor with the wizard: **[Create a monitor](/monitoring/create-a-monitor)**.
2. Learn to read and triage the queue: **[Work with active alerts](/monitoring/manage-alerts)**.
3. Baseline the health of your links: **[Link Quality](/monitoring/link-quality)**.
4. Wire alerts to your team: **[Notifications](/incident-response/notifications)**.
