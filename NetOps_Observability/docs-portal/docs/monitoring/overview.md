---
title: Monitoring & Alerting overview
sidebar_label: Overview
sidebar_position: 1
description: Create monitors, get alerted, and track link quality and anomalies.
---

# Monitoring & Alerting

Define what "bad" looks like and get told when it happens. Correlix combines **threshold monitors** you define with **automatic anomaly detection**, so you catch both the conditions you know about and the ones you don't.

## What's in it

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Monitor Rules** | <kbd>Monitoring → Monitor Rules</kbd> | Your defined monitors |
| **[Create Monitor](/monitoring/create-a-monitor)** | <kbd>Monitoring → Create Monitor</kbd> | Build a new monitor |
| **Active Alerts** | <kbd>Monitoring → Active Alerts</kbd> | Currently firing alerts |
| **Link Quality** | <kbd>Monitoring → Link Quality</kbd> | Latency/jitter/loss baselines per link |
| **Anomalies** | <kbd>Monitoring → Anomalies</kbd> | Auto‑detected deviations (z‑score) |

## How detection works (operator view)

- **Monitors** watch a metric against a threshold you set and raise an **alert** when breached.
- **Anomaly detection** learns each metric's normal range and flags deviations with **no threshold to tune** — good for the long tail you'd never write rules for.
- Alerts route to people and tools via **[Notifications](/incident-response/overview)**.

Start with **[Create a monitor](/monitoring/create-a-monitor)**.
