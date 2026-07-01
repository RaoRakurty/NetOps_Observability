---
title: Create a monitor
sidebar_label: Create a monitor
sidebar_position: 2
description: Build a threshold monitor that alerts your team when a condition is breached.
---

# Create a monitor

A **monitor** watches a metric or condition and raises an **alert** when it's breached. Create one at <kbd>Monitoring → Create Monitor</kbd>.

## Steps

1. Go to <kbd>Monitoring → Create Monitor</kbd>.
2. Choose **what to watch** — a metric (e.g. interface utilization, CPU, availability) and the scope (a device, a group, or all).
3. Set the **condition** — the threshold and comparison (e.g. utilization `> 90%` for `5m`).
4. Set **severity** (warning/critical).
5. Choose **notifications** — the [channels](/incident-response/notifications) to alert (Slack, PagerDuty, email, …).
6. Name it and save.

The monitor now appears under <kbd>Monitoring → Monitor Rules</kbd>, and breaches show under <kbd>Monitoring → Active Alerts</kbd>.

## Thresholds vs anomalies

You don't have to write a rule for everything. Correlix's **[anomaly detection](/monitoring/overview)** flags deviations automatically with no threshold to tune — use monitors for the specific conditions you care about, and let anomaly detection cover the long tail.

## Tips

- Add a **duration** (`for 5m`) to avoid flapping on brief spikes.
- Alerts feed **[correlation](/incidents/overview)** — a monitor breach that lines up with other signals strengthens an incident's verdict.
