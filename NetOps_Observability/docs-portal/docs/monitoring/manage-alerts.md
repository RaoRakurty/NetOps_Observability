---
title: Work with active alerts
sidebar_label: Work with active alerts
sidebar_position: 3
description: Read the Active Alerts queue, drill into an alert's context, pivot to device logs, and follow an alert into an incident.
---

# Work with active alerts

<kbd>Monitoring → Active Alerts</kbd> is the live queue of every monitor rule currently firing. It refreshes automatically (about every 10 seconds), so what you see is the network's state now — not a history. Triage here before alerts correlate into incidents.

## Reading the page

### The header

At the top, a **firing** counter and four KPIs summarize the queue:

| KPI | Meaning |
| --- | --- |
| **Active alerts** | Total rules-instances firing right now |
| **Critical** | Alerts at critical severity — work these first |
| **Warning** | Alerts above threshold but not severe |
| **Aging `>` 1h** | Alerts that have been firing for over an hour — sustained breaches nobody has cleared |

A healthy quiet network shows **0 firing** and the empty state *"No active alerts — all monitored conditions are within threshold."*

### The alert queue

Each row is one firing alert. Because monitors fire **per matching series**, one rule breached on three devices produces three rows — the queue tells you *what is affected*, not just *which rules tripped*.

| Column | Meaning |
| --- | --- |
| **Rule** | The monitor that fired (the name you gave it, e.g. `HighCPU-Leafs`) |
| **Severity** | `info` / `warning` / `critical`, color-coded; the row's edge is tinted to match |
| **Device** | The device this alert instance is about, when the signal carries one (blank for fleet-wide conditions) |
| **Summary** | Human-readable description of the breach, including the measured value |
| **Fired** | When this alert *first* started firing. This is preserved across evaluations — it's true time-in-breach |

Columns sort by clicking the header; the default sort is newest-fired first. Sort by **Severity** to work criticals top-down, or by **Fired** ascending to find the oldest unresolved breaches.

## Triage an alert, step by step

1. Go to <kbd>Monitoring → Active Alerts</kbd>.
2. Sort by **Severity** and start with critical rows.
3. **Click a row** to open the alert's detail panel (the inspector). It shows:
   - the severity badge and rule name,
   - the **summary** and, when the rule defines one, a longer **description**,
   - **Fired** / **Resolved** timestamps, the **Device**, the alert **ID**,
   - all **labels** attached to the alert (device, interface, and anything the rule adds) — these tell you exactly which series breached.
4. If the alert names a device, click **View logs**. This docks that device's recent syslog (last hour) in the drawer, right next to the alert — the fastest way to see *why* an interface went down or a session dropped.
5. Decide the path:
   - **Transient / already recovering** — leave it; the alert resolves itself on the next evaluation once the condition clears (within about 30 seconds).
   - **Real problem** — go fix the underlying cause; use the labels to identify the exact device and interface.
   - **Part of something bigger** — check <kbd>Monitoring → Incidents</kbd>. Firing alerts feed [correlation](/incidents/overview); if this alert lines up with log events, anomalies, or other alerts, you'll find an incident there with the combined evidence and root-cause analysis.

## Alert lifecycle — what you can and can't do

Correlix alerts are **condition-driven, not workflow-driven**:

- An alert exists exactly as long as its condition holds. When the condition clears, the alert **resolves automatically** on the next 30-second evaluation and leaves the queue. There is no manual acknowledge or close button — you can't dismiss an alert while the network condition is still true, and you never have to remember to close one that isn't.
- **Notifications fire once**, when the alert first starts firing. A three-hour breach produces one notification, not 360. Delivery goes to the channels configured under [Incident Response → Notifications](/incident-response/notifications).
- To **stop an alert you no longer want**, change or remove its monitor: <kbd>Monitoring → Monitor Rules</kbd> → **Delete** on the custom rule (its alerts resolve on the next evaluation), or recreate it with a higher threshold or longer hold-for via [Create Monitor](/monitoring/create-a-monitor).

:::note
Incident-level workflow — assignment, tickets, status — lives on the [incident](/incidents/overview), not the raw alert. Alerts are the raw signal; incidents are the unit of response.
:::

## From an alert to the underlying metric

The alert's **Summary** includes the measured value at fire time, and the labels name the device and interface. To see the metric's behavior around the breach:

1. Note the device (and interface, if present) from the alert detail.
2. Open <kbd>Infrastructure → Device Monitoring</kbd> and locate the device to chart the signal over the alert's **Fired** window.
3. For link-shaped alerts (errors, discards, utilization), <kbd>Monitoring → Link Quality</kbd> shows the same device ranked against the rest of the fleet — useful for judging whether it's an outlier or a fleet-wide pattern. See [Link Quality](/monitoring/link-quality).

## Verify it worked

After fixing the underlying cause:

1. Stay on <kbd>Monitoring → Active Alerts</kbd> — the page refreshes itself.
2. Within one evaluation tick (up to 30 seconds) plus the rule's hold-for behavior, the alert disappears from the queue.
3. The KPI counters drop accordingly; **0 firing** means every monitored condition is back within threshold.

## Troubleshooting

- **An alert won't clear even though the device looks fine.** The condition is still evaluating true — open the alert, read the summary's measured value, and check the metric directly. Remember resolution is tick-grained: allow up to 30 seconds after the condition actually clears.
- **The same alert keeps re-firing.** The value is oscillating around the threshold. Each re-fire is a *new* alert (new Fired time, new notification). Raise the threshold or lengthen the monitor's **Must hold for** — see [Create a monitor](/monitoring/create-a-monitor).
- **A row has no Device.** The rule's signal doesn't carry a device label (for example, a fleet-wide custom expression). The labels in the detail panel show whatever identity the series does have.
- **No notification arrived for a firing alert.** Notifications dispatch only on the *first* fire, and only to configured channels — check [Notifications](/incident-response/notifications) setup and channel test delivery.
