---
title: Create a monitor
sidebar_label: Create a monitor
sidebar_position: 2
description: Step-by-step guide to the Create Monitor wizard — signal templates, conditions, thresholds, severity, and the live preview.
---

# Create a monitor

A **monitor** watches a condition over your telemetry and raises an **alert** when it's breached. The guided wizard at <kbd>Monitoring → Create Monitor</kbd> builds one in three steps — pick a **signal**, tune the **condition**, then **review** with a live preview that shows exactly what would fire right now.

Every signal template is backed by telemetry the platform already collects. If a template's signal isn't currently arriving, the wizard marks it **no live data** — the monitor would still be valid, but it won't fire until that signal is collected.

## Before you begin

- Devices must be onboarded and reporting metrics — see [Verify monitoring](/onboard-devices/verify-monitoring).
- To have alerts reach your team, configure a [notification channel](/incident-response/notifications) first. Alerts fire either way; only delivery needs a channel.

## Step 1 — Pick a signal

1. Go to <kbd>Monitoring → Create Monitor</kbd>.
2. Under **Signal**, click a template card. Cards are grouped by category:

| Category | Template | Watches for | Default threshold | Default hold / severity |
| --- | --- | --- | --- | --- |
| Availability | **Device unreachable** | A monitored device stopped answering its collector | — (state) | 120 s / critical |
| Availability | **Interface down** | An admin-up interface went operationally down | — (state) | 120 s / critical |
| Availability | **Interface flapping** | Repeated interface state changes within 10 minutes | 4 changes/10m | fire immediately / warning |
| Resources | **High CPU** | Device CPU utilization above a threshold | 85 % | 300 s / warning |
| Resources | **High memory** | Device memory utilization above a threshold | 85 % | 300 s / warning |
| Interfaces | **Interface errors** | Combined input + output error rate above a threshold | 1 errs/s | 300 s / warning |
| Interfaces | **Interface discards** | Packet discard rate above a threshold (congestion signal) | 1 pkts/s | 300 s / warning |
| Interfaces | **Interface utilization** | Inbound bandwidth as a share of line speed | 90 % | 300 s / warning |
| Routing | **BGP peer down** | A BGP session left the Established state | — (state) | 120 s / critical |
| Routing | **OSPF neighbor down** | An OSPF adjacency left the Full state | — (state) | 120 s / critical |
| Path SLA | **Path RTT** | Active-probe round-trip time above a threshold | 150 ms | 300 s / warning |
| Path SLA | **Path loss** | Active-probe packet loss above a threshold | 1 % | 300 s / critical |
| Custom | **Custom query** | Any query-language condition you write yourself | — | 300 s / warning |

Templates marked "— (state)" watch a state transition rather than a numeric level, so they have no threshold field in the next step.

3. Click **Next**.

## Step 2 — Tune the condition

Fill in the **Condition** step. Which fields appear depends on the template:

| Field | What it does | Example value |
| --- | --- | --- |
| **Device scope** | Optional. Restricts the monitor to devices whose name matches this pattern (regular expression). Leave empty to watch the whole fleet. | `leaf.*` or `edge-1` |
| **Threshold** | The breach level, shown with the template's unit (%, ms, errs/s, …). Only present on threshold templates. | `80` |
| **Must hold for** | Seconds the condition must hold **continuously** before the alert fires. `0` fires on the first matching evaluation (the engine evaluates every 30 seconds). A brief drop below the condition restarts the clock. | `300` |
| **Severity** | How loud the alert is: `info`, `warning`, or `critical`. Drives the color and sorting on Active Alerts and the routing weight downstream. | `critical` |
| **Query expression** | Custom template only — replaces scope and threshold. Write any query-language condition; the monitor fires while it returns at least one series. | `avg by (device) (device_cpu_percent) > 90` |

:::tip
Keep a non-zero **Must hold for** on anything noisy (CPU, utilization, errors) — it's the difference between "sustained problem" and "someone ran a backup for 40 seconds".
:::

Click **Next**.

## Step 3 — Review and create

1. Enter a **Monitor name** — letters, digits, dashes, and underscores; must be unique. Example: `HighCPU-Leafs`.
2. Check the **Final expression** — the exact query the engine will evaluate, with your scope and threshold filled in.
3. Read the **live preview**. The wizard evaluates the condition immediately and reports either **"would fire on N series right now"** — listing the matching devices/interfaces with their current values — or **"quiet right now — fires when the condition starts holding"**. If it would fire on far more series than you expect, tighten the scope or raise the threshold *before* creating.
4. Click **Create monitor**.

You'll see a **Monitor created** confirmation: the monitor is live and evaluated every 30 seconds. Use **View monitors →** to jump to the rules list, or **Create another**.

## Worked examples

### Interface utilization above 80%

1. <kbd>Monitoring → Create Monitor</kbd> → under **Interfaces**, pick **Interface utilization**.
2. **Device scope**: `wan-.*` (or empty for all). **Threshold**: `80` %. **Must hold for**: `300`. **Severity**: `warning`.
3. Name it `WanUtilization80`, check the preview — busy links show up with their current utilization — and click **Create monitor**.

### Device down

1. Under **Availability**, pick **Device unreachable**.
2. **Device scope**: empty (whole fleet). No threshold — a state template. **Must hold for**: keep `120` so a single missed poll doesn't page. **Severity**: `critical`.
3. Name it `DeviceUnreachable` and create.

### BGP session drop

1. Under **Routing**, pick **BGP peer down**.
2. **Device scope**: `edge-.*` if only your edge routers peer externally. **Must hold for**: `120`. **Severity**: `critical`.
3. Name it `BGPPeerDown-Edge` and create. Alerts fire per peer — two dropped sessions show as two alerts, each naming its device.

## Verify it worked

1. Go to <kbd>Monitoring → Monitor Rules</kbd> — your monitor is listed with Source **custom**, plus its severity, expression, and hold-for.
2. If the preview said it would fire, wait one evaluation (up to 30 seconds) plus your hold-for, then check <kbd>Monitoring → Active Alerts</kbd>.
3. If a notification channel is configured, confirm delivery — one message per newly-fired alert.

## Troubleshooting

- **The monitor never fires, even though the condition is true.** Check the template didn't carry a **no live data** badge — the signal may not be collected yet ([verify monitoring](/onboard-devices/verify-monitoring)) — and confirm your **Device scope** pattern actually matches your device names.
- **It fires and resolves repeatedly.** The value is hovering around the threshold — raise the threshold slightly or increase **Must hold for**.
- **"Expression error" in the preview** (Custom template). The query has a syntax problem; fix it before creating.
- **Name rejected.** Names allow only letters, digits, dashes, and underscores, must start with a letter or digit, and must be unique across all rules.

## The quick path for experts

<kbd>Monitoring → Monitor Rules</kbd> → **Add rule** opens a two-step form (**Define**: name + severity; **Condition**: raw expression + hold-for) with no templates and no live preview — same engine, same result, for when you already know the exact expression. To remove a custom monitor, use **Delete** on its row; its active alerts resolve on the next evaluation.
