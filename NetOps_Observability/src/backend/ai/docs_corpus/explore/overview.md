---
title: Explore Your Data overview
sidebar_label: Overview
sidebar_position: 1
description: Ad-hoc exploration of metrics, flows, and logs — and how the global search ties them together.
---

# Explore Your Data

The **Data** zone is where you query raw telemetry directly — no pre-built dashboard in the way. Reach for it when you're investigating ("what did that router log at 02:14?"), validating ("is traffic actually flowing through the new circuit?"), or just exploring what your network is telling you.

There are three explore surfaces, one per telemetry plane:

| Surface | Console path | Ask it… |
| --- | --- | --- |
| **[Metrics Explorer](/explore/metrics)** | <kbd>Metrics</kbd> | *"How is this measured value trending?"* — CPU, memory, interface throughput, errors, temperature. Pick a metric or write a query, get a chart. |
| **[Flow analytics](/explore/flows)** | <kbd>Flows</kbd> | *"Who is talking to whom, and how much?"* — top talkers, conversations, ports, protocols, TCP flags, per-exporter volume. |
| **[Log Search](/explore/logs)** | <kbd>Logs → Log Search</kbd> | *"What exactly happened, in the device's own words?"* — full-text search over device syslog, SNMP traps, firewall logs, and flow records, with saved searches. |

## Choosing the right surface

A quick decision guide:

- **You have a number in mind** (utilization, error rate, a threshold) → **Metrics**. It charts time series and lets you compare devices side by side.
- **You have a bandwidth or "who/what" question** (a saturated link, an unexpected top talker, a port scan) → **Flows**. It aggregates flow records into Top-N views you can filter by IP, exporter, and interface.
- **You need the exact event text** (a BGP neighbor message, a firewall deny, a trap) → **Logs**. It's the only surface that returns the raw records themselves, one per row, with the full document behind each.

These surfaces work together. A typical investigation walks all three: a spike in the Metrics chart → the Flows view to see *what traffic* caused it → Log Search to see *what the device said* while it happened. The same global time range follows you between them.

## The global time range

The **time-range picker** in the top bar governs every explore surface (and most of the rest of the console):

1. Click the range picker in the top bar (it reads e.g. **Last 1 hour**).
2. Choose a preset, or select **＋ Add preset…** and enter a duration in minutes (e.g. `30`, `720`, `4320`) to create your own.

The selected range is **remembered per section**, so your Logs window and your Flows window can differ without fighting each other.

## The global search box

The **Search…** box in the top bar is a cross-object search, not just a log query. As you type (two characters or more), a live dropdown resolves your text against:

- **Devices** — matched on name, address, or any inventory field. Selecting one jumps to <kbd>Infrastructure → Devices</kbd>.
- **Active alerts** — matched on summary, rule, severity, or device. Selecting one jumps to the active-alerts view.
- **Saved objects** — saved searches, dashboards, and reports, matched by name or content.
- **Search logs for "…"** — always offered last: a handoff that runs your text as a log query.

Keyboard behavior:

- **Enter** runs your text as a **log search** — it opens <kbd>Logs → Log Search</kbd> pre-filled with the query — unless you have highlighted a specific result.
- **↑** / **↓** move the highlight through the dropdown; **Enter** then opens the highlighted result.
- **Esc** closes the dropdown.

This makes the top bar a fast pivot: paste an IP address you found in a flow, and the dropdown offers both the matching **device** and a **log search** for that IP.

:::tip Command palette
Press <kbd>⌘K</kbd> (or <kbd>Ctrl+K</kbd>) anywhere to open the command palette — the keyboard-first version of the same search. It adds navigation entries (jump to any page) and quick actions (theme, density, the assistant) on top of the live device/alert/saved results. Arrow keys move, **Enter** runs the highlighted row, **Esc** closes.
:::

## Scope and safety

Everything in the Data zone is **tenant-scoped by the platform, not by convention**: every query you run — metrics, flows, logs, global search — is filtered to your own tenant's telemetry before it executes. You cannot see, or be seen by, another tenant's data, and there is nothing to configure to get that behavior.

## Prerequisites

Explore surfaces show what your devices send. If a surface is empty, its feed usually isn't wired up yet:

- **Metrics** appear once devices are onboarded and polling — see [Onboard devices](/onboard-devices/overview).
- **Flows** appear once devices export flow records — see [Send flow data](/send-data/flows).
- **Logs** appear once devices send syslog (and optionally traps) — see [Send syslog](/send-data/syslog) and [Send SNMP traps](/send-data/traps).

Each page in this section ends with a Troubleshooting list for the empty-view case.
