---
title: Explore your data
description: The four raw telemetry planes - metrics, logs, flows and events - how to choose between them, and the global search box and time range that tie them together.
page_type: index
sidebar_position: 1
---

# Explore your data

**Explore** is where you query raw telemetry with no dashboard in the way. Reach for it when you are investigating what a device logged at a given minute, validating that traffic moved through a new circuit, or reading the event timeline around a change. Every query is filtered to your tenant on the server before it executes.

| Page | Console path | Ask it |
|---|---|---|
| [Query metrics](/explore/metrics) | **Explore → Metrics** | How is this measured value trending? Pick a metric from the catalog or write a query, and get a chart. |
| [Search logs](/explore/logs) | **Explore → Logs** | What exactly happened, in the device's own words? Full-text search over syslog, traps, firewall logs and sampled flow records. |
| [Analyse flows](/explore/flows) | **Explore → Flows** | Who is talking to whom, and how much? Top talkers, conversations, ports, protocols and TCP flags. |
| [Review the event feed](/explore/events) | **Explore → Events** | What happened, and what changed? Syslog, SNMP traps and active alerts on one timeline. |

**Explore → Saved Searches** holds the searches you named and kept.

## Choosing a plane

- A number in mind, such as utilization, an error rate or a threshold: use **Metrics**. It charts time series and compares devices side by side.
- A bandwidth or who-and-what question, such as a saturated link or an unexpected top talker: use **Flows**. It aggregates flow records into Top-N views you can filter by address, exporter and interface.
- The exact event text, such as a BGP neighbor message or a firewall deny: use **Logs**. It is the only plane that returns the raw records themselves, one per row, with the whole document behind each.
- A timeline to correlate against: use **Events**. It merges device log events, SNMP traps and active alerts in time order.

A typical investigation walks all four: a spike on a metric chart, then flows to see which traffic caused it, then logs for what the device said, then events for what else fired at the same moment.

## The global time range

The time-range picker sits in the top bar and governs the explore surfaces:

1. Select the picker in the top bar. It shows the current window.
2. Choose a preset, or choose the add-preset entry and enter a window length in minutes, for example `30`, `720` or `4320`.

The chosen range is remembered per navigation section, so a Logs window and a Flows window can differ without fighting each other. Custom presets are stored in the browser you created them in.

## The global search box {#the-global-search-box}

The **Search…** box in the top bar is a cross-object search rather than a log query. From two characters, a live dropdown resolves your text against Devices, Resources, Services, Accounts, Cases, Alerts and Saved objects, and always closes the list with a log-search handoff labelled `Search logs for "…"`.

Keyboard behaviour:

- **Enter** runs your text as a log search and opens **Explore → Logs** pre-filled, unless you have highlighted a specific result.
- The up and down arrows move the highlight, and **Enter** then opens the highlighted result.
- **Esc** closes the dropdown.

Each side of the search degrades independently. A failed sub-query leaves its own group empty rather than failing the whole box, so a short result list is not proof that nothing matched.

:::tip Command palette
Press `Cmd+K` or `Ctrl+K` anywhere for the keyboard-first version of the same search. It adds navigation entries and quick actions on top of the live device, alert and saved results.
:::

## Time is rendered per tenant

Timestamps render in the mode a tenant administrator chose under **Administration → Settings**: your local zone or UTC. Storage is always UTC and only the rendering changes. Chart axes follow the same setting. See [System settings](/administration/system-settings).

## Prerequisites

An explore surface shows what your devices send. Where one is empty, its feed is usually not wired yet:

- Metrics appear once devices are onboarded and polling. See [Onboard devices](/onboard-devices/overview).
- Flows appear once devices export flow records. See [Send flow data](/send-data/flows).
- Logs and events appear once devices send syslog and traps. See [Send syslog](/send-data/syslog) and [Send SNMP traps](/send-data/traps).
