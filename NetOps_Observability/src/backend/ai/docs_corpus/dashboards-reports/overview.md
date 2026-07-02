---
title: Dashboards & Reports overview
sidebar_label: Overview
sidebar_position: 1
description: The dashboard surfaces, how the global time range drives them, and where reports fit.
---

# Dashboards & Reports

The **Dashboards** section is the operator's front door: three curated landing views, a directory of built-in boards, and the report builder.

| Surface | Console path | What it's for |
| --- | --- | --- |
| **Home (Command Center)** | <kbd>Dashboards → Home</kbd> | The NOC action queue — correlated incidents, RCA state, owners, tickets |
| **Operations Overview** | <kbd>Dashboards → Operations Overview</kbd> | Fleet-wide health, root cause and impact at a glance |
| **My Dashboard** | <kbd>Dashboards → My Dashboard</kbd> | A dense single-screen operations board over live signals |
| **Dashboard List** | <kbd>Dashboards → Dashboard List</kbd> | The catalog of built-in boards (device, interface, BGP, bandwidth, WAN, and more) |
| **Reports** | <kbd>Dashboards → Reports</kbd> | Build, schedule, preview and deliver reports |

## Home — the Command Center

<kbd>Dashboards → Home</kbd> opens the **Command Center**, the operational control plane. It is *not* a raw alert table: each row is a **correlated incident** (a group of related signals) that already carries an RCA state, severity, impact, fault domain, evidence completeness, owner, age, ticket state, and a recommended **next action**.

Working the queue:

1. Read the KPI tiles across the top — **Correlated incidents**, **Critical**, **Untriaged**, **Suspected RCA**, **Confirmed RCA**, **Owner missing**, **RCA blocked**, **Ticketed**. Click a tile to filter the Action Queue to exactly that set; click it again to clear.
2. Use the filter bar above the table (**RCA**, **Severity**, **Fault domain**, **Evidence**, **Owner**, plus the **Needs action** chip) to narrow further.
3. Click a row to expand it. The expansion shows **Impacted entities** (each is a link to that device's live status), an **Evidence** brief (click through to the full evidence ledger), and the **Recommended next action**.
4. From the expanded row, use **Open RCA**, **View topology**, **Assign owner**, or **Create ticket** to act. The **Problem ID** link (for example `P-5564D1`) opens the same incident in the RCA view.

The page refreshes itself every 30 seconds.

## Operations Overview

<kbd>Dashboards → Operations Overview</kbd> answers "is anything broken, who does it hurt, what changed, what do I do first?" on one screen:

- A **KPI strip** — health score, active (confirmed) incidents, suspected RCA, impacted sites and devices, telemetry coverage — each with a recent trend sparkline. Every tile drills into its detail view.
- A **headline spotlight**: one plain sentence naming the top confirmed or suspected issue and its evidence.
- Panels for **RCA coverage**, **Top health contributors**, **Top active issues**, **Hot paths**, **Recommended action**, **RCA path view**, **Capacity outlook**, **What changed** (last 24 h), **Impact**, **Telemetry coverage**, and **Platform health**.

Panels never fabricate data: a panel with nothing to show reads as a deliberate "No data / inactive" state with a hint about what would populate it. The page auto-refreshes every 20 seconds.

## My Dashboard

<kbd>Dashboards → My Dashboard</kbd> is a fixed, curated single-screen board that walks the network top-down in numbered sections: **Service health → Resource saturation → Traffic & flows → WAN & interfaces → Errors & quality → Control-plane → Path quality → Events & incidents → Topology**.

:::note
My Dashboard is a curated layout, not a build-your-own canvas — you cannot add, remove, or rearrange its panels today. Composable, saved dashboards are planned (see the **Saved dashboards** slot at the bottom of the Dashboard List).
:::

Two interactions on every panel:

- Click the **⤢** button in a panel's corner to enlarge it in a modal.
- Panel titles marked with an arrow icon are drill-throughs — clicking the title opens the full detail view (for example, **Interface utilization — Top 10** opens Interface Performance).

## Dashboard List

<kbd>Dashboards → Dashboard List</kbd> is the directory of every built-in board, grouped as **Network monitoring**, **Traffic & paths**, and **Health & operations**. Each card opens the board it names. See the [built-in dashboards tour](/dashboards-reports/built-in-dashboards) for what each one answers.

## The global time range

The **time-range picker** sits in the top bar, next to the search box, and drives the metric boards (the Dashboard List boards and other range-aware views). The three landing views above are **live** views — they poll on their own fixed cadence and are not window-scoped.

To change the range:

1. Click the range picker in the top bar (it shows the current window, e.g. **Last 1 hour**).
2. Pick a preset: **Last 15 min**, **Last 1 hour**, **Last 6 hours**, **Last 24 hours**, or **Last 7 days** — plus any custom presets you have added.

Two behaviors worth knowing:

- **Remembered per section.** Each navigation section remembers the range it was last viewed with, so switching from Dashboards to Infrastructure and back restores each section's own window. The default is **Last 1 hour**.
- **Custom presets are yours.** They are stored in your browser and shared across sections.

### Add a custom preset

1. Open the time-range picker in the top bar.
2. Choose **＋ Add preset…** (the last entry in the list).
3. In the prompt, enter the window length **in minutes** — e.g. `30` (30 min), `720` (12 hours), `4320` (3 days).
4. The new preset is applied immediately and appears in the list, sorted by duration, labelled automatically ("Last 12 hours", "Last 3 days", …).

## Reports

<kbd>Dashboards → Reports</kbd> builds scheduled or on-demand reports — what to report, when to send it, who receives it, and which formats to produce (HTML always, plus Excel and PDF). See [Reports](/dashboards-reports/reports) for the step-by-step.

## Troubleshooting

- **A metric board is empty but devices are monitored.** Check the time-range picker first — a 15-minute window on a quiet metric can legitimately be empty. Widen the range, then verify collection under [verify monitoring](/onboard-devices/verify-monitoring).
- **Home shows "No correlated incidents require action" during an outage.** The Command Center lists *correlated* groups, not raw alerts. Check <kbd>Monitoring → Active Alerts</kbd> for raw signals that have not yet formed a group.
- **The range picker didn't change a landing page.** Expected — Home, Operations Overview, and My Dashboard are live views with their own refresh cadence; the range drives the metric boards.
- **A custom preset disappeared.** Presets live in the browser you created them in; a different browser or profile won't have them.
