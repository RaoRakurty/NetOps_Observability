---
title: Dashboards and reports
description: The landing views, the built-in board directory, dashboards you compose yourself, the global time range, and where reports fit.
page_type: index
sidebar_position: 1
---

# Dashboards and reports

Boards and reports live under **Analytics**, alongside the operational landing views under **Overview**. The landing views poll on their own cadence. The metric boards are driven by the global time range.

| Surface | Console path | What it is for |
|---|---|---|
| Home, the Command Center | **Overview → Home** | The triage queue: correlated incidents with RCA state, owner, ticket state and a recommended next action. |
| Operations Overview | **Overview → Operations Overview** | Fleet-wide health, root cause and impact on one screen. |
| My Dashboard | **Overview → My Dashboard** | A fixed, dense operations board over live telemetry. |
| [Built-in dashboards](/dashboards-reports/built-in-dashboards) | **Analytics → Dashboards → Dashboard List** | The directory of built-in boards, plus the dashboards you compose yourself. |
| [Schedule a report](/dashboards-reports/reports) | **Analytics → Reports** | Build, schedule, preview and deliver a report. |

**Analytics → RCA Reports** holds promoted real outages, and **Analytics → Recovery Scorecard** holds the reliability trend.

## Home, the Command Center

**Overview → Home** is not a raw alert table. Each row is a correlated incident that already carries an RCA state, severity, impact, fault domain, evidence completeness, owner, age, ticket state and a recommended next action.

1. Read the KPI tiles across the top. Select a tile to filter the Action Queue to that set, and select it again to clear.
2. Narrow further with the filter bar above the table.
3. Select a row to expand it. The expansion shows the impacted entities, each linking to that device's live status, an evidence brief, and the recommended next action.
4. Act from the expanded row: open the RCA case, view the topology, assign an owner, or create a ticket.

The **Problem ID** column is a stable, short handle for the case: the letter `P`, a hyphen, and the first six hexadecimal characters of the correlation identifier in upper case. The full identifier stays in the hover title and in the link, which is what the API keys on. The same handle is used in the RCA inspector and by Iris, so one case reads the same everywhere.

The page refreshes every 30 seconds.

## Operations Overview

**Overview → Operations Overview** answers what is broken, who it hurts, what changed and what to do first. A KPI strip with trend sparklines heads it, and a headline spotlight names the top confirmed or suspected issue in one sentence. Panels below cover RCA coverage, top health contributors, top active issues, hot paths and the recommended action, then the RCA path view, capacity outlook, what changed, impact, telemetry coverage and platform health.

A panel with nothing to show reads as a deliberate no-data state with a hint about what would populate it. It never renders a reassuring blank.

## My Dashboard

**Overview → My Dashboard** is a fixed, curated board that walks the network top down in nine numbered sections: Service health, Resource saturation, Traffic and flows, WAN and interfaces, Errors and quality, Control-plane, Path quality, Events and incidents, and Topology.

Its liveness header is derived from real fetches rather than from a wall clock. Panels report every poll outcome, and the header states what they said: **Live** with the time of the last successful data, **Connecting** before anything has loaded, or **Disconnected** with a count of failing feeds. A total backend outage therefore cannot read as a live board.

Two interactions on every panel: enlarge it in a modal, or select a drill-through title to open the full detail view.

My Dashboard is curated and not editable. To arrange your own board, use the composer described in [Built-in dashboards](/dashboards-reports/built-in-dashboards).

## The global time range {#the-global-time-range}

The time-range picker sits in the top bar and drives the metric boards. The three landing views above are live views on their own fixed cadence and are not window-scoped.

1. Select the picker in the top bar. It shows the current window.
2. Choose a preset, or choose the add-preset entry and enter a window length in minutes, for example `30`, `720` or `4320`.

Two behaviours to expect. The range is remembered per navigation section, so switching sections and back restores each section's own window. Custom presets are stored in the browser you created them in, so a different browser or profile will not have them.

## Related

- [Built-in dashboards](/dashboards-reports/built-in-dashboards) for what each board answers.
- [Schedule a report](/dashboards-reports/reports) for scheduled and on-demand delivery.
- [Read an RCA case](/investigate/read-an-rca-case) for the case a Problem ID opens.
