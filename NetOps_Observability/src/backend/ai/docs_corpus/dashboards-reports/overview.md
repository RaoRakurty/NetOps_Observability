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
| [Operations Overview](/dashboards-reports/operations-overview) | **Overview → Operations Overview** | Fleet-wide health, root cause and impact on one screen. |
| [My Dashboard](/dashboards-reports/my-dashboard) | **Overview → My Dashboard** | A fixed, dense operations board over live telemetry. |
| [Built-in dashboards](/dashboards-reports/built-in-dashboards) | **Analytics → Dashboards → Dashboard List** | The directory of built-in boards, plus the dashboards you compose yourself. |
| [Schedule a report](/dashboards-reports/reports) | **Analytics → Reports** | Build, schedule, preview and deliver a report. |

**Analytics → RCA Reports** holds promoted real outages, and **Analytics → Recovery Scorecard** holds the reliability trend. See [Review the Recovery Scorecard](/dashboards-reports/recovery-scorecard).

## Home, the Command Center

**Overview → Home** is not a raw alert table. Each row is a correlated incident that already carries an RCA state, severity, impact, fault domain, evidence completeness, owner, age, ticket state and a recommended next action.

1. Read the KPI tiles across the top. Select a tile to filter the Action Queue to that set, and select it again to clear.
2. Narrow further with the filter bar above the table.
3. Select a row to expand it. The expansion shows the impacted entities, each linking to that device's live status, an evidence brief, and the recommended next action.
4. Act from the expanded row: open the RCA case, view the topology, assign an owner, or create a ticket.

The **Problem ID** column is a stable, short handle for the case: the letter `P`, a hyphen, and the first six hexadecimal characters of the correlation identifier in upper case. The full identifier stays in the hover title and in the link, which is what the API keys on. The same handle is used in the RCA inspector and by Iris, so one case reads the same everywhere.

The page refreshes every 30 seconds.

## Operations Overview

**Overview → Operations Overview** answers what is broken, who it hurts, what
changed and what to do first, on one screen. See
[Read the Operations Overview](/dashboards-reports/operations-overview).

## My Dashboard

**Overview → My Dashboard** is a fixed, curated board that walks the network
top down in nine numbered sections, with a header that says whether the board
is live. It is not editable. See [Read My Dashboard](/dashboards-reports/my-dashboard).

## The global time range {#the-global-time-range}

The time-range picker sits in the top bar and drives the metric boards. The three landing views above are live views on their own fixed cadence and are not window-scoped.

1. Select the picker in the top bar. It shows the current window.
2. Choose a preset, or choose the add-preset entry and enter a window length in minutes, for example `30`, `720` or `4320`.

Two behaviours to expect. The range is remembered per navigation section, so switching sections and back restores each section's own window. Custom presets are stored in the browser you created them in, so a different browser or profile will not have them.

## Related

- [Built-in dashboards](/dashboards-reports/built-in-dashboards) for what each board answers.
- [Schedule a report](/dashboards-reports/reports) for scheduled and on-demand delivery.
- [Read an RCA case](/investigate/read-an-rca-case) for the case a Problem ID opens.
