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
| [Home, the Command Center](/dashboards-reports/command-center) | **Overview → Home** | The triage queue: correlated incidents with RCA state, owner, ticket state and a recommended next action. |
| [Operations Overview](/dashboards-reports/operations-overview) | **Overview → Operations Overview** | Fleet-wide health, root cause and impact on one screen. |
| [My Dashboard](/dashboards-reports/my-dashboard) | **Overview → My Dashboard** | A fixed, dense operations board over live telemetry. |
| [Built-in dashboards](/dashboards-reports/built-in-dashboards) | **Analytics → Dashboards → Dashboard List** | The directory of built-in boards, plus the dashboards you compose yourself. |
| [Schedule a report](/dashboards-reports/reports) | **Analytics → Reports** | Build, schedule, preview and deliver a report. |

**Analytics → RCA Reports** holds promoted real outages, and **Analytics → Recovery Scorecard** holds the reliability trend. See [Review the RCA Reports library](/dashboards-reports/rca-reports) and [Review the Recovery Scorecard](/dashboards-reports/recovery-scorecard).

## Home, the Command Center

**Overview → Home** is not a raw alert table. Each row is a correlated incident that already carries an RCA state, severity, impact, fault domain, evidence completeness, owner, age, ticket state and a recommended next action. The KPI tiles across the top filter the queue, and the page refreshes every 30 seconds. See [Read the Command Center](/dashboards-reports/command-center).

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
