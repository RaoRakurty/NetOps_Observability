---
title: Schedule a report
description: Build a report from the guided wizard, schedule it, pick recipients and formats, preview it, and read the execution history of every run.
page_type: task
sidebar_position: 3
---

# Schedule a report

**Analytics → Reports** builds a report from four decisions: what to report, when to send it, who receives it, and which formats to produce. The server renders every chosen format and delivers them. Each report is tenant-scoped, so it reflects only your own devices and alerts.

## Before you begin

- The report scheduler running. `ENABLE_REPORT_SCHEDULER` is the one flag in this area that defaults **on**; scheduled delivery stops only when it is explicitly set to `false`.
- At least one contact point. A report delivers to contact points, which are reusable recipient groups. Create them under **Administration → Incident Response → Notifications**. Where none exist, the recipients step reads `No contact points yet — create email groups in Administration → Notifications.`
- A decision on report type. Seven are available:

| Type | What it contains |
|---|---|
| Active alerts summary | Alert counts by severity plus the most recent alerts |
| Device inventory | Discovered devices and their addresses |
| Stack health | Platform uptime, device count, active-alert count |
| WAN circuit utilization | Per-link load, status, loss and QoE |
| Security threats | Findings by severity over the last 24 hours plus critical alerts |
| Device utilization | Top devices by CPU and memory |
| Latency, jitter and SLA | Per-link latency, jitter and loss plus availability SLA |

## Steps

### Step 1 - Open the guided setup

1. Go to **Analytics → Reports**.
2. Select **Create a report**. A five-step wizard opens: **Goal**, **Audience**, **Schedule**, **Recipients**, **Preview**.

### Step 2 - Choose the goal and the audience

1. On **Goal**, pick the outcome card. Each maps to a report type: Executive Overview to Stack health, Network Health to Active alerts summary, SLA Summary to Latency, jitter and SLA, Capacity Trends to Device utilization, Security Summary to Security threats, and WAN / Circuits to WAN circuit utilization.
2. On **Audience**, choose **Executives**, **NOC Team**, **Operations** or **Customer**. This sets the report's tone note and severity tag.

### Step 3 - Set the schedule

On **Schedule**, pick the cadence: **Hourly**, **Every 6 hours**, **Every 12 hours**, **Daily**, **Weekly** with a weekday, or **Monthly** with a day of the month. A daily, weekly or monthly schedule also takes a send hour, a minute and a timezone. The timezone defaults to your browser's, and daylight-saving shifts follow the zone you picked.

A plain-language line beside the controls states what you set, so the cadence is confirmed in words before you save it.

### Step 4 - Choose recipients and formats

1. On **Recipients**, select one or more contact points.
2. Tick the output formats. HTML is always produced and is the email body. Excel produces real cells rather than a text blob for the tabular types. PDF is offered as a chip, and whether a PDF artifact is produced depends on PDF rendering being configured in your deployment. Where it is not, the other formats still render and deliver.
3. Choose the delivery mode: email the report, or a secure link.

### Step 5 - Preview and create

On **Preview**, name the report, which is required, review the live rendered preview, and select **Create report**.

The report appears in the Reports table with its schedule, formats, status, **Last sent** and **Next** run time. The scheduler delivers it on that cadence while the report is enabled.

### Step 6 - Edit, pause or delete a scheduled report

1. Select **Edit** on the report's row. The full editor opens with the name, the content type, the schedule, the formats, the severity, an optional note prepended to the report, the recipients and the delivery mode.
2. To pause automatic delivery, untick **Enabled** and save. The schedule column then reads **Paused**. **Send now** still works while paused.
3. Select **Preview** at any point to render the current draft before saving.
4. Select **Save changes**, or use the row's delete action and confirm.

### Step 7 - Send one immediately

1. Select **Send now** on the report's row.
2. Where named notification channels are configured, a picker opens. Tick the channels that should also receive it. Contact-point email always goes to the report's own recipients regardless.
3. The run is queued and the execution-history drawer opens on the fresh run.

## Result

The Reports table shows the report with its cadence in words, its formats, and a **Next** run time. After the first run, **Last sent** carries a timestamp.

Select **History** on the row to read the last 50 runs with fire time, status, duration and per-recipient delivery results. In a run's artifacts column, select a format to download that document. Expand a run for the phase timeline with elapsed times, and a delivery table listing every recipient, its channel, its status and any error.

:::note Execution history needs the database-backed store
On the default file-backed installation, reports still render and deliver on schedule, and the History drawer states that per-run history is unavailable. Per-run records and artifact downloads need the database-backed app-state store.
:::

The routes behind the page:

| Route | What it does |
|---|---|
| `GET /api/reports/runs` | The scheduled reports and their run state. |
| `POST /api/reports/run` | Sends one now. |
| `GET /api/reports/channels` | The named notification channels available to the send-now picker. |
| `GET /api/reports/executions` | The execution history. Append an id for one run. |
| `POST /api/reports/preview` | Renders the current draft. |
| `GET /api/reports/view/` | The token-authenticated secure link. |

## Related

- [Notifications](/incident-response/notifications) for creating the contact points a report delivers to.
- [Built-in dashboards](/dashboards-reports/built-in-dashboards) for reading the same data interactively.
- [Feature flags](/reference/feature-flags) for `ENABLE_REPORT_SCHEDULER`.
