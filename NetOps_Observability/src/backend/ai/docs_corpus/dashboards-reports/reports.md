---
title: Reports
sidebar_label: Reports
sidebar_position: 3
description: Build, schedule, preview and deliver reports — step by step.
---

# Reports

<kbd>Dashboards → Reports</kbd> builds reports from four decisions: **what** to report, **when** to send it, **who** receives it, and **which formats** to produce. The server renders every chosen format in parallel and delivers them to your recipients; each report is also tenant-scoped, so it reflects only your own devices and alerts.

## Report types

| Type | What it contains |
| --- | --- |
| **Active alerts summary** | Alert counts by severity plus the most recent alerts |
| **Device inventory** | Discovered devices and their addresses |
| **Stack health** | Platform uptime, device count, active-alert count |
| **WAN circuit utilization** | Per-WAN/overlay link load, status, loss and QoE |
| **Security threats** | Findings by severity (last 24 h) plus critical alerts |
| **Device utilization** | Top devices by CPU and memory |
| **Latency, jitter & SLA** | Per-link latency, jitter and loss plus availability SLA |

## Output formats

- **HTML** — always produced; it is the email body.
- **Excel** — real tables (cells, not a text blob), for the tabular report types.
- **PDF** — offered as a format chip; whether a PDF artifact is actually produced depends on your deployment's PDF rendering being configured. If it isn't, the other formats still render and deliver.

## Before you start: recipients

Reports deliver to **contact points** — reusable recipient groups (for example, email groups). If the recipients step says "No contact points yet", create them first under <kbd>Administration → Notifications</kbd> (see [Notifications](/incident-response/notifications)). Named notification channels (Slack, PagerDuty, …) can additionally receive a report when you use **Send now**.

## Create a report (guided setup)

1. Go to <kbd>Dashboards → Reports</kbd>.
2. Click **Create a report** ("Guided setup — pick an outcome, schedule and recipients."). A five-step wizard opens: **Goal → Audience → Schedule → Recipients → Preview**.
3. **Goal** — pick the outcome card. Each card maps to a report type:
   - **Executive Overview** → Stack health
   - **Network Health** → Active alerts summary
   - **SLA Summary** → Latency, jitter & SLA
   - **Capacity Trends** → Device utilization
   - **Security Summary** → Security threats
   - **WAN / Circuits** → WAN circuit utilization
4. **Audience** — choose who it's for (**Executives**, **NOC Team**, **Operations**, **Customer**). This sets the report's tone note and severity tag.
5. **Schedule** — pick the cadence: **Hourly**, **Every 6 hours**, **Every 12 hours**, **Daily**, **Weekly** (choose the weekday), or **Monthly** (choose the day of month). Daily/weekly/monthly schedules also take a send time (hour and minute) and a **timezone**. A plain-language preview ("Every Monday at 7:00 AM (UTC)") confirms what you set.
6. **Recipients** — select one or more contact points, tick the output **formats** (HTML is always on), and choose **Delivery**: *Email the report* or *Secure link*.
7. **Preview** — name the report (required) and review the live rendered preview, then click **Create report**.

The report appears in the **Reports** table with its schedule, formats, status, **Last sent** and **Next** run time. The scheduler delivers it automatically on the cadence while the report is enabled.

## Edit, pause, or delete a report

1. In the **Reports** table, click **Edit** on the report's row. The full editor opens with every setting: name, **Content** (report type), schedule, output formats, severity, an optional **Note** (prepended to the top of the report), recipients, and delivery mode.
2. To pause automatic delivery, untick **Enabled** and save — the row's schedule column shows **Paused** until you re-enable it. **Send now** still works while paused.
3. Click **Preview** at any time to render the current draft as HTML in a modal before saving.
4. Click **Save changes** — or the **✕** action on the row to delete the report (with confirmation).

## Send a report immediately

1. On the report's row, click **Send now**.
2. If named notification channels are configured, a picker opens: tick the channels that should also receive it (contact-point email always goes to the report's own recipients regardless), then click **Send**.
3. The run is queued and the **Execution history** drawer opens on the fresh run so you can watch it progress.

## Download a generated report

Every run stores its rendered documents (artifacts), which you can download later:

1. On the report's row, click **History**. The **Execution history** drawer lists up to the last 50 runs with fire time, status, duration, and per-recipient delivery results ("2/2 ok").
2. In a run's **Artifacts** column, click the format button (**html**, **xlsx**, **pdf**) to download that document.
3. Click a run's row to expand it: the **Phase timeline** shows each stage of the run with elapsed times, and the **Delivery** table shows every recipient, its channel, ok/fail status, and any error message.

:::note
Execution history and artifact downloads require the database-backed app-state store. On the default file-backed installation, reports still render and deliver on schedule, but the History drawer reports that per-run history is unavailable.
:::

## Troubleshooting

- **"No contact points yet" in the recipients step.** Create email contact points under <kbd>Administration → Notifications</kbd> first; then reopen the wizard or editor.
- **History says execution history is unavailable.** Your deployment uses the file-backed store — delivery still works, but per-run records and artifact downloads need the database-backed store.
- **"No runs yet" in History.** The report has never fired — click **Send now**, or wait for the next scheduled run (shown in the **Next** column).
- **A recipient shows "fail" in the Delivery table.** Expand the run and read the error next to that recipient — a failed email address or channel does not block the other recipients.
- **No PDF button on a run's artifacts.** PDF rendering is not configured in this deployment; HTML (and Excel, if selected) are still produced.
- **Reports arrive at the wrong hour.** Check the schedule's **timezone** — the wizard defaults to your browser's timezone, and daylight-saving shifts follow the zone you picked.
