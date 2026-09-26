---
title: Review detected findings
sidebar_label: Findings
description: Read the deviations the correlation engine detected, newest first, filter them by severity, and open one with its device, component and logs.
page_type: task
sidebar_position: 3
---

# Review detected findings

**Investigate → Findings** is titled **Detected Findings**. It lists the
observations that deviate from baseline and may contribute to an incident or an
RCA candidate, newest first. A finding is a deviation, not a verdict. It
becomes evidence when correlation attaches it to an RCA case. See
[Anomalies and correlation](/incidents/anomalies-and-correlations).

## Before you begin

- A signed-in account. The list is scoped to the devices you can view, so you
  see findings on your own tenant's devices only.

## Steps

1. Go to **Investigate → Findings**.
2. Read the counts: **Findings**, **Critical**, **Warning** and
   **Informational**.
3. To narrow the list, choose a severity: **All severities**, **Info**,
   **Warning** or **Critical**.
4. Select a row to open the finding. The detail shows its severity, kind,
   score, summary and description, with the time, device, component and id.
5. When the finding names a device, the detail panel offers **View logs**,
   which opens that device's syslog for the last hour in the bottom drawer.

The list refreshes every 10 seconds.

## What you see

One row per finding with **Time**, **Severity**, **Kind**, **Device**,
**Component**, **Summary** and **Score**. Sort by any sortable column.

**No findings in this window.** means the read worked and the engine wrote no
finding. **Findings could not be loaded.** means the read failed. That is not
"no findings": the queue is unknown, and any rows still shown are from the last
successful read.

## Related

- [Anomalies and correlation](/incidents/anomalies-and-correlations)
- [How root-cause analysis works](/investigate/rca-explained)
- [Investigate a symptom](/investigate/investigate-a-symptom)
