---
title: Work the Action Queue
sidebar_label: Action Queue
description: Work through the open correlated incidents that need action, most severe and oldest first, and open the RCA case, the topology or the owner assignment from one row.
page_type: task
sidebar_position: 4
---

# Work the Action Queue

**Operations → Action Queue** is the triage queue of open correlated incidents
that need action, as a page of its own. It is the same queue the Command Center
carries under its KPI tiles, with the same rules for what needs action, so the
two never disagree. Use this page when you want the queue alone at full height,
or a link to it you can bookmark or put in a ticket.

## Before you begin

- `infrastructure:read` to view the queue. The queue is per tenant: you see your own
  tenant's incidents only.

## Steps

1. Go to **Operations → Action Queue**. The queue is sorted by severity, then by
   age, and refreshes every 30 seconds.
2. Narrow it with the filters: **RCA**, **Severity**, **Fault domain**,
   **Evidence** and **Owner**. The bar shows how many rows match out of the
   total.
3. Select a row to expand it. The expansion shows:
   - **Impacted entities**, or **Blast radius not mapped yet.**
   - **Evidence**: what is present and what is missing, or **All evidence
     present.**
   - **Next action**: the recommended next step.
4. Act from the expanded row: **Open RCA**, **View topology**, or **Assign
   owner** when the owner is missing.

## What you see

Each row gives **Sev**, **Problem** (the short problem id), **Incident**,
**RCA** state, **Impact**, **Domain**, **Evidence**, **Owner** and **Started**.
Critical rows carry a red accent and major rows an amber one.

The empty states mean different things:

| Message | Meaning |
|---|---|
| **Nothing correlated yet.** | The read worked and there is no open correlated incident. |
| **Queue unknown — the read failed.** | The queue could not be read. It is not an empty queue. |
| **No match for these filters.** | Incidents exist, and the filters hide all of them. Select **Clear filters**. |

For the KPI tiles over the same queue, follow **KPIs in Command Center →** to
**Overview → Home**.

When the guarded wireless remediation workflow is on, proposals waiting for a
person appear under the queue. See
[Review a proposed wireless remediation](/infrastructure/review-a-wireless-remediation).

## Related

- [Dashboards and reports](/dashboards-reports/overview) for the Command Center.
- [Read an RCA case](/investigate/read-an-rca-case)
- [Work the incident queue](/incidents/working-incidents)
