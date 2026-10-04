---
title: Read the Command Center
sidebar_label: Command Center
description: Read the Home page at the start of a shift, what each header chip and KPI tile counts, and how the tiles filter the Action Queue below them.
page_type: task
sidebar_position: 2
---

# Read the Command Center

**Overview → Home** opens the **Command Center**, the first screen of a shift.
It answers four questions in order: what is burning, who owns it, what is
already ticketed, and what is blocked waiting on evidence. Its rows are
correlated incidents, not raw alerts, so the queue is a list of causes to work
rather than messages to read.

## Before you begin

- `infrastructure:read` to view the page. The Command Center is per tenant: it
  counts and lists your own tenant's incidents only.
- `infrastructure:write` to create a ticket from a row. Without it, the ticket
  control opens the RCA case instead.

## Steps

1. Go to **Overview → Home**. The page refreshes every 30 seconds, which the
   **Live · 30s** marker in the header confirms.
2. Read the header chips from left to right.
3. Read the KPI tiles. Select a tile to filter the **Action Queue** below it to
   that set. Select the same tile again to clear the filter.
4. Narrow the queue further with the filter bar: **RCA**, **Severity**,
   **Fault domain**, **Evidence**, **Owner** and **Needs action**.
5. Select a row to expand it, then act from the expanded row.
6. Before you hand over, read the **Ticketing gap** panel at the foot of the
   page.

## What you see

### Header chips

| Chip | What it says |
|---|---|
| **Nominal**, **Watch**, **Elevated** or **Severe** | The NOC pressure. **Severe** is three or more critical incidents, **Elevated** is at least one, **Watch** is at least one suspected RCA, and **Nominal** is none of those. |
| **Critical** | Incidents at critical severity. |
| **Unassigned** | Incidents with no owner. |
| **No ticket** | Confirmed incidents that need a ticket and do not have one. |
| **Blocked** | Incidents whose RCA is waiting on missing evidence. |

### KPI tiles

Every tile counts the whole queue, and selecting it filters the queue to the
rows it counted, so a number and its rows cannot disagree.

| Tile | What it counts |
|---|---|
| **Correlated incidents** | Every open correlated incident in the queue. Selecting it clears all filters. |
| **Critical** | Incidents at critical severity. A confirmed RCA is always critical. |
| **Untriaged** | Correlated incidents whose RCA has not run or not finished: **Correlated**, **RCA running** or **New**. |
| **Suspected RCA** | A likely cause with impact not yet confirmed. Hold the ticket. |
| **Confirmed RCA** | A cause the evidence confirms. Ticket and escalate. |
| **Owner missing** | No owning team is known for the incident. |
| **RCA blocked** | A suspected cause with three or more evidence streams missing. |
| **Ticketed** | Tickets that synced to your ITSM, over the number of tickets needed. Selecting it opens **Administration → Integrations**. |

The queue leaves out lone observations that never grouped into an
incident, and incidents on Correlix's own stack. Those belong to **Platform →
Stack Health**.

### The Action Queue on this page

The queue is the same one **Operations → Action Queue** shows at full height.
It is sorted by severity, then by age. Each row carries **Sev**, **Problem**,
**Incident**, **RCA**, **Impact**, **Domain**, **Evidence**, **Owner**,
**Started**, **Age**, **Ticket** and **Next**.

The **Problem** column is a stable, short handle for the case: the letter `P`,
a hyphen, and the first six hexadecimal characters of the correlation
identifier in upper case. The full identifier stays in the hover title and in
the link. The RCA inspector and Iris use the same handle, so one case reads the
same everywhere.

The **Next** column is the recommended next step:

| Next | When |
|---|---|
| **Assign owner · escalate** | Confirmed, and no owner is known. |
| **Open ticket · escalate** | Confirmed, owner known, no ticket yet. |
| **Track resolution** | Confirmed and ticketed. |
| **Add evidence · unblock RCA** | The RCA is blocked on missing evidence. |
| **Assign owner · open RCA** | Not confirmed, and no owner is known. |
| **Confirm impact · hold ticket** | Suspected. |
| **Review correlation** | Anything else. |

The expanded row shows the impacted entities, each linking to that device's
status, an evidence brief with what is missing, and the next action. Its
buttons are **Open RCA**, **View topology**, **Assign owner** when the owner is
missing, and **Create ticket** when a ticket is needed. A ticket request is
queued: the ticket appears in your ITSM shortly after.

### The Ticketing gap panel

| Tile | What it counts |
|---|---|
| **Ticketed** | Incidents whose ticket synced to your ITSM. |
| **Ticket needed** | Confirmed incidents without a ticket. |
| **Not eligible** | Incidents that do not qualify for a ticket yet: suspected, still correlating, or resolved. |
| **Sync failed** | Tickets your ITSM refused or that failed to sync. Selecting it opens **Administration → Integrations**. |

## Common questions

**The queue says "Nothing correlated yet." Is the network healthy?** The read
worked and no open correlated incident exists. Individual alerts can still be
firing on **Operations → Active Alerts**; they appear here once they group into
an incident.

**Why is an incident marked Unassigned?** Its verdict names no owning team.
The owner shown on other rows is a recommendation taken from the verdict, not
an assignment.

**Why does a suspected incident say "Not eligible" for a ticket?** Correlix
holds the ticket until the impact is confirmed, so a suspected cause does not
open a ticket against the wrong team.

## Related

- [Start a shift](/noc-guide/where-to-start)
- [Work the Action Queue](/incidents/action-queue)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
