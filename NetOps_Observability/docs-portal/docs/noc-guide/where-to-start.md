---
title: Start a shift
sidebar_label: Start a shift
description: Read the Command Center, work the Action Queue in priority order, and follow the decision path for when the queue is empty and a user still reports a problem.
page_type: task
sidebar_position: 2
---

# Start a shift

This is the routine for the first ten minutes of a shift, and for the moment
someone reports that something is wrong. It gives you one entry point, a ranked
queue, and a decision path for the cases the queue does not yet cover.

## Before you begin

- **An account with access to the operations surfaces.** The Action Queue,
  Active Alerts and Incidents are all tenant-scoped to your account.
- **Devices already reporting.** If the inventory is empty, start with
  [Onboard your first device](/getting-started/quickstart).
- **The handover from the previous shift**, if there is one. In-flight incidents
  live on **Operations → Incidents** with their timelines.

## Steps

### Step 1 — Read the Command Center header

1. Go to **Overview → Home**. The page is titled **Command Center** and refreshes
   every 30 seconds.
2. Read the chip row: **NOC pressure** (Nominal, Watch, Elevated or Severe), the
   critical count, the owner gap, the ticket gap and the RCA blocked count.
3. Read the KPI tiles: **Correlated incidents**, **Critical**, **Untriaged**,
   **Suspected RCA**, **Confirmed RCA**, **Owner missing**, **RCA blocked** and
   **Ticketed**. Each tile is a button that filters the queue below to exactly
   the rows it counts.
4. Read the decision line under the tiles. It states in words what to work
   first, for example *Work confirmed-RCA criticals with missing owners first*.

The pressure chip is derived from counts, not from a judgement: three or more
criticals reads Severe, one or two reads Elevated, any suspected case with no
critical reads Watch, and nothing outstanding reads Nominal.

### Step 2 — Work the Action Queue

The queue holds correlated incidents, not raw alerts, sorted by severity and
then by age.

1. Take the top row and read it across: **Sev**, **Problem ID** (a stable handle
   such as `P-5564D1`), **Incident / correlation group**, **RCA state**,
   **Impact**, **Fault domain**, **Evidence**, **Owner**, **Started**, **Age**,
   **Ticket** and **Next action**.
2. Select the row to expand it. Three panes open: **Impacted entities**, where
   each device links to its live status; **Evidence**, which states how many
   observations correlated across how many nodes and links to the full ledger; and
   **Recommended next action**.
3. Act from the buttons on the expanded row: **Open RCA**, **View topology**,
   **Assign owner** when the owner is missing, and **Open ticket** when one is
   needed.
4. Narrow a long queue with the filter bar (RCA, Severity, Fault domain,
   Evidence, Owner) or the **Needs action** chip, which selects rows with a
   missing owner, an unticketed confirmed incident, or an RCA blocked on
   evidence.

Work in this order when the decision line does not already say otherwise:

1. **RCA state Confirmed, severity critical, Owner Missing.** Assign the owner
   and open the RCA.
2. **Confirmed with Ticket needed.** Open the ticket, or check the **Ticketing
   gap** panel to confirm the policy has done it.
3. **Suspected.** Open the RCA and read what evidence is absent. Hold on
   ticketing: the expanded row states that customer impact is not confirmed and
   that independent evidence is needed first.
4. **Blocked, Correlated or RCA running.** Still gathering. Come back to it, or
   investigate by hand if users are already reporting an effect.

Four columns carry closed vocabularies, and knowing them makes the queue
scannable.

| Column | Values |
|---|---|
| RCA state | New, Correlated, RCA running, Suspected, Confirmed, Blocked, Resolved |
| Evidence | Single-stream, Partial, Complete |
| Fault domain | LAN, SD-WAN, Data Center, ISP / Carrier, Cloud Provider, Application, Security, Unknown |
| Owner | Missing, Recommended, Assigned, Escalated |

Evidence is the fastest read on how much a verdict is worth.
**Single-stream** means one source only, **Partial** means corroborated with the
gaps named, and **Complete** means every expected class is present. Fault domain
decides who the work goes to: **ISP / Carrier** and **Cloud Provider** are
escalations outward, while **LAN** and **Data Center** are worked internally.
**Unknown** means the seam has not been narrowed, and it is a prompt to open the
case rather than to assign it.

### Step 3 — Read the queue's silence correctly

An empty Action Queue means no correlated incident needs action. It does not
mean the network is quiet, and the page says so: *The queue groups raw alerts
into incidents, none have correlated.* The surfaces below hold what has not
grouped yet.

| Question | Where |
|---|---|
| Which monitor rules are firing right now? | **Operations → Active Alerts** |
| What did the network say, in order, unjudged? | **Explore → Events** |
| What deviated from its own baseline? | **Investigate → Findings** |
| What exactly did one device log? | **Explore → Logs** |

Each of these answers a narrower question than the queue, and none of them
carries a verdict. **Explore → Events** in particular merges syslog, SNMP traps
and firing alerts onto one timeline with Time, Type, Severity, Source and Event
columns, and judges nothing. Use it when you know roughly when something
happened and want everything around that moment in order.

### Step 4 — Follow the decision path

Stop at the first case that matches.

1. **The Action Queue has rows.** Work them as in Step 2.
2. **The queue is empty and alerts are firing.** Open **Operations → Active
   Alerts**. Repeated firings collapse into episodes, so a condition that has
   fired forty times is one row to triage once. Read the **Active episodes**,
   **Critical**, **Flapping** and **Notifications paused** counts. A **Flapping**
   chip on a row means the condition is changing state rapidly, which is usually
   worse than a clean failure, because everything downstream keeps
   reconverging. **Notifications paused** counts episodes someone muted or
   snoozed, so read it before concluding that nobody has been told. Open the
   newest episode, and use its **View logs** pivot to see what the device itself
   said. Acknowledge, assign, mute, snooze and note are all available on the
   episode. If the noise comes from planned work, the right fix is a window on
   **Operations → Maintenance Windows** rather than a mute.
3. **The queue is empty and a user reports a problem.** Go to **Explore →
   Logs**, set the signal selector to **Syslog (devices)** and the range to
   **Last 1h**, and search for the device by name. The technique is in
   [Read device logs during an incident](/noc-guide/reading-logs).
4. **Nothing anywhere, and the report persists.** Confirm the device is actually
   being read before concluding it is healthy. Silence from a device that
   normally reports is a finding, not an all-clear. See
   [Verify monitoring](/onboard-devices/verify-monitoring).
5. **You inherited an in-flight incident.** Go to **Operations → Incidents**,
   filter the status to investigating, open the row, and read the timeline.
   Every acknowledgement, note, status change and ticket sync is recorded there
   in order.

### Step 5 — Close the loop before you hand over

1. On **Operations → Incidents**, acknowledge what you have seen, mark what you
   are working as investigating, and add a note so the next operator inherits
   your context.
2. Back on the Command Center, read the **Ticketing gap** panel. **Ticket
   needed** should trend towards zero for confirmed incidents, and **Sync
   failed** should be empty. A non-empty **Sync failed** means the ITSM push
   errored; see [Integrations](/incident-response/integrations).

## Result

You have worked every row the queue ranked, know why the rows you left are still
open, and have left a written trail on each incident you touched. Anything the
platform could not prove is either being investigated by hand or recorded as an
open question, not silently closed.

## Related

- [Read device logs during an incident](/noc-guide/reading-logs)
- [From observation to ticket](/noc-guide/from-signal-to-ticket)
- [Work with active alerts](/monitoring/manage-alerts)
- [Work incidents](/incidents/working-incidents)
- [Read an RCA case](/investigate/read-an-rca-case)
