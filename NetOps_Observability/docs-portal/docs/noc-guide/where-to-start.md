---
title: Where to start
sidebar_label: Where to start
sidebar_position: 2
description: The operator's on-shift entry points — start at the Command Center, work the Action Queue, and know when to drop to Active Alerts, Events, or Log Search instead.
---

# Where to start

You've just sat down for a shift, or something is reportedly wrong. This page is the routine: one primary entry point, a short ranked queue, and a plain decision path for the cases where the queue doesn't have the answer yet.

## Step 1 — Open the Command Center

1. Go to <kbd>Dashboards → Home</kbd>. This is the **Command Center**, and its header answers the first question of any shift: *"What's burning, who owns it, and what still needs human action."*
2. Read the chip row at the top: **NOC pressure** (Nominal / Watch / Elevated / Severe), the **critical** count, the **owner gap**, the **ticket gap**, and **RCA blocked**. The page is live and refreshes every 30 seconds.
3. Scan the KPI tiles: **Correlated incidents**, **Critical**, **Untriaged**, **Suspected RCA**, **Confirmed RCA**, **Owner missing**, **RCA blocked**, **Ticketed**. Each tile is a button — clicking it filters the queue below to exactly the rows it counts.
4. Read the one-line **decision summary** under the tiles. It states, in words, what to work first (for example: "Work confirmed-RCA criticals with missing owners first.").

You should now see the **Action Queue**: one row per *correlated incident* — grouped problems, not raw alerts — sorted by severity, then age.

## Step 2 — Work the Action Queue

1. Take the top row. Read it left to right: severity dot, **Problem ID** (a stable handle like `P-5564D1`), the incident title, **RCA state**, **Impact** (devices and sites), **Fault domain** (LAN, SD-WAN, Data Center, ISP / Carrier, Cloud Provider, Application, Security), **Evidence** (Complete / Partial / Single-stream), **Owner**, **Age**, **Ticket**, and the recommended **Next action**.
2. Click the row to expand it. You should now see three panes: **Impacted entities** (each device links to its live status), **Evidence** (what correlated, with a link to the full evidence ledger), and **Recommended next action**.
3. Act on the buttons: **Open RCA** for the full case, **View topology** to see it on the map, **Assign owner** if the owner is missing, **Create ticket** if one is needed.
4. Use the filter bar (RCA / Severity / Fault domain / Evidence / Owner) or the **Needs action** chip to narrow a long queue to rows missing an owner, missing a ticket, or blocked on evidence.

Priority order, when the decision line doesn't already say it:

1. **Confirmed** RCA + critical severity + **Owner: Missing** — assign and open the RCA.
2. **Confirmed** + **Ticket needed** — file the ticket (or let the policy do it; check the **Ticketing gap** panel at the bottom).
3. **Suspected** — open the RCA and read what evidence is missing. **Hold on ticketing**: suspected means customer impact is *not confirmed*, and the expand pane says so explicitly.
4. **Blocked / Correlated / RCA running** — still gathering; check back, or investigate manually if users are already complaining (see Step 4).

:::note
The Command Center intentionally hides what hasn't correlated. An empty Action Queue means *no grouped incidents need action* — it does not mean the network is silent. That's what the next steps are for.
:::

## Step 3 — When to drop to the other queues

Sometimes you don't want the correlated view. Use these entry points instead when:

- **A specific threshold just tripped and you want the live state** → <kbd>Monitoring → Active Alerts</kbd>. Every monitor rule currently firing, refreshed continuously — "triage before they correlate into incidents." Watch the **Aging > 1h** tile: an alert firing for over an hour without an incident deserves a look. Row click gives context and a **View logs** pivot. See [Work with active alerts](/monitoring/manage-alerts).
- **You want the raw, unjudged timeline** → <kbd>Monitoring → Events</kbd>. Syslog, traps, and alerts merged on one time axis. Best when you know roughly *when* something happened and want to see everything around that moment.
- **You suspect something the platform hasn't flagged** → <kbd>Logs → Log Search</kbd>. Full query access to everything collected. This is your free-form investigation surface; the whole technique is covered in [Reading logs](/noc-guide/reading-logs).
- **You want to see abnormality before it groups** → <kbd>Monitoring → Anomalies</kbd>. Individual baseline deviations, newest first, each with severity and score.

## Step 4 — Triage decision path

Follow this numbered path top to bottom; stop at the first step that matches.

1. **The Action Queue has rows.** Work them per Step 2. Done.
2. **The queue is empty but Active Alerts is firing.** Open <kbd>Monitoring → Active Alerts</kbd>, sort by **Fired**, click the newest row, and use **View logs** to see the device's own syslog for the last hour. The alert hasn't correlated (yet) — you're seeing it pre-grouping.
3. **The queue is empty but users report an issue** → start in Log Search:
   1. Open <kbd>Logs → Log Search</kbd>.
   2. Set the signal dropdown to **Syslog (devices)** and the range to **Last 1h**.
   3. Search for the affected device: `host:"edge-router-01"` (use your device's name), or for the affected service's addresses: `src_addr:10.20.30.5`.
   4. Look for errors and state changes around the reported time — bursts, link flaps, protocol adjacency messages ([Reading logs](/noc-guide/reading-logs) shows the patterns).
   5. Found a suspect device? Check <kbd>Monitoring → Anomalies</kbd> filtered to it, then <kbd>Infrastructure → Topology Canvas</kbd> to see its neighborhood.
4. **Nothing anywhere, but the report persists.** Verify the device is actually being monitored ([verify monitoring](/onboard-devices/verify-monitoring)) — silence from a device that should be talking is itself a finding. Also check <kbd>Monitoring → Events</kbd> with a wider time range; the issue may predate your window.
5. **You inherited an in-flight incident from the previous shift.** Go to <kbd>Monitoring → Incidents</kbd>, filter status to `investigating`, click the row, and read the **Timeline** — every acknowledgement, note, status change, and ticket sync is there in order.

## Step 5 — Close the loop before you move on

For anything you touched:

1. Track its lifecycle in <kbd>Monitoring → Incidents</kbd> — **Acknowledge** what you've seen, **Investigate** what you're working, add a note so the next operator inherits your context.
2. Check the **Ticketing gap** panel back on the Command Center: **Ticket needed** should trend to zero for confirmed incidents, and **Sync failed** should be empty (if it isn't, the ITSM push errored — see [Integrations](/incident-response/integrations)).

:::tip
Make the Command Center your muscle memory, not your prison. The queue ranks what Correlix could *prove*; the drop-down paths (alerts, events, logs) exist precisely for the minutes before proof arrives.
:::

Next: learn to read the raw material itself in [Reading logs](/noc-guide/reading-logs), or follow one incident end to end in [From signal to ticket](/noc-guide/from-signal-to-ticket).
