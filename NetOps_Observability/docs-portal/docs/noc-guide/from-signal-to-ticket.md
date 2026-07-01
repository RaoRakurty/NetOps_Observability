---
title: "From signal to ticket: one incident, end to end"
sidebar_label: From signal to ticket
sidebar_position: 4
description: Follow a single incident through the console — anomaly, correlation, every element of the RCA view, topology verification, and the auto-filed ticket.
---

# From signal to ticket: one incident, end to end

This walkthrough follows **one incident** through every chapter of its story. At each step: the tab, what you look at, and what question it answers. Do it once with a real incident and the console's layout will never feel arbitrary again.

## Step 1 — The anomaly fires

**Tab:** <kbd>Monitoring → Anomalies</kbd> · **Question:** *is something abnormal?*

1. Open the **Detected Findings** queue. New findings appear at the top as the engine detects deviations from each device's statistical baseline.
2. Find your incident's first clue: a row with a Severity (say, `critical`), a Kind, a Device, a plain-language Summary, and a Score.
3. Click the row. You should now see the finding's context — time, device, component — and a **View logs** button. Click it if you want the raw narration ([how to read it](/noc-guide/reading-logs)).

A finding is one clue, not a verdict. Leave it and move downstream.

## Step 2 — The evidence groups

**Tab:** <kbd>Monitoring → Correlations</kbd> · **Question:** *do the clues belong together, and what do they suggest?*

1. Open the **RCA Candidates** queue. Each row is a correlation group — anomalies and events bound by time and network relationship.
2. Find the candidate containing your finding (match device and time window). Read its row: **Status** (Confirmed / Suspected / Not confirmed), **Quality**, **Likely cause** (a named failure pattern, or "Not yet determined"), **Owner**, **Linked by** (Boundary / Boundary + path / Same path), **Evidence types**, and **Signals** — how many raw signals correlated in.
3. Note the honest bar stated right in the header: *a root cause is confirmed only when independent evidence agrees across at least two signal classes — weaker candidates say exactly what's missing.*
4. Click the row to open the RCA workspace.

## Step 3 — Walk the RCA view

**Tab:** the **Root cause analysis** workspace (opened from the row) · **Question:** *what happened, how sure are we, and what do we do?*

Read it top to bottom — the order is the argument:

1. **Title, status pills, and confidence.** The case title states the diagnosed problem. Pills show the verdict (**CONFIRMED** or suspected/not confirmed) and **Confidence** (e.g. "Confidence: High"). Below, the **Decision** callout gives the one-sentence operational call, and the line under it records **Observed at** and the **RCA ID**. The side panel names the **root cause object** (the device/link at fault) and the **Likely owner** — the team the evidence points at. *Answers: what and how sure.*
2. **Executive RCA summary.** A paragraph you could paste into a bridge call, followed by labelled "why" lines and — importantly — **Ruled out**: competing causes the evidence does not support. *Answers: why this cause and not another.*
3. **Impact & blast radius.** Key/value scope: what's affected and how widely. (The queue-level **Fault domain** classification — LAN, SD-WAN, ISP / Carrier, and so on — lives on the [Command Center](/noc-guide/where-to-start) row for this incident.) *Answers: who feels it.*
4. **Ask RCA Assistant / Time impact.** When enabled, an AI panel answers questions grounded only in this RCA's facts, and a time-impact card breaks down where the incident's time went. Both are aids, not evidence.
5. **External ticket.** The live ticket card — we return to it in Step 5.
6. **Network path & causal topology.** The devices and boundaries involved, drawn as a path with the failure located on it. If there isn't enough routing or path evidence, it says so ("Path location not placed yet") rather than guessing. *Answers: where in the network.*
7. **Evidence matrix.** One card per evidence stream, each with a status pill, what was found, and — crucially — cards for evidence that is *missing* or *conflicting*. *Answers: what supports (and what would strengthen) the verdict.*
8. **Confidence ladder.** The promotion steps from raw signal to confirmed cause, with completed steps lit and the still-locked ones showing what's required. *Answers: why the verdict is exactly this strong and no stronger.*
9. **Evidence timeline.** Lanes per signal group with clickable markers; click any marker and the detail line explains why it was counted as evidence. This is the cascade in time — what happened first, what followed. *Answers: the sequence.*
10. **Hypothesis ranking.** A table of every cause considered — Rank, Hypothesis, Confidence, Reason. *Answers: what else was on the table.*
11. **Ticket & escalation decision** and **Next actions.** The engine's recommendation on ticketing/escalation, then a numbered action list with the recommended owner. *Answers: what to do now.*

:::note
The **Operator View / Debug View** toggle (top right) switches to the engine's raw accounting — which signals were used or ignored and why, and a deterministic replay. **Export PDF** produces the same case as a report.
:::

## Step 4 — Verify on the map

**Tab:** <kbd>Infrastructure → Topology Canvas</kbd> · **Question:** *does the story match the network's shape?*

1. Open the canvas and switch the workflow selector to **Investigate** ("Triage an incident. Lands on the RCA path; select a node to refocus.").
2. Investigate auto-pins the most actionable current incident and spotlights its fault path; use the incident dropdown to pin yours if it landed elsewhere.
3. Read the verdict banner: the same verdict, confidence, summary, recommended action — and an honest *what's missing to confirm* list. The path shows **where**; the banner shows **why**.
4. Select a node to refocus on its first-degree neighborhood and sanity-check the blast radius against what users report. More in [Topology Canvas](/infrastructure/topology-canvas).

## Step 5 — The ticketing leg

**Tabs:** <kbd>Incident Response → RCA Auto-Ticketing</kbd> and the RCA's **External ticket** card · **Question:** *is this on the record, exactly once?*

1. **The policy decides.** Policies at <kbd>Incident Response → RCA Auto-Ticketing</kbd> govern when an RCA object opens a ServiceNow ticket — **one ticket per root cause, never per raw alert**. Gates include **Minimum verdict** (suspected or confirmed), **Require customer-facing**, **Suspected needs critical**, persistence and flap-suppression windows, plus routing (assignment group, default impact/urgency). With no policy, a safe default applies: customer-facing confirmed faults open an incident; internal, probe-only, and undetermined are held. Use **Simulate a decision** to dry-run a policy — it answers "Would open a ticket" or "Held", with the reason. Full reference: [RCA Auto-Ticketing](/incident-response/rca-ticketing); the ServiceNow connection itself is configured under [Integrations](/incident-response/integrations).
2. **Watch the ticket appear.** Back on your RCA, the **External ticket** card shows the state, then the ticket number (deep-linked into ServiceNow), **Last synced**, **Verdict at sync**, and a **History** trail of every action and result. Operators with write access get **Create ticket** / **Sync ticket** buttons; actions are queued and completed by a background worker moments later.
3. **See it everywhere.** The incident row in <kbd>Monitoring → Incidents</kbd> now shows the ticket reference, and the Command Center's **Ticketing gap** panel counts it under *Ticketed*.

## Step 6 — Resolve and close the loop

**Tab:** <kbd>Monitoring → Incidents</kbd> · **Question:** *is the story finished?*

1. Open the incident, click **Resolve** when the fault is fixed (then **Close**, or **Reopen** if it recurs). Add a note — the next shift reads this timeline.
2. The **Timeline** records every status change, note, and ticket-sync event in order — the incident's complete audit trail.
3. After a ticket resolves, the policy's **flap suppression** window prevents a brief recurrence from immediately opening a duplicate. Resolved correlations remain reviewable under <kbd>Monitoring → Correlations</kbd> with the state filter set to **Resolved**.

One anomaly became grouped evidence, a graded verdict, a located fault, a single ticket, and an auditable record — and every claim along the way stayed clickable back to the raw signals that support it.
