---
title: Reading an incident
sidebar_label: Reading an incident
sidebar_position: 2
description: A step-by-step walk through the RCA detail view — verdict, evidence matrix, causal topology, evidence timeline, ticket card, and time metrics.
---

# Reading an incident

Opening an RCA candidate renders the **root cause analysis workspace** — a single-column report that reads top-to-bottom: what happened, how sure we are, what the evidence is, and what to do next. This page walks it section by section.

## Open the detail view

1. Go to <kbd>Monitoring → Correlations</kbd>.
2. Click any row in the **Candidate queue**. The detail opens in the side inspector, titled **Root cause analysis**.
3. Use the tabs at the top right to switch between **Operator View** (default, plain NOC language) and **Debug View** (raw engine data). **⤓ Export PDF** generates a print-ready RCA report of exactly what's on screen.

## Step 1 — Read the headline and status pills

The case header states *what was observed* — for example "Routing adjacency change" or "Middle-mile latency increase". The title is factual; the certainty is carried by the pills next to it:

- **Verdict pill** — `✓ CONFIRMED`, `NOT CONFIRMED`, `✕ RULED OUT` (the leading cause was contradicted by evidence), or `● RECOVERED` (the incident has cleared).
- **Confidence** — High / Medium / Low, driven by how many independent signals attached.
- **RCA state** — the investigation lifecycle: *Under review* (gathering evidence), *Open incident* (confirmed and active), *Recovering* (clear signals arriving), *Recovered*.

Below the pills, the **Decision** callout gives the recommended NOC action in one line — one of:

- **OPEN INCIDENT** — customer impact is confirmed by independent evidence; assign ownership.
- **INVESTIGATE** — evidence is aligned but not sufficient to confirm; validate the missing signals first.
- **MONITOR** — the triggering signal has cleared with no impact evidence; auto-close if it doesn't recur.
- **HOLD** — suspected only; ticketing stays on hold until independent evidence confirms impact.

The header also shows **Observed at** (UTC) and the **RCA ID** — the incident id you can quote in tickets and hand-offs.

## Step 2 — Check the summary sidebar

The right-hand sidebar answers triage at a glance:

- **Root cause object** — the device (and peer, for a routing adjacency) the analysis localizes to.
- **Likely owner** — who should act: NetOps, ISP / carrier, cloud provider, app team, SD-WAN vendor, colo provider.
- **Signals** — how many telemetry signals attached as evidence.
- **Suggested ticket** — *Open P2* when confirmed, *Hold* otherwise.

## Step 3 — Read the executive summary and the "why" lines

The **Executive RCA summary** panel narrates the case in one paragraph, followed by labeled reasoning lines:

- **Why suspected** — what localized the issue.
- **Why confirmed** / **Why not confirmed** — whether independent evidence aligned, or what single observation the case still rests on.
- **To confirm** — exactly which additional evidence would raise the verdict (peer-side routing state, traffic-flow loss, downstream impact, an active check from an independent vantage).
- **Ruled out** — competing causes the evidence does not support, when discriminating evidence exists.

Next to it, **Impact & blast radius** lists the affected device, peer, scope type, and whether service/application and path impact are confirmed. An unconfirmed case honestly reads "No confirmed customer impact" — the view never promotes a claim the engine didn't make.

## Step 4 — Read the Time Impact card

The **Time Impact** card decomposes this incident's clock into two zones, each row showing elapsed time from the first impact signal:

- **RCA evidence timeline** (measured by Correlix): *Detected → Correlated → Root / seam isolated ★ → Owner assigned → Evidence bundle ready*. The starred isolation row is the hero metric (MTTI) and carries the isolated boundary and owner inline.
- **Workflow & recovery timeline** (requires ITSM/recovery evidence): *Ticket created → Acknowledged → Mitigated → Service recovered → Ticket closed*.

A banner names the **current bottleneck** (a real, measured delay) or a **current measurement gap** — workflow rows read "Not measured" when no ITSM or operator-workflow evidence is connected: a visibility gap, not a process failure. Derived timestamps are tagged **Inferred**.

## Step 5 — Check the External ticket card

The **External ticket** card shows this incident's ITSM state: a status pill (*No ticket*, *Creation queued*, *Open*, *Updated*, *Resolved*, *Failed*), the ticket number as a deep link, the last sync time and verdict at sync, and a **History** audit trail of every action. Operators with write permission get a **Create ticket** or **Sync ticket** button. See [Working incidents](/incidents/working-incidents#from-incident-to-ticket).

## Step 6 — Read the causal topology

**Network path & causal topology** draws the affected chain: the root-cause device (tagged **ROOT CAUSE** when confirmed, **SUSPECTED** otherwise), its routing peer, and each affected path segment with edge labels for the failing measurement. If there isn't enough routing or path evidence to place the issue, the panel says so plainly ("Path location not placed yet") rather than guessing.

When the incident carries cloud or application evidence, additional sections appear here: **Cloud application & resources** (affected cloud resources and configuration changes, and whether an independent network observer corroborates them) and **Application impact** (which applications are affected, with source and confidence band).

## Step 7 — Walk the evidence matrix and confidence ladder

The **Evidence matrix** shows one card per evidence plane — **Device health**, **Routing / link**, **Traffic flow**, **Active checks** — each pilled as *Main evidence*, *Used*, or *Not observed*. Absent planes are shown deliberately: they tell you exactly what's missing to confirm.

The **Confidence ladder** shows how far the verdict climbed: *Observed → Suspected → Probable → Confirmed*. Locked steps (🔒) name what's still required to advance.

## Step 8 — Walk the evidence timeline

The **Evidence timeline** plots every signal on one time axis, one lane per signal group. Empty lanes are kept visible on purpose — an empty lane is information.

1. Read left to right: what fired first, what followed, which lanes agree.
2. **Click any marker** for its detail: the signal, the device, and whether it was *counted as evidence* or merely *seen in the window but not linked*.

## Step 9 — Hypotheses, next actions, and the assistant

- **Hypothesis ranking** lists the competing explanations with a confidence pill and the reason each ranks where it does.
- **Ticket & escalation decision** restates the ticket recommendation with its rationale.
- **Next actions** is a numbered playbook from the matched failure signature — ESCALATE / INVESTIGATE / CHECK / MONITOR steps in priority order.
- **Ask RCA Assistant** answers questions grounded *only* in this RCA's evidence (e.g. "Why is this not confirmed?"). It requires Correlix AI to be connected; otherwise it shows the suggested reasoning inline.

## Debug View

Switch to **Debug View** for the engine's raw accounting: every signal with its used/ignored status, weight, and reason; the promotion thresholds; the full correlation data model; and a **Replay object** button that deterministically re-runs the analysis and reports whether it reproduces bit-perfect. Use it to defend a verdict, not for day-to-day triage.

## Troubleshooting

- **The detail says "Loading…" indefinitely** — the case can't render if the correlation service is unreachable; check the platform's own health under the Stack pages.
- **A deep link says "RCA not found"** — the linked incident resolved and aged out, or your role doesn't have access to it. The page falls back to the current candidate list.
