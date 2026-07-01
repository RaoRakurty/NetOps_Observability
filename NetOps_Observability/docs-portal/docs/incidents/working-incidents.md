---
title: Working incidents
sidebar_label: Working incidents
sidebar_position: 3
description: The operator loop — triage the RCA queue, drive the incident lifecycle, file the ticket, and know when to trust a verdict.
---

# Working incidents

This page is the operator loop: start at the queue, drill into what matters, drive it to resolution, and let the scorecard measure how it went. Two queues share the work — **Correlations** (the RCA candidates: *what is wrong and why*) and **Incidents** (the tracked records: *who is doing what about it*).

## Triage the RCA queue

1. Go to <kbd>Monitoring → Correlations</kbd>. The header KPIs give you the room's state at a glance: **Candidates**, **Confirmed**, **Suspected**, **Not confirmed**.
2. Scan the **Candidate queue** columns:
   - **Status** — Confirmed / Suspected / Not confirmed.
   - **Quality** — how openable the row is: `strong` (confirmed, multi-stream), `candidate` (suspected with grounded, multi-plane evidence), `weak` (thin evidence).
   - **Likely cause** — the matched failure signature (e.g. *BGP peer flap*, *Local link fault*), or "Not yet determined".
   - **Owner** — the recommended acting party (NetOps, ISP / carrier, cloud provider, …).
   - **Linked by** — what ties the evidence together: *Boundary* (a responsibility handoff such as your ISP edge), *Same path*, or *Boundary + path*.
   - **Evidence types** — how many independent signal classes attached.
   - **Evidence source** — *trusted*, *weak*, or *test check* (a synthetic/debug signal, never actionable).
   - **Signals** — raw signal count.
3. Filter with the two dropdowns — state (**Open** / **Resolved**) and status (**Confirmed** / **Suspected** / **Not confirmed**) — and sort by any column. Sort by **Quality** descending to work strongest-first.
4. Click a row to open the [RCA detail view](/incidents/reading-an-incident).

:::note Internal objects are hidden by default
The queue shows customer-network issues. The platform's own self-monitoring objects are hidden; tick **Show internal/stack** only when debugging the platform itself.
:::

## When to trust "Confirmed" vs "Suspected"

Correlix applies a hard rule: **a root cause is confirmed only when independent evidence agrees across at least two signal classes.** A routing-or-device event, a traffic-flow change, and an active probe are three independent ways of seeing the same fault — "Confirmed" requires at least two of them, aligned in time and scope. A single stream, however strong, reads as **Suspected**, and the view can never overclaim past the engine.

In practice:

- **Confirmed** → act. Open or escalate the incident; the Decision callout reads **OPEN INCIDENT** and auto-ticketing (if policy allows) will file.
- **Suspected** → investigate, don't escalate. The detail view's **To confirm** line tells you exactly which evidence would settle it — often the fastest move is to check that source directly (device state, an active probe, [flow data](/explore/flows)).
- **Not confirmed** → watch. These are gathering evidence; the **Signature coverage gaps** panel below the queue shows which recurring shapes keep falling short of a verdict and what they lacked.

## Work the incident queue

Tracked incidents are the system of record — deduplicated (a recurrence folds into the same row and bumps its **Count**), owned, and driven through a lifecycle.

1. Go to <kbd>Monitoring → Incidents</kbd>. The KPIs show **Open**, **Critical**, **Unassigned**, and **Ticketed** counts.
2. Filter the **Incident queue** by status (*open, acknowledged, investigating, resolved, closed*) and severity (*critical, high, medium, low, info*). The default view shows open incidents, newest activity first (**Last seen**).
3. Click a row. The detail pane shows the incident's severity, title, occurrence count, description, and any linked external ticket.
4. Drive the lifecycle with the action buttons:
   - **Acknowledge** — you've seen it; it's yours.
   - **Investigate** — work has started.
   - **Resolve** — the condition is fixed.
   - **Close** / **Reopen** — available once resolved.
5. Use **Add a note to the timeline…** to record findings as you go — notes, status changes, assignments, deduplicated recurrences, and ITSM sync events all appear on the incident's **Timeline**, merged chronologically. Sync entries show the direction (↑ outbound / ↓ inbound), the provider, and the result.

## From incident to ticket

1. Open the RCA detail (<kbd>Monitoring → Correlations</kbd> → click the row) and find the **External ticket** card.
2. If no ticket exists and you have write permission, click **Create ticket**. The action is queued — "Ticket creation queued — the worker will open it shortly." — and the card updates with the ticket number, deep link, and state.
3. For an already-open ticket, **Sync ticket** pushes the current verdict and evidence to it.
4. Every action lands in the card's **History** trail with its result — your compliance record.

Correlix files **one ticket per incident**, keyed to the incident id, so re-syncs update rather than duplicate. To make this automatic (e.g. every confirmed verdict files itself), configure a policy under <kbd>Incident Response → RCA Auto-Ticketing</kbd> — see [RCA Auto-Ticketing](/incident-response/rca-ticketing). Notification routing (Slack, PagerDuty, email) is configured under [Notifications](/incident-response/notifications).

## Measure the loop

Close the loop weekly on the <kbd>Monitoring → Recovery Scorecard</kbd>:

1. Pick a window (**7d / 30d / 90d**) and optionally an owner filter (ISP, Cloud, SaaS, App, LAN / Network).
2. Read the headline cards: **Median root-domain isolation time** (MTTI p50 — Correlix's hero metric: detection to an evidence-backed root domain and owner), its **p90** long tail, correlation time, recovery and ticket-closure time, **MTBF**, **repeat rate**, and the **top time-loss driver**.
3. Use **Owner Domain Breakdown** to see where the pain lands, and **Recurring Failure Sources** for the objects that keep coming back, each with a recommended action.

:::note Some metrics need workflow evidence
Recovery and ticket-closure timing read **"Not measured"** until ITSM or recovery evidence is connected — the scorecard never fabricates an MTTR. The **Evidence coverage** strip shows exactly which phases are measurable.
:::

## Verify

- A newly acknowledged incident shows a `status_change` entry (`open → acknowledged`) on its timeline, and the queue KPIs update after **Refresh**.
- A queued ticket action appears in the External ticket card's History within a few seconds, and the ticket number deep-links into your ITSM.

## Troubleshooting

- **"Incident management isn't enabled in this environment yet."** — the incidents store isn't provisioned in this deployment; use the Correlations queue and alerts directly.
- **Ticket stuck in "Creation queued"** — check the ITSM connection under <kbd>Incident Response → Integrations</kbd> ([Integrations](/incident-response/integrations)); failed attempts and their reasons appear in the ticket card's History.
- **Empty queue** — "No incidents match — quiet is good." If you expected data, confirm devices are reporting under [Verify monitoring](/onboard-devices/verify-monitoring).
