---
title: Work the incident queue
sidebar_label: Work the incident queue
description: Work the RCA candidate queue and the operational incident list, from first triage through to an external ticket.
page_type: task
sidebar_position: 3
---

# Work the incident queue

Two queues carry a shift. The RCA candidate list ranks what the engine believes
is happening. The operational incident list tracks what the team is doing about
it. This page works both, in that order.

## Before you begin

- `alerts:read` for both queues, and `alerts:write` to drive an incident's
  lifecycle. `infrastructure:write` is required for the ticket actions on an RCA
  case.
- The Postgres backend, for the operational incident list. On the file backend
  the incident routes answer `409` with `the incident system requires the
  Postgres backend`.

## Steps

### Triage the RCA queue {#triage-the-rca-queue}

1. Go to **Investigate → RCA**. The page is titled **RCA Candidates**.
2. Use the count chips above the table to narrow: all candidates in the last 24
   hours with merged duplicates excluded, confirmed, suspected, undetermined, or
   promoted real outages.
3. Read the row left to right.

| Column | What it carries |
|---|---|
| **ID** | The Problem ID, in the form `P-XXXXXX`. |
| **Updated** | When the case last changed. |
| **Status** | The verdict tier. |
| **RCA doc** | **Promoted** when the case is a real outage with a document in the RCA Reports library. |
| **Quality** | Whether the case is a planned resilience drill rather than a customer incident. |
| **Likely cause** | The top hypothesis. |
| **Owner** | The seam owner. |
| **Notified via** | The destinations this case was already filed to. |
| **Linked by** | What grounded the grouping. |
| **Evidence types** | How many independent evidence classes contributed. |
| **Evidence source** | The authority behind the evidence. |
| **Obs.** | Raw observations collected. |

4. Work confirmed cases first, then suspected cases at critical severity, then
   the rest.

The **Obs.** column measures persistence, not evidence. A case with
400 observations from one source is weaker than a case with 6 observations from
three sources, and the **Evidence types** column is the one that says so.

### When to trust confirmed vs suspected {#when-to-trust-confirmed-vs-suspected}

`confirmed` means independent evidence classes agree in the same window and
scope. Two sources that both derive from the same collector are one source, and
the engine counts them that way.

`suspected` means the evidence points somewhere and no independent pair has
confirmed customer impact yet. The case header states which single source saw it
and that a second independent source is needed.

Act on a suspected case when the severity justifies acting before confirmation
arrives, and treat the named cause as a hypothesis when you talk to the owning
party. The product phrases it that way on purpose: an unconfirmed case reads
`Not confirmed — possibly because of X`, never a bare cause.

`contradicted` means the leading cause was ruled out by discriminating evidence.
The sequence stays visible for the record, not as a live explanation. Do not
escalate a contradicted cause to a provider.

`undetermined` means no cause has enough supporting evidence yet. State the
symptom and the impact, and do not imply a root cause.

Correlix records what you think of a verdict. Rating a case feeds the
false-positive rate, which is reported honestly as absent until there are
ratings to compute it from:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/correlations/feedback/summary
```

```json
{
  "by_template": [],
  "counts": { "correct": 0, "partial": 0, "wrong": 0 },
  "days": 30,
  "false_positive_rate": null,
  "n": 0,
  "since": "2026-08-04T03:48:41Z"
}
```

`false_positive_rate` is `null`, not `0`. Nobody has rated a case, so nothing was
measured. See [rate an RCA case](/investigate/rate-an-rca-case).

### Work the operational incident list

1. Go to **Operations → Incidents**. The page is titled **Operational
   Incidents**.
2. Read the row: **ID** (in the form `INC-XXXXXX`), **Severity**, **Status**,
   **Title**, **Count**, **Source**, **Notified via** and **Last seen**.
3. Drive the lifecycle. The status ladder is `open`, `acknowledged`,
   `investigating`, `resolved`, `closed`, and the actions available on an
   incident are acknowledge, investigate, resolve, close, reopen, assign, note
   and promote.

The severity ladder is `info`, `low`, `medium`, `high`, `critical`. A filter
value outside that ladder is refused with `400` rather than silently mapped to
`info`, so a query for warnings never returns info incidents labelled as
warnings.

The **Count** column is the deduplicated occurrence count. Alerts, findings and
anomalies fold into one incident rather than each opening their own.

### From incident to ticket {#from-incident-to-ticket}

Ticketing is driven off correlated RCA cases, never off raw alerts. A storm of
57 alerts that correlate into one cause produces one ticket, not 57.

1. Open the RCA case and find the **External ticket** card. With more than one
   destination it is titled **External tickets & paging**.
2. Read the state pill. With no ticket, the card reads **No external ticket has
   been opened for this RCA object yet.**
3. With `infrastructure:write`, select **Create ticket**. On a case that already
   has an open ticket the control reads **Sync ticket**, and after a failed
   attempt it reads **Retry create**.
4. Read the confirmation. Creating shows
   `Ticket creation queued — the worker will open it shortly.` and syncing shows
   `Sync queued — the open ticket will update shortly.` The card re-polls on its
   own.

The action is enqueued to an outbox and drained by a worker. Ticketing never
blocks correlation, so a slow or unreachable ITSM system delays the ticket and
nothing else.

Once a ticket exists, the card shows its state pill, the ticket number as a deep
link, the destination system, and the last sync time. Below that, **History**
lists the most recent actions with their result, including a dead-letter result
when an action exhausted its retries.

A case that does not meet the ticketing policy says why. The blocked reason is
the policy's own words, for example `undetermined — no grounded cause yet`,
`internal monitoring only — not customer-impacting`, or
`suspected but severity below critical — held below threshold`.

## Result

The RCA queue is triaged in verdict order, each operational incident carries a
status and an owner, and the cases that meet policy have a ticket number and a
deep link on the card.

## Related

- [Read an incident](/incidents/reading-an-incident)
- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
- [Connect ServiceNow or Jira](/incident-response/integrations)
- [Configure a notification channel](/incident-response/notifications)
