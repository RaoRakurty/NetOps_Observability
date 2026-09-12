---
title: Track a ticket that has not arrived
sidebar_label: Track a ticket that has not arrived
description: Read the delivery outbox and the ticket audit trail to find out where an RCA ticket stopped, and sweep two-way integrations for drift.
page_type: task
sidebar_position: 5
---

# Track a ticket that has not arrived

RCA ticketing does not call the ticketing system from the correlation path. A
policy decides a case should be filed, a row is queued in an outbox, and a
worker drains that outbox with bounded retries. **Ticket Delivery** is the view
of that outbox, the audit trail beside it, and the provider's own refusal text
on any row that failed.

Use this page when an operator says a ticket never appeared. It separates the
two causes that look identical from the case: no policy filed anything, or
something was filed and the provider refused it.

## Before you begin

- `infrastructure:read` in the tenant whose delivery you are reading. Both
  reads are tenant-filtered on the server, so you see your own tenant's rows and
  no one else's.
- `administration:admin` to run **Sync now**. It acts on the caller's own
  tenant.
- A configured destination. See
  [connect ServiceNow or Jira](/incident-response/integrations). With no
  destination configured there is nothing to deliver and nothing to sweep.

## Steps

### Step 1 — Read the outbox

1. Go to **Administration → Incident Response → Ticket Delivery**.
2. Read the three counts at the top: queued, failed, delivered.
3. Select **Failed** to narrow the table to rows that stopped.

Each row names the RCA case, the destination, the action, the attempt count
against the maximum, the next scheduled attempt, and **Last refusal**. The
refusal is the provider's own wording, kept verbatim, because it is the one
fact that says what to fix.

The states map onto the lanes like this:

| Lane | Row status | What it means |
|---|---|---|
| Queued | `pending`, `retrying` | The worker has the row and will attempt it again |
| Failed | `failed`, `dead_letter` | Attempts are exhausted or the row was set aside |
| Delivered | `sent` | The provider accepted it |

An empty outbox is not evidence that a ticket was filed. The outbox holds work
on its way out, and a delivered row leaves it. The audit trail is what proves a
delivery happened.

### Step 2 — Read the audit trail for one case

1. Copy the case id from the RCA case URL.
2. Paste it into **RCA case id** under **Audit trail** and select **Filter**.
3. Read the recorded transitions: when, which destination, which action, who
   acted, the state change, and the result.

An empty trail for a case means nothing was ever sent for it, in either
direction. That points at the policy rather than at the provider. See
[open tickets automatically from RCA](/incident-response/rca-ticketing).

The same read over the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/tickets/audit?corr_object_id=$CASE&limit=50"
```

### Step 3 — Re-drive one case

Select **Sync this case** on a row. It queues a fresh sync for that RCA case and
adds a new outbox row. It does not replay the stuck row, and the page says so
where the control is.

### Step 4 — Sweep two-way integrations

Select **Sync now**. It reads the current state of every bidirectional
integration configured for your tenant and records what changed on the
provider's side. It does not open or close a ticket.

The count it reports can honestly be zero while integrations exist. Only
bidirectional integrations are swept, so a one-way integration is not counted.
It still delivers; it has no state to read back.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/integrations/reconcile
```

```json
{"reconciled_providers": 2}
```

## Result

A failed row carries the provider's refusal, so you know whether to fix a field
mapping, a credential or a permission at the ticketing system. A case with no
audit entries tells you the policy never fired. The page states which of those
two you are looking at rather than showing one blank table for both.

Paging is explicit. The line under the table says either "this is the whole
outbox" or "the first N of M rows", so a bounded page is never mistaken for the
complete set.

## Related

- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
- [Connect ServiceNow or Jira](/incident-response/integrations)
- [Configure a notification channel](/incident-response/notifications)
- [Read the audit log](/administration/audit-log)
