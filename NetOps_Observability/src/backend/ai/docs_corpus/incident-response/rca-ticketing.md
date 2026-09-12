---
title: Open tickets automatically from RCA
sidebar_label: Open tickets automatically from RCA
description: Open one ticket per root cause with an RCA ticketing policy, and read the ticket card on a case.
page_type: task
sidebar_position: 4
---

# Open tickets automatically from RCA

RCA ticketing files one ticket per root cause. It is driven off correlated RCA
cases, never off raw alerts, so a storm of 57 alerts that correlate into one
cause produces one ticket rather than 57.

The lane is opt-in and dormant by default.

## Before you begin

- `FEATURE_RCA_TICKETING=true` in the deployment environment. Without it the
  outbound worker, the sweeper and the inbound state sync never start, and
  ticketing never runs unasked.
- A configured destination. See
  [connect ServiceNow or Jira](/incident-response/integrations), and
  [configure a notification channel](/incident-response/notifications) for the
  PagerDuty and Slack destinations.
- `administration:read` to view a policy and `administration:write` to change
  one, in the tenant whose policy you are editing.

## Steps

### Step 1: enable the lane

1. Set `FEATURE_RCA_TICKETING=true`.
2. Restart the api service.

### Step 2: set the policy

1. Go to **Administration → Incident Response → Ticketing & Automation**.
2. Set the destination in **external system**.
3. Set **minimum verdict** to `suspected` or `confirmed`.
4. Set the guardrails. The shipped default policy is deliberately narrow:

| Setting | Default | What it does |
|---|---|---|
| `min_verdict` | `suspected` | The weakest verdict allowed to file. |
| `require_customer_facing` | on | A case with no meaningful affected entity is held. |
| `suspected_requires_critical` | on | A suspected case files only at critical severity. |
| `allow_probe_only` | off | A single low-authority active check is not corroborated evidence. |
| `allow_internal_monitoring` | off | Internal and debug-only monitoring never opens a customer ticket. |
| `allow_validation_scenarios` | off | A validation or fault-injection scenario never files a production ticket. |
| `require_persistence_seconds` | 0 | A case must persist this long before it files. |
| `default_impact`, `default_urgency` | 2, 2 | The ServiceNow priority mapping for a suspected case. |

5. Save.

| Route | Permission | What it does |
|---|---|---|
| `GET /api/incident-policies` | `administration:read` | List this tenant's policies. |
| `POST /api/incident-policies` | `administration:write` | Create or replace one. |
| `PUT /api/incident-policies/{id}` | `administration:write` | Update one. |
| `DELETE /api/incident-policies/{id}` | `administration:write` | Remove one. |
| `POST /api/incident-policies/{id}/test` | `administration:read` | Simulate the policy against a case. It makes no external call and enqueues nothing. |

Use the simulator before enabling a policy. It answers the create-or-hold
question with the same code the worker runs, without filing anything.

Priority escalates automatically unless you pin values. A confirmed critical case
maps to impact 1 and urgency 1, a confirmed case to urgency 1, and a suspected
case uses the defaults. An explicit value wins outright.

### Step 3: watch the outbox

An action is enqueued, not sent inline. Ticketing never blocks correlation.

| Route | What it shows |
|---|---|
| `GET /api/tickets/outbox` | Queued actions with `status` of `pending`, `sent`, `failed`, `retrying` or `dead_letter`, plus the retry count and last error. |
| `GET /api/tickets/audit` | The action ledger: one row per action with actor, old and new status, and result. |
| `GET /api/tickets/links` | Every ticket link for the caller's tenant, which is what the RCA queue's **Notified via** column joins against. |

### The ticket card on an incident

1. Open an RCA case at **Investigate → RCA**.
2. Find the **External ticket** card. With more than one destination it is
   titled **External tickets & paging**.

With no ticket, the card reads **No external ticket has been opened for this RCA
object yet.**

With one or more, each destination row carries a state pill, the ticket number
as a deep link, the destination system, and the last sync time. Link status
values are `pending`, `open`, `updated`, `resolved` and `failed`.

Actions require `infrastructure:write`:

| Control | When it appears | What it does |
|---|---|---|
| **Create ticket** | No ticket exists. | Enqueues a create. |
| **Retry create** | A previous create failed. | Enqueues another create. |
| **Sync ticket** | An open or updated ticket exists. | Pushes the current RCA state onto it. |

The confirmation text is exact. Creating shows
`Ticket creation queued — the worker will open it shortly.` and syncing shows
`Sync queued — the open ticket will update shortly.` The card re-polls on its own
a few seconds later.

Below the actions, **History** lists the most recent actions with their result,
including `dead_letter` when an action exhausted its retries.

## Result

Each destination carries a stable deduplication identity derived from the tenant
and the correlation id, in the form `tenant:correlation-id:system`. PagerDuty
prefixes that with `correlix:` and sends it as the Events v2 `dedup_key`.

That identity is what makes the behaviour idempotent:

- A repeated create is an update at the destination, never a second incident.
- Retries reuse the same key, so a retry after an ambiguous failure cannot
  duplicate.
- One link exists per tenant, correlation object and system.

PagerDuty incidents close automatically when the alerts clear. Correlix sends a
resolve on the same routing key and deduplication key, with no payload needed.
Without it, resolved conditions would accumulate as stale open incidents.

Correlix to PagerDuty is one-way by design. Telemetry is the resolution
authority, and the ITSM system records the human response phases.

Human display ids lead every destination's text, so one handle follows the
incident across systems. RCA cases carry a Problem ID in the form `P-XXXXXX`,
and the operational incident record carries a display id in the form
`INC-XXXXXX`. ServiceNow also receives the Problem ID in the
`u_correlix_problem_id` field. The raw correlation UUID stays canonical inside
the deduplication key and never appears in operator-facing copy.

### When a case is held

A case that does not meet policy is held, and the reason is the policy's own
words. These appear verbatim on the case:

- `ticketing policy disabled`
- `undetermined — no grounded cause yet`
- `internal monitoring only — not customer-impacting`
- `validation scenario — production ticket side effects suppressed`
- `active-check-only (low authority) — awaiting independent corroboration`
- `single active-probe plane — awaiting independent corroboration`
- `no meaningful affected entity to scope a ticket to`
- `suspected but severity below critical — held below threshold`
- `ticket already open (…)`

A held case is not a failure. It is Correlix declining to file a ticket it cannot
justify.

### Inbound state sync

Under `FEATURE_RCA_TICKETING`, Correlix also polls ServiceNow for state changes
and appends each action to the audit ledger at most once. The interval is set by
`RCA_TICKETING_INBOUND_INTERVAL` and defaults to 45 seconds. This is a poller,
with no webhook and no shared secret. It is separate from the signed webhook path
described under
[two-way sync and webhook secrets](/incident-response/integrations#two-way-sync-and-webhook-secrets).

### The legacy raw-alert path

Filing tickets directly from raw alerts was removed. The legacy incident-to-ITSM
sync answers that it is deprecated and that tickets file via RCA auto-ticketing
policies. It is re-enablable only with `FEATURE_LEGACY_ALERT_ITSM`, which is off
by default and should stay off. Ticketing off raw alerts is what produced 57
tickets for one cause.

## Related

- [Connect ServiceNow or Jira](/incident-response/integrations)
- [Incident timing and recovery](/incident-response/rca-time-intelligence)
- [Work the incident queue](/incidents/working-incidents)
- [Incidents](/incidents/overview)
