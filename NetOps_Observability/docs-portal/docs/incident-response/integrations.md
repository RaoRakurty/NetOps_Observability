---
title: Connect ServiceNow or Jira
sidebar_label: Connect ServiceNow or Jira
description: Connect a ServiceNow instance or a Jira project so incidents project into your system of record, with optional signed two-way sync.
page_type: task
sidebar_position: 3
---

# Connect ServiceNow or Jira

An ITSM connector projects a Correlix incident into your system of record and
keeps its state in step. The connector is configured per tenant, so each tenant
reaches its own ServiceNow instance or Jira project and never another tenant's.

Correlix does not depend on the ticket. The incident is the system of record
inside the platform, and the external ticket is a projection of it.

## Before you begin

- `administration:admin` in the tenant you are configuring. Connector
  configuration is tenant-scoped, so a tenant admin sets up their own. The
  platform owner manages the global connector used for platform incidents.
- For ServiceNow: the instance URL, a service account user and its password, and
  the assignment group tickets should land in.
- For Jira: the base URL, the Atlassian account email, an API token, the project
  key and the issue type.
- A reachable target. Connector URLs are validated against the outbound-request
  guard, so a private or loopback address is refused unless the deployment sets
  `SSRF_ALLOWED_HOSTS` or `SSRF_ALLOW_PRIVATE`.

## Steps

### Step 1: open the connector list

1. Go to **Administration → Incident Response → Integrations**.
2. Pick a tile. Each tile shows **Not connected**, **Connected** or
   **Disabled**, and its control reads **Set up** or **Manage**.

PagerDuty and Slack are alert channels, not connectors. They are configured under
[Notifications](/incident-response/notifications).

### ServiceNow

1. Select **Set up** on the ServiceNow tile.
2. Enter the **instance URL**. It must start with `http://` or `https://`. A
   trailing slash is stripped.
3. Enter the **user** and **password**. Authentication is HTTP Basic.
4. Set the **assignment group** tickets should be routed to.
5. Set the **minimum severity**. The default is `critical`.
6. Enable the connector and save.

Correlix uses the ServiceNow Table API at `/api/now/table/incident`. Tickets are
deduplicated by fingerprint, and the open-ticket map is persisted to disk so
deduplication and auto-close survive a restart.

When the underlying alert clears, Correlix resolves the ticket automatically. It
sets the close code to `Resolved by caller`, the close notes to
`Auto-resolved by Correlix: the underlying alert cleared.`, and adds a work note
saying the incident was auto-resolved.

### Jira

1. Select **Set up** on the Jira tile.
2. Enter the **base URL**, the **email** and the **API token**. Authentication
   is HTTP Basic with the Atlassian account email and the token.
3. Enter the **project key**. It is stored upper-cased.
4. Enter the **issue type**.
5. Set the **resolve transition** if your workflow needs a specific one, by id
   or by name.
6. Set the **minimum severity**. The default is `critical`.
7. Enable the connector and save.

Correlix uses the Jira REST v2 API. Resolution is a workflow transition rather
than a field write. The pinned transition wins when you set one. Otherwise
Correlix takes the first available transition whose name matches `done`,
`resolve`, `close` or `complete`, and adds the comment
`Auto-resolved by Correlix: the underlying alert cleared.`

If no transition matches, the action fails permanently with
`jira: no resolve transition available (pin one in the Jira connection settings)`.
Pin one in the connector settings and the next action succeeds.

### Two-way sync and webhook secrets

Outbound-only is the default. Two-way sync lets the external system tell Correlix
about state changes made by a human in the ticket.

1. In the connector's guided setup, set **Sync mode** to `bidirectional`.
2. Tick **Accept inbound state changes**.
3. Enter a **Webhook signing secret**. It is write-only: on read it comes back
   only as `webhook_secret_set`, and the field label appends `(stored)` once one
   exists.
4. Save, and copy the **webhook URL** Correlix returns. It has the form
   `/api/integrations/webhook/{provider}/{token}`, where the token is a per-tenant
   opaque value minted the first time webhooks are enabled.
5. Register that URL in ServiceNow or Jira as an outbound webhook, and configure
   the signature header.

The webhook route is not authenticated by a Correlix login. It is authenticated
by the opaque token in the path plus the provider's signature.

| Provider | Header | Scheme |
|---|---|---|
| ServiceNow | `X-NetOps-Webhook-Signature` and `X-NetOps-Webhook-Timestamp` | HMAC-SHA256 hex over `{timestamp}.{body}`, with a 5-minute replay window. |
| ServiceNow (fallback) | `X-NetOps-Webhook-Secret` | Constant-time comparison against the raw secret. No replay protection. |
| Jira | `X-Hub-Signature` | `sha256=` followed by the hex HMAC-SHA256 of the body, with a replay bound on the body timestamp. |

The replay window for the Jira form is set by `WEBHOOK_REPLAY_WINDOW` and
defaults to one hour. All comparisons are constant-time.

A bad signature returns `401` with `signature verification failed` and increments
the rejection counter. An unknown token, the wrong provider, or a webhook that is
not enabled all return `404`, because the endpoint must not reveal which check
failed. A body over 512 KiB is refused. A failure to record the event returns
`500` so the sender redelivers.

Ingest and mutation are gated separately. A signature-verified event is always
recorded to the ledger. It only changes incident state when
`FEATURE_ITSM_INBOUND` is enabled and the connector is set to bidirectional.
Until then, the console states that inbound webhooks are recorded but not yet
driving incident state.

### Step 2: reconcile

Webhooks can be missed. A drift reconciler re-reads external ticket state on a
timer as a safety net.

1. Set `FEATURE_ITSM_RECONCILE=true`.
2. Set `ITSM_RECONCILE_INTERVAL` if the default of 5 minutes does not suit. The
   minimum is 1 minute.
3. To force a pass now, use the **sync now** control, which posts to
   `POST /api/integrations/reconcile`.

## Result

The tile reads **Connected**. Secrets read back as booleans and never as values:
ServiceNow as `has_password`, Jira as `has_token`, and each connector also
reports `configured`. Blanking a secret field on update keeps the stored one, so
the console can mask a value it can never re-read.

The routes behind the console:

| Route | What it does |
|---|---|
| `GET`, `PUT` `/api/notify/itsm` | Read and write the tenant's ServiceNow and Jira configuration. |
| `GET` `/api/integrations` | List connector state including `webhook_secret_set` and the webhook URL. |
| `PUT` `/api/integrations/{provider}` | Set sync mode, webhook enablement and the signing secret. |
| `POST` `/api/integrations/reconcile` | Run a reconciliation pass now. |
| `POST` `/api/integrations/webhook/{provider}/{token}` | The inbound webhook endpoint. |
| `GET` `/api/itsm/servicenow` | Read-only ServiceNow connector status. |
| `GET` `/api/itsm/jira` | Read-only Jira connector status. |

Environment variables seed the global connector on first run only. After that
the stored configuration is the source of truth.

| Connector | Feature flag | Other variables |
|---|---|---|
| ServiceNow | `FEATURE_SERVICENOW_NOTIFICATIONS` | `SERVICENOW_INSTANCE_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD`, `SERVICENOW_MIN_SEVERITY`, `SERVICENOW_ASSIGNMENT_GROUP`, `SERVICENOW_STATE_FILE` |
| Jira | `FEATURE_JIRA_NOTIFICATIONS` | `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`, `JIRA_ISSUE_TYPE`, `JIRA_MIN_SEVERITY`, `JIRA_RESOLVE_TRANSITION`, `JIRA_STATE_FILE` |

Enabling a connector does not by itself file tickets from RCA cases. That is a
separate lane, gated by `FEATURE_RCA_TICKETING`. See
[open tickets automatically from RCA](/incident-response/rca-ticketing).

## Related

- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
- [Configure a notification channel](/incident-response/notifications)
- [Work the incident queue](/incidents/working-incidents)
- [Feature flags reference](/reference/feature-flags)
