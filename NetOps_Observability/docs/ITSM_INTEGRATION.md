# ITSM & Ticketing

> **Status: ServiceNow + Jira implemented.** Both connectors auto-ticket
> bi-directionally (`notify/servicenow.go`, `notify/jira.go`): alerts at/above a
> configurable severity open a deduped ticket and **auto-resolve** it when the
> alert clears, with open-ticket state persisted across restarts and live status
> under **Administration → ITSM** (`GET /api/itsm/servicenow`,
> `GET /api/itsm/jira`). Either or both can run at once.
>
> - **ServiceNow** — `FEATURE_SERVICENOW_NOTIFICATIONS=true`,
>   `SERVICENOW_INSTANCE_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD`, optional
>   `SERVICENOW_MIN_SEVERITY` (default `critical`) and
>   `SERVICENOW_ASSIGNMENT_GROUP`.
> - **Jira** — `FEATURE_JIRA_NOTIFICATIONS=true`, `JIRA_BASE_URL`, `JIRA_EMAIL`,
>   `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`, optional `JIRA_ISSUE_TYPE`
>   (default `Task`), `JIRA_MIN_SEVERITY` (default `critical`) and
>   `JIRA_RESOLVE_TRANSITION` (transition name/id used to close; auto-detected
>   from `Done`/`Resolve`/`Close`-like transitions when unset).
>
> Full inbound (poll/webhook) state-sync remains the build plan below.

Turn NetOps alerts and correlated incidents into tickets in the customer's
system of record — **ServiceNow** and **Jira** — with bi-directional sync. This
builds directly on the backend's existing **notifier framework**
(`src/backend/notify/`: slack/pagerduty/email/sns/twilio), which already has the
right shape: a pluggable set of outbound integrations triggered by alert events.

---

## Model

An **ITSM connector** is a notifier that also reads back. For each connector:

```
itsm_connectors(id, tenant_id, kind ENUM(servicenow|jira),
                base_url, auth_jsonb,        -- token/oauth/basic, secret-ref
                field_map_jsonb,             -- severity→priority, etc.
                enabled, created_at)

ticket_links(incident_id, connector_id, external_key,   -- e.g. INC0012345 / NETOPS-42
             external_url, state, synced_at)
```

- **Outbound:** when an alert/incident fires (or is promoted by the correlation
  service), open or update a ticket. Severity → priority via `field_map_jsonb`.
- **Inbound:** poll (or webhook) the ticket's state; reflect status/assignee/
  comments back onto the NetOps incident. On NetOps-side resolve, transition the
  ticket; on ticket close, optionally resolve the incident.
- **Dedup:** `ticket_links` keys an incident to its ticket so re-fires update the
  same ticket instead of spawning duplicates.

---

## ServiceNow

- **API:** Table API (`/api/now/table/incident`) for CRUD; optional CMDB lookup
  (`cmdb_ci`) to enrich tickets with the affected device.
- **Auth:** OAuth2 (preferred) or basic; secret stored by reference, never echoed
  back to the UI (same contract as existing Settings → Integrations).
- **Mapping:** NetOps severity → ServiceNow `impact`/`urgency` → `priority`;
  device/site → `cmdb_ci`/assignment group.

## Jira

- **API:** REST v2 (`notify/jira.go`) — create issue, list/POST transitions, add
  comment. (v2 accepts a plain-text description; v3 requires the verbose ADF
  document body — Jira Cloud serves both.)
- **Auth:** Atlassian account email + API token over HTTP Basic.
- **Mapping:** severity → issue summary/labels; project + issue-type configurable;
  NetOps incident resolve → a `Done`/`Resolve`/`Close`-like workflow transition,
  resolved at close time (transition ids are project-specific) and overridable
  with `JIRA_RESOLVE_TRANSITION`.
- **Dedup + persistence:** keyed by alert fingerprint, state in
  `JIRA_STATE_FILE` (default `/data/jira_tickets.json`) — identical shape to the
  ServiceNow connector.

---

## Reuse, don't reinvent

- **PagerDuty** and **Slack** connectors already exist in `notify/` and are
  marked *Available* in the Integrations UI — they cover on-call routing and
  chat-ops today.
- ServiceNow/Jira slot into the **same notifier interface** for the outbound
  half; the new part is the **inbound sync loop** and `ticket_links` state.
- Connectors are **tenant-scoped** and gated by RBAC (`Alerts: admin` to
  configure), consistent with `IDENTITY_ACCESS.md`.

---

## Build order

1. ~~Outbound: ServiceNow + Jira create/update as notifier plugins.~~ **Done** —
   both auto-open + auto-resolve, deduped, with file-backed open-ticket state.
2. `itsm_connectors` + `ticket_links` tables; connector config UI wired (today
   config is env-driven; secrets never traverse the UI).
3. Inbound sync loop (poll/webhook) → reflect state onto incidents.
4. Field-mapping editor in the UI; CMDB enrichment for ServiceNow.

---

## Related

- `src/backend/notify/` — existing notifier framework (the foundation).
- [`IDENTITY_ACCESS.md`](IDENTITY_ACCESS.md) — tenancy + RBAC gating.
- UI: `src/frontend/src/tabs/admin.tsx` (`IntegrationsAdmin`).
