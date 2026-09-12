# Jira Integration — Setup Guide

Correlix opens **Jira issues from correlated RCA objects** — the work-tracking
lane for Jira shops. One deduplicated issue per root cause, updated in place,
transitioned to Done on resolve. Raw alerts never open Jira issues (the legacy
raw-alert connector is deprecated and dormant behind
`FEATURE_LEGACY_ALERT_ITSM`).

> **Validation status:** implemented and tested against a local fake Jira REST
> v2 server (lifecycle, retry classes, tenant isolation). **Not yet validated
> against a real Atlassian site** — per the standing directive, real-app
> validation happens when the owner supplies a Jira Cloud site + API token.

## 1. Jira side (get the credentials)

Correlix speaks the **Jira REST API v2** (served by Jira Cloud and Server/DC)
with HTTP Basic auth:

1. Create (or pick) a service account, e.g. `correlix-noc@yourorg.com`.
   Issues and comments are authored as this account.
2. Jira Cloud: **Account settings → Security → Create and manage API tokens →
   Create API token**. Copy the token (shown once). Treat it as a secret.
3. Ensure the account can **create issues, comment, and transition** in the
   target project (project role `Member`/`Service Desk Team` or equivalent).
4. Note the **project key** (e.g. `NOC`) and, if your workflow is custom, the
   name or id of the **transition that closes an issue** (e.g. `Done`,
   `Resolve Issue`).

## 2. Correlix side

### Connection (per tenant)

Administrator login → **Incident Response → Integrations → Jira** (guided
setup): base URL (`https://yourorg.atlassian.net`), account email, API token
(write-only; blank keeps the stored one), project key, issue type (default
`Task`), resolve transition (optional — auto-detects a Done/Resolve/Close/
Complete-like transition when empty).

API equivalent (`PUT /api/notify/itsm`, tenant-scoped): the `jira` block of
the ITSM config. `configured` in the response reflects what the RCA lane
resolves against: enabled + base URL + project key.

### Policy (per tenant, strictly opt-in)

Administration → **RCA Auto-Ticketing** → New policy → External system =
`jira`. Verdict/severity/persistence gates work exactly like ServiceNow
policies. One enabled policy per (tenant, system); a tenant can run
ServiceNow + PagerDuty + Slack + Jira side by side (separate policies,
separate links, independent retries). **No Jira policy → no issues, ever.**

## 3. Lifecycle & identity

- **create** → `POST /rest/api/2/issue` — project/issue-type from the
  connection, summary `[P-XXXXXX] <RCA title>` (the same friendly Problem ID
  the RCA Inspector, ServiceNow, PagerDuty and Slack carry — #103 UX-2), the
  RCA diagnosis as plain-text description, labels
  `correlix, rca, verdict-<verdict>, correlix-id-<correlation-uuid>`.
- **update** → `PUT /rest/api/2/issue/{id}` refreshing summary + description
  only — never labels (the dedupe label must survive) and never workflow
  state. Updates only enqueue when the RCA state materially changed
  (payload-hash gate).
- **work note** → issue comment.
- **resolve** → workflow transition (configured hint by id/name, else the
  first Done/Resolve/Close/Complete-like transition), with the resolution
  comment attached. An issue already in the `done` status category is a
  success no-op (idempotent replays); a workflow with no resolve-like
  transition dead-letters with an actionable error — pin the transition in
  the connection settings.
- **identity**: the canonical ref is the immutable numeric issue id; the
  issue key (`NOC-123`) is the operator-visible number and the deep link
  (`/browse/NOC-123`). Crash-after-create recovery looks the issue up by the
  `correlix-id-<uuid>` label (JQL), so a lost link store never files a
  second issue.
- **delivery**: same transactional outbox + SKIP-LOCKED worker as every
  destination — backoff + jitter, 429 honors `Retry-After`, 400/401/403
  dead-letter (permanent), tenant asserted before every external call
  (mismatch = quarantined, never sent). Errors never contain the API token.

## 4. Deliberate scope choices

- **Priority is not set** on created issues: priority schemes are
  per-instance and an unknown name fails the whole create (400). Map
  priority in Jira from the `verdict-*` label with an automation rule if
  needed.
- **Inbound state sync** (Jira → Correlix incident phases) is not wired —
  the inbound syncer is ServiceNow-only today; Jira's workflow categories
  don't map 1:1 onto the ITSM lifecycle model. Future work, documented in
  the #103 tracker entry.

## 5. Troubleshooting / runbook

| Situation | Action |
|---|---|
| Issues never open | Policy simulator first (`runtime_state` names the governing Jira policy — remember Jira is opt-in), then the connection card (`configured` requires enabled + base URL + project key), then `GET /api/tickets/outbox`. |
| 400 dead-letters on create | Project key wrong, issue type not in the project's scheme, or a required custom field on the create screen — the audit row carries Jira's `errors` map verbatim (bounded). |
| 401/403 dead-letters | Token revoked or account lost project permission. Rotate/fix in Jira, re-enter the token; deliveries re-enqueue on the next RCA change. |
| Resolve dead-letters with "no resolve transition" | The project workflow has no Done/Resolve/Close-like transition from the issue's current state — pin the exact transition (name or id) in the connection settings. |
| Duplicate issues suspected | Search `labels = "correlix-id-<uuid>"` — one hit per root cause is the invariant; two hits means the label was manually removed (the recovery lookup depends on it). |
| Issue edited/moved in Jira | Safe: updates address the immutable issue id, not the key; moved issues keep working, the stored deep link keeps the old key until the next create. |
