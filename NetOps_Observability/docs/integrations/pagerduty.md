# PagerDuty Integration — Setup Guide

Correlix pages PagerDuty through **Events API v2**: alerts that clear the
severity gate trigger PD incidents with stable dedup keys, and **auto-resolve
them when the alert clears** (resolution propagation, 2026-07-11). One alert =
one PD incident for its whole lifecycle — re-fires update, they never
duplicate.

## 1. PagerDuty side (get the Integration Key)

1. Log in to your PagerDuty account → **Services** → **Service Directory**.
2. Either open an existing service or **+ New Service**
   (name: e.g. `Correlix NetOps`; assign the escalation policy that should
   receive network pages).
3. On the service → **Integrations** tab → **+ Add an integration** →
   choose **Events API V2** → **Add**.
4. Copy the 32-character **Integration Key** (a.k.a. routing key). This is
   the only PagerDuty credential Correlix needs.

Treat the key as a secret — it authorizes event submission to your service.

## 2. Correlix side

### UI (preferred)

1. Administrator login → **Administration → Notification channels →
   PagerDuty**.
2. Paste the **Integration Key** (write-only; stored encrypted, shown only as
   `routing key set`).
3. **Minimum severity**: default `critical` — recommended. PD is for waking
   humans; leave `warning`-class chatter to Slack/email.
4. Toggle **Enabled** → **Save** → **Test**. A test event must appear as a
   triggered incident on the PD service (resolve it in PD afterwards).

### API (equivalent)

```bash
curl -X PUT https://<host>/api/notify/pagerduty \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"routing_key":"<32-char-key>","min_severity":"critical"}'
curl -X POST https://<host>/api/notify/pagerduty/test -H "Authorization: Bearer $TOKEN"
```

Config persists in the encrypted notify store; the legacy `PAGERDUTY_KEY` env
var only seeds it on first boot — the UI/API value is authoritative.

## 3. Behavior details (what to expect)

- **Trigger**: each qualifying alert sends `event_action: trigger` with a
  dedup key derived from the alert identity; PD severity is normalized to the
  Events v2 enum (a 2026-07-11 fix — earlier 400-rejections came from empty
  `source`/non-enum severities).
- **Resolve**: when the alert leaves the engine's active set, Correlix sends
  `event_action: resolve` with the SAME dedup key — the PD incident closes
  itself. No payload needed; gate-suppressed resolves are harmless no-ops.
- **History note**: resolution only fires on clears that happen *after* the
  feature shipped. If your service accumulated a backlog before then,
  bulk-resolve once in the PD UI; the count tracks reality from that point.
- **Severity gate**: applies to triggers only; resolutions always pass
  (closing an incident is never noise).

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Test button fails, PD shows nothing | Wrong/revoked integration key, or the service uses a different integration type — must be **Events API V2**, not email/API-token integrations. |
| HTTP 400 from PD in api logs | Malformed event — normalized since 2026-07-11; if seen on newer builds, capture the log line and file it. |
| Incidents pile up and never close | Pre-propagation backlog (bulk-resolve once), or the alert never actually clears in Correlix — check the alert's state in the UI before blaming PD. |
| Duplicate incidents for one alert | Should be impossible (dedup key). If observed, compare the `dedup_key` on both PD incidents — differing keys means the alert identity changed (e.g. rule renamed mid-flight). |
| Too many pages | Raise `min_severity` to `critical`, and remember alert-quality work belongs in `rules.yaml`, not in gating everything out at the channel. |
| TLS error on test (lab only) | Versa egress interception — host CA bundle mount in the compose override handles it; restart api if the override was just added. |

## 5. RCA policy lane (#103 — customer paging, SHIPPED)

Customer-network paging is **policy-driven off correlated RCA objects** —
raw customer alerts never page directly. One PagerDuty incident per root
cause, updated in place, auto-resolved on recovery.

### Setup (per tenant)

1. **Connect the tenant's routing key**: Administration → RCA Auto-Ticketing →
   **PagerDuty paging connection** — paste the tenant's own Events API v2
   integration key (write-only; API: `PUT /api/itsm/pagerduty-rca`).
2. **Create a PagerDuty incident policy**: same pane → New policy → External
   system = `pagerduty`. Verdict/severity gates work exactly like ServiceNow
   policies; `Default urgency` maps to page severity (1 = critical page).
   One enabled policy per (tenant, system) — a tenant can run ServiceNow AND
   PagerDuty policies side by side. **Paging is opt-in**: no PagerDuty
   policy → no pages, ever.
3. **Simulator**: the policy Test button dry-runs against a real correlation
   and reports `runtime_state` for the PagerDuty lane specifically.

### Lifecycle & identity

- Dedup identity: `correlix:<tenant-id>:<correlation-uuid>:pagerduty` —
  immutable IDs only; renames/severity changes never fork a new incident.
  A 57-alert storm inside one correlation = ONE PagerDuty incident.
- create → `trigger`; RCA updates → `trigger` same key (payload refresh);
  RCA resolve → `resolve` same key. Policy-exit (severity/verdict drops)
  follows ServiceNow semantics: the page stays open until the RCA object
  resolves. Work notes stay in the Correlix audit trail (Events v2 has none).
- Delivery: transactional outbox + SKIP-LOCKED worker, backoff + jitter,
  429 honors Retry-After, 400/401/403 dead-letter (permanent), tenant-match
  asserted before every external call (mismatch = quarantined, never sent).
- Display identity (#103 UX-2): the incident summary leads with the friendly
  Correlix Problem ID — `[P-XXXXXX] Confirmed local link fault on edge1` — and
  `custom_details.problem_id` carries the same handle (the one the RCA
  Inspector and ServiceNow tickets show). The correlation UUID stays canonical
  in `dedup_key` and `custom_details.correlation_id`.

## 6. Platform self-health lane (the global key's ONLY job)

The **platform-global** routing key (§1–2 above) now pages exclusively for
Correlix stack health — the failures where the correlation engine itself may
be down: allowlisted `layer` classes `stack` (containers/restarts), `host`
(memory/disk/OOM-killer), `clickhouse`, `platform` (core service/scrape
reachability). Customer alerts (devices, interfaces, BGP, paths, flows)
are default-closed rejected from this lane — they page via tenant policies.
Resolutions always pass. Legacy behavior (`scope: "all"`) remains an
explicit, deprecated opt-back on `/api/notify/pagerduty`.

## 7. Runbook

| Situation | Action |
|---|---|
| Routing key revoked (401/403 dead-letters) | Rotate the key in PD, re-enter in the paging connection card; dead-letters stay for audit — re-enqueue happens on the next RCA change. |
| Delivery backlog | `GET /api/tickets/outbox` (status retrying/dead_letter + last_error); worker metrics on /metrics. |
| Duplicate PD incidents suspected | Compare `dedup_key` on both PD incidents — identical keys CANNOT duplicate (Events v2); different keys = different correlations (check merge chain). |
| Page didn't fire | Policy simulator (runtime_state names the governing policy), then connection card (`has_routing_key`), then outbox. |
| Stuck-open PD incident | Check the RCA object state — resolve propagates on RCA resolution; manual resolve in PD is safe (dedup key remains valid for future). |
| Platform-health verification | `layer` label present on the alert? Only stack/host/clickhouse/platform page globally. |
