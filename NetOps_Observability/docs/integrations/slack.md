# Slack Integration — Setup Guide

Two independent tiers, both shipped (#43/#43a):

| Tier | What you get | Slack-side requirement | Correlix-side requirement |
|---|---|---|---|
| 1 — Notifications | Alerts + incident cards (with buttons rendered) posted to a channel | An **Incoming Webhook URL** | Webhook URL + min severity in Notification channels |
| 2 — Bidirectional | Button clicks (Acknowledge / Resolve / Escalate) drive the incident lifecycle in Correlix | App **Interactivity** pointed at the stack + **Signing Secret** | Integration webhook enabled (token + signing secret) + the stack reachable from Slack's cloud |

Tier 1 works standalone. Tier 2 adds the return path.

---

## 1. Create the Slack app (once per workspace)

1. Go to <https://api.slack.com/apps> → **Create New App** → **From scratch**.
2. Name it (e.g. `Correlix`), select your workspace, **Create App**.
3. You land on **Basic Information**. The only credential Correlix ever needs
   from this page is the **Signing Secret** (Tier 2). The Client ID / Client
   Secret (OAuth) and the deprecated Verification Token are **not used** —
   don't configure them anywhere.

### Credential handling rules

- The Incoming Webhook URL **embeds a bearer secret** — treat the whole URL as
  a credential. Enter it only in the Correlix admin UI (or a direct API call);
  never commit it, and avoid pasting it into chats/tickets.
- Correlix stores both the webhook URL and the signing secret **write-only and
  encrypted at rest** (vault, #17). The API returns only `webhook_set: true` /
  `webhook_secret_set: true` — values are never readable back.
- If a secret is ever exposed, rotate it at the source: **Incoming Webhooks →
  regenerate** (Slack) / **Basic Information → Rotate** (signing secret), then
  re-enter in Correlix.

---

## 2. Tier 1 — channel notifications

### Slack side

1. App page → **Features → Incoming Webhooks** → toggle **Activate Incoming
   Webhooks** ON.
2. Bottom of the page → **Add New Webhook to Workspace** → pick the target
   channel (e.g. `#netops-alerts`) → **Allow**.
3. Copy the generated URL: `https://hooks.slack.com/services/T…/B…/…`

### Correlix side (UI — preferred)

1. Log in as an administrator → **Administration → Notification channels →
   Slack**.
2. Paste the webhook URL, choose **Minimum severity**
   (`warning` = default; `critical` for pages-only channels), toggle
   **Enabled**, **Save**.
3. Click **Test** — a test message must arrive in the channel.

### Correlix side (API — equivalent)

```bash
curl -X PUT https://<host>/api/notify/slack \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"webhook_url":"https://hooks.slack.com/services/…","min_severity":"warning"}'
curl -X POST https://<host>/api/notify/slack/test -H "Authorization: Bearer $TOKEN"
```

Notes:

- Config is **persisted in the encrypted notify store**; the legacy
  `FEATURE_SLACK_NOTIFICATIONS` / `SLACK_WEBHOOK_URL` env vars only SEED the
  store on first boot and are otherwise ignored — the UI/API value wins.
- Notification channels are **platform-global plumbing** (CLAUDE.md §3a):
  configuring them requires platform-admin scope, not tenant admin.
- What posts to Slack: alert notifications that clear the severity gate, and
  **interactive incident cards** (Acknowledge / Resolve / Escalate buttons)
  for new incidents at/above the threshold. Without Tier 2 the buttons render
  but clicks do not round-trip.

---

## 3. Tier 2 — bidirectional (button clicks drive incidents)

### Correlix side (already the source of truth for the two values Slack needs)

1. **Administration → Integrations → Slack** (or the API below): enable the
   integration, enable the webhook, and set the **Signing Secret** from the
   app's Basic Information page.

```bash
curl -X PUT https://<host>/api/integrations/slack \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"sync_mode":"bidirectional","webhook_enabled":true,"webhook_secret":"<signing-secret>"}'
```

2. The response contains the minted inbound endpoint:

```
"webhook_url": "/api/integrations/webhook/slack/<opaque-token>"
```

   The token is part of the URL's secrecy; the signing secret is verified on
   every request on top of it (defense in depth — an unguessable URL AND a
   cryptographic signature).

### Slack side

1. App page → **Features → Interactivity & Shortcuts** → toggle ON.
2. **Request URL**: `https://<publicly-reachable-host>/api/integrations/webhook/slack/<opaque-token>`
3. **Save Changes**. Slack immediately probes the URL — it must be reachable
   over the public internet with a valid TLS certificate.

### Reachability (the usual blocker)

Slack's cloud must reach the Request URL. Options:

- **Production/customer deployment**: normal public ingress in front of nginx.
- **Lab/testing**: a tunnel, e.g. `cloudflared tunnel --url http://localhost:8000`
  (free, ephemeral hostname) or ngrok. Update the Request URL whenever the
  tunnel hostname changes.
- Until reachable: Tier 1 is unaffected; button clicks show a Slack error and
  are simply lost (no queueing on the Slack side).

### What the round-trip does

Button click → Slack POSTs (signed) to the webhook → signature + token
verified → payload normalized + deduped → incident lifecycle action
(acknowledge / resolve / escalate) applied under the integration's tenant
scope → 200 returned immediately (processing is async, never blocks Slack's
3-second timeout).

---

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| **Test** button fails with a TLS/certificate error | Lab egress TLS interception (Versa MITM) — the compose override mounts the host CA bundle (`SSL_CERT_FILE`); make sure the override file is in use, then restart the api service. |
| Test OK but no alert traffic | Severity gate: channel `min_severity` vs actual alert severities. Check Administration → Notification channels shows `Enabled` + webhook set. |
| Buttons visible, clicks do nothing | Tier 2 not reachable (NAT/tunnel down) or Request URL stale. Slack shows a warning triangle on the message when the POST fails. |
| Slack rejects the Request URL on save | URL not publicly reachable, TLS invalid, or the opaque token path is wrong — re-read `webhook_url` from `GET /api/integrations`. |
| `invalid signature` in api logs | Signing secret mismatch — re-copy from Slack Basic Information and PUT it again (write-only; you cannot compare, only overwrite). |
| Duplicate incident actions | None expected — inbound is 3-level deduped; if observed, capture `X-Slack-Request-Timestamp` headers and file it. |

## 5. Security summary

- Webhook URL + signing secret: write-only, encrypted at rest, never logged.
- Inbound endpoint is unauthenticated by design but double-gated (opaque
  token + HMAC signature verification, bounded request bodies).
- OAuth Client ID/Secret and Verification Token: unused — leave them alone,
  rotate the Client Secret if it was ever shared.
- Slack posts contain operational data (alert titles, device names). Point
  the webhook at a **private channel** if the workspace has guests.
