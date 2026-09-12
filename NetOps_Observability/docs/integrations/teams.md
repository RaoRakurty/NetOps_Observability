# Microsoft Teams Integration — Setup Guide

Correlix posts alerts to a Teams channel through an **Incoming Webhook**, using
the MessageCard (Office 365 connector) format so Teams renders a colored title
bar per severity.

| What you get | Teams-side requirement | Correlix-side requirement |
|---|---|---|
| Alerts posted to a channel, colored by severity, filtered by a severity floor | An **Incoming Webhook URL** for the target channel | Webhook URL + min severity in Settings → Notification channels |

Teams is a **notification-only** (outbound) integration. Unlike Slack there is
no return path today — button clicks / adaptive-card actions do not drive the
incident lifecycle. If you need the bidirectional loop, use Slack (`slack.md`).

---

## 1. Create the Incoming Webhook (once per channel)

1. In Teams, open the channel you want alerts in → **⋯** → **Connectors**
   (or **Manage channel → Connectors**).
2. Find **Incoming Webhook** → **Configure**.
3. Name it (e.g. `Correlix`), optionally upload an icon, → **Create**.
4. **Copy the URL.** This is shown once. It looks like
   `https://<tenant>.webhook.office.com/webhookb2/<guid>@<guid>/IncomingWebhook/<id>/<guid>`.

> Workspaces that have retired the Office 365 connector should create the
> webhook through a **Workflows / Power Automate** "post to a channel when a
> webhook request is received" flow instead. The resulting URL works the same
> way here — Correlix only needs an HTTPS endpoint that accepts a JSON POST.

### Credential handling rules

- The webhook URL **embeds a bearer secret** — treat the whole URL as a
  credential. Anyone holding it can post into your channel.
- Enter it only in the Correlix admin UI (or a direct API call). Never commit
  it, and avoid pasting it into chats or tickets.
- Correlix stores it **write-only and encrypted at rest** (platform DEK, #17).
  The API returns only `webhook_set: true` — the value is never readable back,
  on any endpoint, at any privilege level.
- **HTTPS is enforced.** An `http://` webhook is refused with a 400: the bearer
  token and every alert body would otherwise cross the network in clear text.
- If the URL leaks, remove the connector in Teams and create a new one, then
  re-enter it in Correlix.

---

## 2. Configure the channel in Correlix

Settings → **Notification channels** → **Microsoft Teams**:

| Field | Meaning |
|---|---|
| Enabled | Registers the channel with the alert dispatcher. Disabling removes it live — no restart. |
| Webhook URL | The Incoming Webhook from step 1. Write-only: leave it blank on a later save to keep the stored value. |
| Min severity | The floor for broadcast alerts. Default **`warning`** (Teams is a chat channel — same class as Slack). |

Or via the API (platform owner only):

```bash
curl -X PUT https://<stack>/api/notify/teams \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"webhook_url":"https://…/IncomingWebhook/…","min_severity":"warning"}'
```

Then prove it end to end — this posts a test card to the channel:

```bash
curl -X POST https://<stack>/api/notify/teams/test -H "Authorization: Bearer $TOKEN"
```

`200 {"status":"sent"}` means Teams accepted the card. `502` returns the
provider's own rejection so you can see whether the URL is stale or revoked.

### Who may configure it

Notification channels are **platform-GLOBAL plumbing**, so `/api/notify/teams`
and `/api/notify/teams/test` are gated by `requirePlatformAdmin`
(CLAUDE.md §3a rule 3). An org or tenant administrator holds full
`administration:admin` **within its own scope** and is still refused with
**403** here — it must not be able to read the operator's channel inventory or
repoint where the platform's alerts go.

---

## 3. Severity floor — what actually gets posted

Broadcast alert dispatch runs through a severity gate, so the floor is the
whole filter:

| Floor | Posts at |
|---|---|
| `info` | everything |
| `warning` (default) | warning, error, critical |
| `error` | error, critical |
| `critical` | critical only |

Two things deliberately bypass the floor:

- **Scheduled reports** delivered to a named channel (an explicit send is
  intentional — a low-severity report still reaches a `critical`-gated channel).
- **The `/test` hook**, so you can verify a channel without waiting for a real
  alert.

Delivery itself rides the shared bounded worker pool: retries with exponential
backoff + jitter, a per-alert time budget, and per-channel `sent` / `failed` /
`retries` / `dropped` counters on `/metrics`. A failed post is logged
structurally, never silently swallowed.

---

## 4. Migrating from the old `TEAMS_WEBHOOK_URL` env wiring

Teams used to be wired straight from environment variables
(`FEATURE_TEAMS_NOTIFICATIONS` + `TEAMS_WEBHOOK_URL`). That path had no admin
surface, **no severity gate at all** — every alert at every severity was posted
— and needed a restart to change.

On upgrade, Correlix migrates the env wiring into the managed config
**automatically and exactly once**:

- The webhook URL is adopted, `enabled` follows `FEATURE_TEAMS_NOTIFICATIONS`,
  and the floor is set to the `warning` default.
- A deprecation warning is written to the application log naming the channel.
- The migration is **latched** (`env_seeded.teams` in the stored config, which
  persists across restarts). After that the environment variables are ignored —
  so if you disable Teams in the admin UI, a `TEAMS_WEBHOOK_URL` still sitting
  in `.env` will not resurrect it at the next boot.
- If the env URL is not a usable HTTPS webhook, nothing is migrated and the
  error is logged loudly on every boot until it is fixed or the channel is
  configured in the UI.

**Action for operators:** after confirming the channel in Settings →
Notification channels, delete `FEATURE_TEAMS_NOTIFICATIONS` and
`TEAMS_WEBHOOK_URL` from `.env`. They are dead weight and a copy of a
credential outside the sealed store.

---

## 5. Troubleshooting

| Symptom | Cause |
|---|---|
| `400` with "must use https" | The webhook URL is `http://`. Teams always issues HTTPS URLs — re-copy it. |
| `400` with "configure a webhook url before enabling Teams" | `enabled: true` with no webhook stored or supplied. |
| `502` on `/test` | Teams rejected the post. The connector was removed, the flow was disabled, or the URL is stale — recreate it. |
| Nothing arrives, no error | The alert is below the severity floor, or the channel is disabled. Check `min_severity` and the per-channel counters on `/metrics`. |
| Posts stopped after an upgrade | The env migration adopted the channel with the `warning` floor; previously it posted at every severity. Lower the floor if you want `info`/`notice` back. |
| Correlix cannot reach the webhook host | The SSRF guard (SR-015) blocks non-public addresses. A self-hosted relay needs `SSRF_ALLOWED_HOSTS`. |

See `architecture.md` for how the platform channel lane relates to the
tenant-scoped RCA incident lane.
