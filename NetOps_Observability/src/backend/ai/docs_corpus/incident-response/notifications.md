---
title: Notifications (Slack, PagerDuty, Email, SMS & Push)
sidebar_label: Notifications
sidebar_position: 2
description: Route alerts to your team's channels — Slack, PagerDuty, email, SMS (Twilio), and phone push — with per-channel severity thresholds and test sends.
---

# Notifications

Notification channels deliver alerts to where your team already works. Configure them at <kbd>Incident Response → Notifications</kbd> — a gallery of four channel tiles, each opening its own guided setup:

| Channel | Delivers via | Typical use |
| --- | --- | --- |
| **Email** | Your SMTP relay | NOC distribution lists |
| **SMS &amp; Push** | Twilio (SMS) and ntfy (free push) | Paging phones on critical alerts |
| **Slack** | Slack Incoming Webhook | Team channel visibility |
| **PagerDuty** | PagerDuty Events API v2 | On-call escalation |

Each tile shows its state at a glance — **Not set up**, **On**, or **Off** — and the stat strip at the top counts **Channels**, **Enabled**, and **Contact points**.

:::note Platform administrator required
Notification channels are platform-wide delivery plumbing; configuring them requires a platform administrator. All secrets (passwords, tokens, webhook URLs, routing keys) are **write-only**: they are never displayed after saving, and re-saving with a blank secret field keeps the stored value.
:::

## How delivery works

- An alert is dispatched **once, when it first starts firing** — not on every evaluation. See [Manage alerts](/monitoring/manage-alerts).
- Every *enabled* channel receives every alert, filtered by that channel's own **Send on severity ≥** selector. Severity levels, lowest to highest: `info`, `notice`, `warning`, `error`, `critical`.
- Notification channels are separate from [Integrations](/incident-response/integrations) (ServiceNow/Jira ticketing). Use both: page the on-call *and* file the ticket.

## Email (SMTP)

1. Go to <kbd>Incident Response → Notifications</kbd> and click the **Email** tile.
2. Check **Enable email delivery**.
3. Fill in the fields:

| Field | Required | What it is | Example |
| --- | --- | --- | --- |
| **Host** | Yes | Hostname of your SMTP relay | `smtp.example.com` |
| **Port** | Yes | SMTP port — 587 for STARTTLS, 465 for TLS-on-connect, 25 for plain relay | `587` |
| **From** | Yes | The From address alert emails are sent as | `noc@example.com` |
| **Recipients (comma-separated)** | Yes | One or more addresses that receive alert emails | `oncall@example.com, noc@example.com` |
| **Username** | No | SMTP auth username; leave blank for an unauthenticated relay | `alerts` |
| **Password** | No | SMTP auth password (write-only — blank keeps the stored value) | — |
| **Security** | Yes | Transport encryption: **STARTTLS (587, secure)**, **TLS on connect (465, secure)**, or **None (plain relay, insecure)** | STARTTLS |
| **Send on severity ≥** | Yes | Only alerts at or above this severity are delivered to this channel | `error` |

4. Click **Save**, then **Send test**.

**Verify it worked:** the page shows "Test sent — check your inbox/phone" and a test email arrives at every recipient. The Email tile now reads **On** with `Relay <your-host>` beneath it.

**Troubleshooting**

- **Test failed** with a connection error — the port and **Security** setting must match your relay (587 ↔ STARTTLS, 465 ↔ TLS on connect); a mismatch is the most common failure.
- **Test sent but nothing arrives** — check the relay's logs and spam filtering; many relays reject a **From** address outside their own domain.
- **Auth errors** — re-enter the password (write-only, so you can't visually confirm the stored one).

## SMS & Push

The **SMS &amp; Push** tile holds two phone-delivery methods in one place: metered SMS via **Twilio** and free push via **ntfy**. Use ntfy to rehearse critical-alert paging without SMS cost, then add Twilio for production.

### SMS via Twilio

1. In the Twilio Console, note your **Account SID** (starts with `AC…`), **Auth token**, and a Twilio **sending phone number**.
2. In Correlix, open the **SMS &amp; Push** tile and check **Enable SMS delivery** under *SMS · Twilio*.
3. Fill in the fields:

| Field | Required | What it is | Example |
| --- | --- | --- | --- |
| **Account SID** | Yes | Your Twilio Account SID, from the Twilio Console dashboard | `ACxxxxxxxx…` |
| **Auth token** | Yes (first save) | Twilio auth token paired with the SID (write-only) | — |
| **From number** | Yes | A Twilio phone number in E.164 format that messages are sent from | `+15555550123` |
| **To numbers (comma-separated)** | Yes | Recipient phone numbers in E.164 format | `+15555550100, +15555550101` |
| **Send on severity ≥** | Yes | Delivery threshold for this channel | `critical` |

4. Click **Save SMS**, then **Send test**.

### Push via ntfy

1. Install the ntfy app on the phones that should receive pushes and subscribe them to a topic name of your choosing (make it unguessable — on a public server, anyone who knows the topic can subscribe).
2. In the **SMS &amp; Push** tile, check **Enable push delivery** under *Push · ntfy* and fill in:

| Field | Required | What it is | Example |
| --- | --- | --- | --- |
| **Server** | No | ntfy server base URL — the public server or your self-hosted instance | `https://ntfy.sh` |
| **Topic** | Yes | The topic Correlix publishes to; subscribe to it in the ntfy app | `netops-a1b2c3` |
| **Token (optional)** | No | Access token for protected topics (write-only) | — |
| **Send on severity ≥** | Yes | Delivery threshold for this channel | `critical` |

3. Click **Save push**, then **Send test**.

**Verify it worked:** the test SMS arrives on every **To** number, and the push appears on every subscribed device. The tile shows **On** with `SMS · Push` beneath it.

**Troubleshooting**

- **Twilio test failed** — numbers must be in E.164 format (`+` and country code); trial Twilio accounts can only text verified numbers.
- **No push received** — the topic in Correlix and in the ntfy app must match exactly, and a protected topic needs the token saved.
- **SMS bills climbing** — raise **Send on severity ≥** to `critical`; Twilio is metered per message per recipient.

## Slack

1. In Slack, create an **Incoming Webhook** for the target channel and copy the webhook URL (it looks like `https://hooks.slack.com/services/…`).
2. In Correlix, open the **Slack** tile and check **Enable Slack delivery**.
3. Fill in the fields:

| Field | Required | What it is | Example |
| --- | --- | --- | --- |
| **Webhook URL** | Yes (first save) | Slack Incoming Webhook URL — it embeds a secret, so it's write-only | `https://hooks.slack.com/services/…` |
| **Send on severity ≥** | Yes | Delivery threshold for this channel | `warning` |

4. Click **Save**, then **Send test**.

**Verify it worked:** a test message appears in the Slack channel the webhook targets; the tile reads **On** with "Webhook configured."

**Troubleshooting:** a failed test usually means the webhook was revoked or the app removed from the channel — create a fresh Incoming Webhook and re-save (paste the full URL; the field shows dots afterward because it is write-only).

## PagerDuty

1. In PagerDuty, on the service that should receive alerts, add an **Events API v2** integration and copy its 32-character **integration (routing) key**.
2. In Correlix, open the **PagerDuty** tile and check **Enable PagerDuty delivery**.
3. Fill in the fields:

| Field | Required | What it is | Example |
| --- | --- | --- | --- |
| **Routing key** | Yes (first save) | Events API v2 integration key from your PagerDuty service (write-only) | 32-char key |
| **Send on severity ≥** | Yes | Delivery threshold — for a paging channel, usually `critical` | `critical` |

4. Click **Save**, then **Send test**.

Each Correlix alert triggers a PagerDuty event carrying the alert summary, severity, source device, and rule, with a per-alert dedup key so a repeated dispatch of the same alert does not stack duplicate PagerDuty incidents.

**Verify it worked:** a test incident appears (and pages) on the PagerDuty service.

**Troubleshooting:** "invalid routing key" means the key isn't the Events API v2 integration key — service API keys and REST API keys will not work.

### Two-way sync (Slack and PagerDuty)

Inside the Slack and PagerDuty setup panels, a collapsible **Bidirectional sync** section lets the provider push state changes (ack, resolve, reassign) back onto Correlix incidents: set **Sync mode** to `bidirectional`, check **Accept inbound state changes**, enter a **Webhook signing secret** (required; inbound calls are HMAC-verified against it), then copy the displayed **Inbound webhook URL** and register it with the provider — for Slack as the app's Interactivity request URL, for PagerDuty as a v3 webhook subscription — and click **Save sync**. The mechanics are identical to the ITSM sync step described under [Integrations](/incident-response/integrations#two-way-sync-and-webhook-secrets).

## Contact points

Below the channel gallery, the **Contact points** card manages reusable delivery audiences — email groups, Slack targets, or webhooks — that **Reports** deliver to (they are not the alert path above). Contact points are scoped to the current tenant. To add one: enter a **Name** (e.g. `NOC on-call`), pick a **Type** (`email`, `slack`, or `webhook`), then either the comma-separated **Email recipients** (email type) or the **Target** URL/channel (other types), and click **Add**.

## Next

- **[Integrations (ServiceNow, Jira)](/incident-response/integrations)** — file tickets, not just messages
- **[RCA Auto-Ticketing](/incident-response/rca-ticketing)** — one ticket per root cause, automatically
